"""vmrunでGuest収集を制御し、照合済み原本をHost変換へ引き渡す。"""
from dataclasses import dataclass
from vmrun_errors import VmrunError, from_result, error_details, ErrorContext, redact
import base64
import json
from pathlib import Path
import subprocess
import time
import uuid
import tui_runtime
from dynamic_evidence import convert_all, sha256, validate_manifest

DEFAULTS = {
    'guest_root': r'C:\Users\Public\r_AKanaly\dynamic',
    'task_name': 'r_AKanaly_DynamicCapture',
    'sample_task_name': 'r_AKanaly_DynamicSample',
    'execution_timeout_seconds': 300, 'post_exit_seconds': 10,
    'ready_timeout_seconds': 120, 'finalize_timeout_seconds': 180,
    'poll_interval_seconds': 2, 'transfer_attempts': 3,
    'transfer_timeout_seconds': 1800,
    'raw_transfer_compression': True, 'compression_timeout_seconds': 1800,
    'conversion_timeout_seconds': 600,
    'max_log_bytes': 4 * 1024**3, 'min_free_bytes': 2 * 1024**3,
    'require_defender_disabled': True,
    'host_procmon_path': 'tools_runtime/ProcessMonitor/Procmon64.exe',
    'sysmon_enabled': True, 'procmon_enabled': True, 'etw_enabled': True,
}

LLM_DEFAULTS = {'enabled': False, 'instruction_file': 'prompts/dynamic_default.md',
                'prompt': None, 'allow_guest_elevation': True, 'max_duration_seconds': 900,
                'screenshot_recording_enabled': False, 'screenshot_interval_seconds': 10,
                'screenshot_output_dir': '{analysis_dir}/dynamic_screenshots'}

DEFENDER_REGISTRY_PATHS = {
    r'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
    r'HKLM:\SOFTWARE\Microsoft\Windows Defender',
}


# Guestが返したゲート省略理由を再検証し、根拠のない成功応答を拒否する。
def valid_defender_bypass(result):
    if result.get('bypass') is not True or result.get('traditional_check_performed') is not False:
        return False
    status = result.get('defender_status') or {}
    if status.get('read_success') is True and status.get('AMRunningMode') == 'Not running':
        return True
    checks = result.get('registry_checks')
    if not isinstance(checks, list):
        return False
    for check in checks:
        if (isinstance(check, dict) and check.get('path') in DEFENDER_REGISTRY_PATHS
                and check.get('name') == 'DisableAntiSpyware'
                and check.get('read_success') is True and check.get('exists') is True
                and check.get('kind') == 'DWord' and type(check.get('value')) is int
                and check.get('value') == 1 and check.get('disables_defender') is True):
            return True
    return False


# OFFは指示を読まず、未入力・空ファイルは同梱の標準指示へ戻す。
def resolve_dynamic_instructions(settings, settings_path, dry_run=False):
    from dynamic_prompt import default_instructions
    options = settings['llm_control']
    if not options['enabled']:
        return ''
    value = options['prompt']
    if value is None and options['instruction_file']:
        source = Path(options['instruction_file'])
        if not source.is_absolute():
            source = Path(settings_path).resolve().parent / source
        if source.is_file():
            value = source.read_text(encoding='utf-8-sig')
        else:
            print('動的解析の指示ファイルがないため、標準指示を使用します')
    return (value or '').strip() or default_instructions()


# 旧ワクチン設定を実行へ流用せず、新方式の設定を検証する。
def parse_dynamic_settings(data):
    values = data.get('dynamic_analysis', {})
    if not isinstance(values, dict):
        raise ValueError('dynamic_analysis must be an object')
    unknown = set(values) - set(DEFAULTS) - {'llm_control', 'evidence_disk', 'recovery'}
    if unknown:
        raise ValueError('Unknown dynamic settings: ' + ', '.join(sorted(unknown)))
    result = dict(DEFAULTS, **values)
    for key, default in DEFAULTS.items():
        value = result[key]
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise ValueError(key + ' must be boolean')
        elif isinstance(default, int):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(key + ' must be a positive integer')
        elif not isinstance(value, str) or not value.strip():
            raise ValueError(key + ' must be a nonempty string')
    if not any(result[k] for k in ('sysmon_enabled', 'procmon_enabled', 'etw_enabled')):
        raise ValueError('At least one dynamic logger is required')
    options = values.get('llm_control', {})
    if not isinstance(options, dict) or set(options) - set(LLM_DEFAULTS):
        raise ValueError('Invalid dynamic_analysis.llm_control settings')
    options = dict(LLM_DEFAULTS, **options)
    for key in ('enabled', 'allow_guest_elevation', 'screenshot_recording_enabled'):
        if not isinstance(options[key], bool):
            raise ValueError('llm_control.' + key + ' must be boolean')
    for key in ('prompt', 'instruction_file'):
        if options[key] is not None and not isinstance(options[key], str):
            raise ValueError('llm_control.' + key + ' must be string or null')
    duration = options['max_duration_seconds']
    if isinstance(duration, bool) or not isinstance(duration, int) or duration <= 0:
        raise ValueError('llm_control.max_duration_seconds must be a positive integer')
    interval = options['screenshot_interval_seconds']
    if isinstance(interval, bool) or not isinstance(interval, int) or interval <= 0:
        raise ValueError('llm_control.screenshot_interval_seconds must be a positive integer')
    if not isinstance(options['screenshot_output_dir'], str) or not options['screenshot_output_dir'].strip():
        raise ValueError('llm_control.screenshot_output_dir must be a nonempty string')
    result['llm_control'] = options
    from evidence_disk import parse_settings as parse_evidence_settings
    result['evidence_disk'] = parse_evidence_settings(values.get('evidence_disk', {}))
    from dynamic_recovery import parse_settings as parse_recovery_settings
    result['recovery'] = parse_recovery_settings(values.get('recovery', {}))
    return result


# 本体に原本・変換状態の確定パスを返す。
@dataclass(frozen=True)
class DynamicResult:
    directory: Path
    status: Path
    sysmon: Path | None


class DynamicSession:
    # Guestへの認証値を永続ファイルやコマンド表示へ含めない。
    def __init__(self, settings, vmware, credentials, vm_password, vmrun, output):
        self.settings = settings
        self.vmware = vmware
        self.credentials = credentials
        self.vm_password = vm_password
        self.vmrun = str(vmrun)
        self.id = uuid.uuid4().hex
        self.output = Path(output) / ('dynamic_' + self.id)
        self.output.mkdir(parents=True, exist_ok=False)
        self.root = settings['guest_root']
        self.run_root = self.root + '\\runs\\' + self.id
        self.started = False
        self.recovery = None
        self.recovery_preserved = False
        self.recovery_activated = False

    # 製品では配置・登録をしない。保存点に用意した固定監視環境を検査して有効化する。
    def prepare_recovery(self):
        options = self.settings.get('recovery', {})
        if not options.get('enabled'):
            return
        path = self.output / 'lifecycle-installed.json'
        self.guest('copyFileFromGuestToHost', self.root + '\\lifecycle-installed.json', path)
        installed = json.loads(path.read_text(encoding='utf-8-sig'))
        if installed.get('version') != 1 or installed.get('complete') is not True:
            raise RuntimeError('Guest lifecycle setup is missing; update the snapshot with setup_lifecycle.ps1')
        active = {'enabled': True, 'analysis_id': self.id,
                  'interactive': self.settings['llm_control']['enabled'],
                  'agent_root': self.root + '\\agents\\' + self.id,
                  'process_snapshot_seconds': options['process_snapshot_seconds'],
                  'expires_utc': time.time() + options['total_seconds'] + 1800}
        local = self.output / 'recovery-active.json'
        local.write_text(json.dumps(active), encoding='utf-8')
        self.guest('copyFileFromHostToGuest', local, self.root + '\\recovery-active.json.tmp')
        quoted = self.root.replace("'", "''")
        script = "$ErrorActionPreference='Stop'; Move-Item -LiteralPath '" + quoted + "\\recovery-active.json.tmp' -Destination '" + quoted + "\\recovery-active.json' -Force"
        self.program(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                     '-NoProfile', '-NonInteractive', '-EncodedCommand',
                     base64.b64encode(script.encode('utf-16le')).decode('ascii'))
        self.recovery_activated = True
        self.program(r'C:\Windows\System32\schtasks.exe', '/Run', '/TN', 'r_AKanaly_LifecycleMonitor')
        deadline = time.monotonic() + self.settings['ready_timeout_seconds']
        while time.monotonic() < deadline:
            try:
                if self.lifecycle_status().get('baseline_ready'):
                    return
            except (RuntimeError, ValueError, OSError):
                pass
            time.sleep(1)
        raise TimeoutError('Guest lifecycle baseline not ready')

    # 小さな最新状態を取得し、古いrunや停止した監視の応答を採用しない。
    def lifecycle_status(self):
        target = self.output / '.lifecycle-status.json'
        self.guest('copyFileFromGuestToHost', self.root + '\\lifecycle-status.json', target, timeout=15)
        value = json.loads(target.read_text(encoding='utf-8-sig'))
        from datetime import datetime, timezone
        stamp = datetime.fromisoformat(value['utc'].replace('Z', '+00:00'))
        if value.get('analysis_id') != self.id or abs((datetime.now(timezone.utc) - stamp).total_seconds()) > 30:
            raise RuntimeError('Stale lifecycle status')
        return value

    # 電源監視と通常Guest操作を分離し、認証引数は既存の秘匿ラッパーに閉じ込める。
    def start_recovery(self, restore=None):
        if not self.settings.get('recovery', {}).get('enabled') or self.recovery is not None:
            return
        from vm_analysis import control
        from dynamic_recovery import RecoveryMonitor
        config = {'vmrun_path': self.vmrun, 'vmx_path': self.vmware.vmx_path,
                  'vm_password': self.vm_password, 'vmrun_timeout_seconds': 15}
        # 一覧取得成功時だけ完全一致で判定する。部分一致やエラー文字列を使わない。
        def power():
            result = control.run_vmrun(config, ['list'], check=True)
            import ntpath
            expected = ntpath.normcase(ntpath.normpath(self.vmware.vmx_path))
            return any(ntpath.normcase(ntpath.normpath(line.strip())) == expected
                       for line in result['output'].splitlines())
        # 復元や検体の再起動をせず、現在のディスク状態のVMだけを起動する。
        def start():
            from guest_isolation import check_vmx
            check_vmx(self.vmware.vmx_path)
            control.run_vmrun(config, ['start', self.vmware.vmx_path, 'nogui'], check=True)
        # 各起動区間のロガー準備完了を確認し、古いreadyファイルを採用しない。
        def restore_capture(status, changed):
            if restore is not None:
                restore(status, changed)
            ready = self.response('ready.json', 10)
            if ready.get('boot_id') != status['boot_id'] or not ready.get('success'):
                raise RuntimeError('Logger not ready for current boot')
        self.recovery = RecoveryMonitor(self.settings['recovery'], self.output, power,
                                        start, self.lifecycle_status, restore_capture)
        self.recovery.start()

    # 正常終了より前に監視とGuestの自動再開を解除する。
    def close_recovery(self):
        if self.recovery is not None:
            self.recovery.stop()
        if getattr(self, 'recovery_activated', False):
            self.send_json('recovery-closed.json', {'analysis_id': self.id})
            self.response('recovery-closed-ready.json', self.settings['ready_timeout_seconds'])
            self.recovery_activated = False

    # 起動不能時は現在のディスクを停止状態の保存点に残し、解析用基準とは分離する。
    def preserve_failed_guest(self):
        from vm_analysis import control
        config = {'vmrun_path': self.vmrun, 'vmx_path': self.vmware.vmx_path,
                  'vm_password': self.vm_password, 'vmrun_timeout_seconds': 120}
        listed = control.run_vmrun(config, ['list'], check=True)['output']
        if self.vmware.vmx_path.lower() in listed.lower():
            raise RuntimeError('Guest is still powered on; evidence snapshot needs a normal shutdown before a new experiment')
        name = 'r_AKanaly_recovery_evidence_' + self.id
        control.run_vmrun(config, ['snapshot', self.vmware.vmx_path, name], check=True)
        self.recovery_preserved = True
        (self.output / 'preserved_snapshot.json').write_text(json.dumps({'snapshot': name,
            'analysis_id': self.id, 'memory_preserved': False, 'reason': 'guest_unavailable'}), encoding='utf-8')
        return name

    # 救出要求では回収済みログを残した上で、通常停止できたGuestの状態を別保存点へ保全する。
    def preserve_for_followup(self, request):
        from vm_analysis import control
        config = {'vmrun_path': self.vmrun, 'vm_password': self.vm_password, 'vmrun_timeout_seconds': 120}
        if self.vmware.vmx_path.lower() in control.run_vmrun(config, ['list'], check=True)['output'].lower():
            control.run_vmrun(config, ['stop', self.vmware.vmx_path, 'soft'], check=True)
        snapshot = self.preserve_failed_guest()
        (self.output / 'rescue_request.json').write_text(json.dumps({'request': request,
            'status': 'evidence_preserved_requires_attention', 'snapshot': snapshot,
            'safe_mode_executed': False, 'linux_boot_executed': False}, ensure_ascii=False, indent=2), encoding='utf-8')
        tui_runtime.set_status('起動状態の救出が必要です。証拠を保存点に保全しました: ' + snapshot)

    # Guestを読めなくてもHostの記録を残し、証拠欠損を明示してレポート工程へ渡す。
    def partial_result(self, error):
        snapshot = self.preserve_failed_guest()
        status = {'analysis_id': self.id, 'all_raw_hashes_verified': False,
                  'capture': {'success': False, 'observation_complete': False, 'errors': [type(error).__name__]},
                  'execution': {'started': False, 'reason': 'guest_unavailable', 'error': 'Guest evidence not recovered'},
                  'conversion_complete': False, 'dynamic_success': False, 'conversions': {},
                  'preserved_snapshot': snapshot,
                  'interpretation': 'Guest evidence was preserved in a powered-off snapshot, not recovered. No absence-of-behavior conclusion is supported.'}
        path = self.output / 'dynamic_status.json'
        path.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding='utf-8')
        return DynamicResult(self.output, path, None)

    # 外部コマンドの例外にも認証情報が露出しないようにする。
    def guest(self, operation, *arguments, timeout=None):
        command = [self.vmrun, '-T', self.vmware.vmrun_type]
        if self.vm_password:
            command += ['-vp', self.vm_password]
        command += ['-gu', self.credentials.username, '-gp', self.credentials.password,
                    operation, self.vmware.vmx_path, *map(str, arguments)]
        try:
            from vmrun_transfer import run_staged
            result = run_staged(command, subprocess.run, capture_output=True, timeout=timeout or 180,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        except subprocess.TimeoutExpired:
            raise VmrunError(None, operation=operation, timed_out=True) from None
        except OSError as error:
            raise VmrunError(None, redact(str(error), command), operation=operation) from None
        if result.returncode:
            raise from_result(command, result)

    # Guest制御は配置済みスクリプトの固定エントリーポイントを用いる。
    def program(self, exe, *args, wait=True):
        self.guest('runProgramInGuest', *([] if wait else ['-noWait']), exe, *args)

    # 要求を書き終えてから転送し、Guestに不完全なJSONを読ませない。
    def send_json(self, name, data):
        local = self.output / ('request_' + name)
        local.write_text(json.dumps(data), encoding='utf-8')
        self.guest('copyFileFromHostToGuest', local, self.run_root + '\\' + name)

    # 一時コピーから応答を読み、別runや未完成の応答を採用しない。
    def response(self, name, timeout):
        deadline = time.monotonic() + timeout
        target = self.output / ('.' + name)
        last_error = None
        while time.monotonic() < deadline:
            try:
                self.guest('copyFileFromGuestToHost', self.run_root + '\\' + name, target,
                           timeout=min(15, max(1, deadline - time.monotonic())))
                value = json.loads(target.read_text(encoding='utf-8-sig'))
                if value.get('analysis_id') != self.id:
                    raise RuntimeError('Response belongs to another run')
                return value
            except (OSError, ValueError, RuntimeError) as error:
                last_error = error
                time.sleep(self.settings['poll_interval_seconds'])
        raise ErrorContext('Guest response timed out: ' + name, last_error)

    # Guestの初期化・改ざん防止OFF・両保護の設定と実効状態を確認し、成功するまで検体を渡さない。
    def ensure_realtime_disabled(self, phase, apply=False):
        if not self.settings['require_defender_disabled']:
            return
        token = uuid.uuid4().hex
        name = 'defender_' + token + '.json'
        destination = self.run_root + '\\' + name
        # 更新済みbaselineに固定配置したrunnerを呼び、通常解析で管理スクリプトを再配置しない。
        guest_script = r'C:\Users\Public\r_AKanaly\dynamic\defender_gate_runner.ps1'
        arguments = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', guest_script,
                     '-AnalysisId', self.id, '-Token', token, '-Phase', phase,
                     '-Destination', destination, '-TimeoutSeconds', str(self.settings['ready_timeout_seconds'])]
        if apply:
            arguments.append('-Apply')
        self.program(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                     *arguments, wait=False)
        result = self.response(name, self.settings['ready_timeout_seconds'] + 15)
        (self.output / (phase + '_defender.json')).write_text(json.dumps(result, indent=2), encoding='utf-8')
        if result.get('token') != token or result.get('success') is not True or result.get('policy_version') != 3:
            raise RuntimeError('Guest Defender check failed: ' + str(result.get('error', 'invalid response')))
        if result.get('bypass') is True:
            if not valid_defender_bypass(result):
                raise RuntimeError('Guest Defender check failed: invalid bypass evidence')
            return
        state = result.get('after') or {}
        preferences = result.get('preferences') or {}
        expected_preferences = {'DisableRealtimeMonitoring': True, 'DisableBehaviorMonitoring': True,
                                'DisableIOAVProtection': True, 'DisableScriptScanning': True,
                                'DisableBlockAtFirstSeen': True, 'MAPSReporting': 0,
                                'SubmitSamplesConsent': 2, 'EnableControlledFolderAccess': 0,
                                'PUAProtection': 0, 'EnableNetworkProtection': 0}
        smart_screen = result.get('smart_screen') or []
        asr_ids, asr_actions = result.get('asr_ids'), result.get('asr_actions')
        if (result.get('bypass') is not False or result.get('traditional_check_performed') is not True
                or any(preferences.get(k) != v or preferences.get(k) is None for k, v in expected_preferences.items())
                or not isinstance(asr_ids, list) or not isinstance(asr_actions, list)
                or len(asr_ids) != len(asr_actions) or any(v != 0 for v in asr_actions)
                or len(smart_screen) < 4 or any(item.get('value') != 0 for item in smart_screen)
                or result.get('initialized') is not True or result.get('stable_checks', 0) < 2
                or state.get('AMRunningMode') != 'Normal' or state.get('AMServiceEnabled') is not True
                or not state.get('AMEngineVersion') or state['AMEngineVersion'] == '0.0.0.0'
                or not state.get('AntivirusSignatureVersion')
                or state.get('RealTimeProtectionEnabled') is not False
                or state.get('BehaviorMonitorEnabled') is not False
                or state.get('IoavProtectionEnabled') is not False
                or state.get('IsTamperProtected') is not False
                or preferences.get('DisableRealtimeMonitoring') is not True
                or preferences.get('DisableBehaviorMonitoring') is not True):
            raise RuntimeError('Guest Defender check failed: ' + str(result.get('error', 'invalid response')))

    # 検体を転送する前に、管理用常駐タスクの環境確認を完了させる。
    def prepare(self):
        from pathlib import PureWindowsPath
        if not PureWindowsPath(self.root).is_absolute() or any(c in self.root for c in '"&|<>\r\n'):
            raise RuntimeError('Invalid dynamic guest root')
        deadline = time.monotonic() + self.settings['ready_timeout_seconds']
        while True:
            try:
                self.guest('listProcessesInGuest')
                break
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        from guest_isolation import check_vmx, check_guest
        check_vmx(self.vmware.vmx_path)
        # 制限付きS4Uタスクにも、このrunの応答ファイルを書ける権限を明示する。
        quoted_root = self.run_root.replace("'", "''")
        script = ("$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force -Path '" + quoted_root + "' | Out-Null; "
                  "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
                  "& icacls.exe '" + quoted_root + "' /grant ('*'+$sid+':(OI)(CI)(M)') | Out-Null; "
                  "if ($LASTEXITCODE -ne 0) { throw 'Run directory permissions failed' }")
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        self.program(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded)
        # LLMのON/OFFによらず、検体の転送より前にHostとGuest両側を確認する。
        check_guest(self.vmware.vmx_path, self.guest, self.program, self.run_root,
                    self.output / 'pre_transfer_network.json')
        self.ensure_realtime_disabled('pre_transfer', apply=True)
        request = dict(self.settings, analysis_id=self.id, run_root=self.run_root)
        request.pop('llm_control', None)
        if self.settings['llm_control']['enabled']:
            request['execution_timeout_seconds'] = self.settings['llm_control']['max_duration_seconds']
        self.send_json('request.json', request)
        pointer = self.output / 'active.json'
        pointer.write_text(json.dumps({'analysis_id': self.id}), encoding='utf-8')
        self.guest('copyFileFromHostToGuest', pointer, self.root + '\\active.json')
        self.program(r'C:\Windows\System32\schtasks.exe', '/Run', '/TN', self.settings['task_name'])
        self.started = True
        ready = self.response('prepared.json', self.settings['ready_timeout_seconds'])
        if not ready.get('success'):
            raise RuntimeError('Dynamic Guest preparation failed: ' + str(ready.get('error')))
        self.prepare_recovery()

    # 観測開始後に登録済みGuestタスクの実行権限で検体を起動する。
    def capture(self, sample, expected_sha256):
        failure = None
        try:
            # 復元先に古いランナーが残っていても、製品同梱版の起動前検査を使う。
            import sys
            bundle = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
            runner = bundle / 'VMWARE_GUEST_CONTROL_PACKAGE/guest/sample_runner.ps1'
            self.guest('copyFileFromHostToGuest', str(runner), self.root + '\\sample_runner.ps1')
            self.ensure_realtime_disabled('pre_execution')
            self.send_json('begin.json', {'analysis_id': self.id})
            ready = self.response('ready.json', self.settings['ready_timeout_seconds'])
            if not ready.get('success'):
                raise RuntimeError('Capture failed to start: ' + str(ready.get('error')))
            self.start_recovery()
            self.send_json('sample.json', {'analysis_id': self.id, 'sample': sample,
                                           'sha256': expected_sha256})
            # 管理者トークンも許容し、実際の起動元権限はexecution.jsonへ記録する。
            self.program(r'C:\Windows\System32\schtasks.exe', '/Run', '/TN', self.settings['sample_task_name'])
            execution = self.response('execution.json', self.settings['execution_timeout_seconds'] + 60)
            tui_runtime.record_result('動的解析', 'partial', '実行応答取得済み。観測・回収結果の確認待ち: ' + str(execution.get('reason')))
        except RuntimeError as error:
            if getattr(self, 'recovery', None) is None:
                raise
            failure = error
        finally:
            # 検体起動や待機が失敗しても、既に収集した原本の保存を要求する。
            if self.started:
                try:
                    if getattr(self, 'recovery', None) is not None:
                        self.close_recovery()
                    if failure is not None:
                        self.send_json('execution.json', {'analysis_id': self.id, 'started': False,
                            'reason': 'execution_result_unknown_after_lifecycle_event', 'error': type(failure).__name__})
                    self.send_json('stop.json', {'analysis_id': self.id})
                except RuntimeError as error:
                    if getattr(self, 'recovery', None) is None:
                        raise
                    failure = error
        try:
            return self.collect()
        except RuntimeError as error:
            if getattr(self, 'recovery', None) is None:
                raise
            return self.partial_result(error)

    # LLMのHook確認と準備完了後だけ観測境界を開く。
    def begin_investigation(self):
        self.ensure_realtime_disabled('pre_execution')
        self.send_json('begin.json', {'analysis_id': self.id})
        ready = self.response('ready.json', self.settings['ready_timeout_seconds'])
        if not ready.get('success'):
            raise RuntimeError('Capture failed to start: ' + str(ready.get('error')))

    # LLMの操作結果をGuest側原本として確定し、その後にロガーを停止する。
    def end_investigation(self, execution):
        try:
            self.send_json('execution.json', dict(execution, analysis_id=self.id))
        finally:
            if self.started:
                self.send_json('stop.json', {'analysis_id': self.id})

    # 全原本を照合し終えるまで変換を一件も開始しない。
    def collect(self):
        tui_runtime.set_stage('ログ回収', 'Guest原本を回収・照合し、Hostで変換しています')
        manifest = self.response('manifest.json', self.settings['finalize_timeout_seconds'])
        files = validate_manifest(manifest, self.id)
        if self.settings.get('raw_transfer_compression', True):
            from dynamic_transfer import collect_compressed
            collect_compressed(self, files)
            (self.output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
            tui_runtime.set_stage('ログ回収', '全原本の照合後、Hostで読み取り用データへ変換しています')
            status = convert_all(self.output, manifest, self.settings)
            sysmon = self.output / 'sysmon.evtx'
            return DynamicResult(self.output, status, sysmon if sysmon.exists() else None)
        for item in files:
            path = self.output / item['name']
            # 回復処理で照合済み原本を再送しない。既存ファイルも毎回ハッシュで確認する。
            if path.is_file() and path.stat().st_size == item['size'] and sha256(path).lower() == item['sha256'].lower():
                continue
            last_error = None
            for attempt in range(self.settings['transfer_attempts']):
                try:
                    self.guest('copyFileFromGuestToHost', self.run_root + '\\' + item['name'], path,
                               timeout=self.settings.get('transfer_timeout_seconds', 1800))
                    if path.stat().st_size == item['size'] and sha256(path).lower() == item['sha256'].lower():
                        break
                except (OSError, RuntimeError) as error:
                    last_error = error
            else:
                raise ErrorContext('Raw artifact failed transfer/hash verification: ' + item['name'], last_error)
        (self.output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        status = convert_all(self.output, manifest, self.settings)
        sysmon = self.output / 'sysmon.evtx'
        return DynamicResult(self.output, status, sysmon if sysmon.exists() else None)
