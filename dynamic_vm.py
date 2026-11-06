"""動的VMを復元せずOSエージェントと画面ブリッジを接続する。"""
from vmrun_errors import error_details, ErrorContext
from dataclasses import replace
import json
from multiprocessing.connection import Listener
from pathlib import Path
import secrets
import threading
import time
from vm_analysis import VmAnalysisSession, PACKAGE, Bridge


class DynamicVmSession(VmAnalysisSession):
    # 動的run専用配置とし、静的エージェントのキュー・IDと混在させない。
    def __init__(self, static_settings, dynamic, source, instructions, settings_dir=None):
        root = dynamic.root + '\\agents\\' + dynamic.id
        settings = replace(static_settings, guest_root=root, visual_control=True)
        super().__init__(settings, dynamic.vmware, dynamic.credentials, dynamic.vm_password,
                         source, dynamic.output / 'agent_state')
        self.dynamic = dynamic
        self.instructions = instructions
        self.deadline = None
        self.completion = None
        self.closed = False
        self.archive_path = None
        from config import APPLICATION_DIR
        self.settings_dir = Path(settings_dir) if settings_dir is not None else APPLICATION_DIR
        self.screen_recorder = None
        self.config['vmrun_timeout_seconds'] = 30
        self.review_request = None

    # 終了回収をロガーの猶予時間内に進めるため、動的制御の再照会回数を制限する。
    def request(self, role, action, **kwargs):
        import uuid
        message = {'role': role, 'timeout': 10, 'request': dict(kwargs, action=action,
                   analysis_id=self.analysis_id, request_id=uuid.uuid4().hex)}
        for _ in range(3):
            response = self.bridge.call(message)
            if not response.get('pending'):
                if not response.get('ok'):
                    raise ErrorContext(str(response), details=response.get('error_details'))
                return response
        raise ErrorContext('Dynamic Guest request timed out: ' + action, details=response.get('error_details'))

    # 復元直後・起動前にだけ一時コンソール設定を追加する。
    def prepare_console(self):
        from console_lifecycle import ConsoleLease
        ConsoleLease.recover_managed(self.config['vmx_path'])
        self.console_lease = ConsoleLease(self.config['vmx_path'], self.state)
        self.console_lease.prepare()

    # 検体投入前にランタイムとOS受付を配備し、画面経路まで疎通する。
    def attach(self):
        self.console_lease.verify()
        self.start_screen_recording()
        root = self.settings.guest_root
        if self.dynamic.settings.get('recovery', {}).get('enabled'):
            # 固定配置は事前セットアップ済み。run専用の状態だけ作成する。
            quoted = root.replace("'", "''")
            fixed = (self.dynamic.root + '\\agent\\runtime').replace("'", "''")
            self.program(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                ['-NoProfile', '-NonInteractive', '-Command',
                 "New-Item -ItemType Directory -Force -Path '" + quoted + "\\transfer','" + quoted + "\\code' | Out-Null; "
                 "New-Item -ItemType Junction -Path '" + quoted + "\\transfer\\runtime' -Target '" + fixed + "' | Out-Null"])
            self.wait_for_login()
            self.program(r'C:\Windows\System32\schtasks.exe', ['/Run', '/TN', 'r_AKanaly_OSAgent'])
            self.connect_bridge()
            return
        self.program(r'C:\Windows\System32\cmd.exe', ['/c mkdir "' + root + '\\code"'])
        self.guest('copyFileFromHostToGuest', str(PACKAGE / 'runtime/guest-transfer.zip'), root + '\\runtime.zip')
        quoted = root.replace("'", "''")
        # 同梱Pythonはisolated _pthなので、別配置のcodeを明示してから起動する。
        setup = ("$ErrorActionPreference='Stop'; $agentRoot='" + quoted + "'; "
                 "Expand-Archive -LiteralPath ($agentRoot+'\\runtime.zip') -DestinationPath ($agentRoot+'\\transfer\\runtime') -Force; "
                 "Get-ChildItem -LiteralPath ($agentRoot+'\\transfer\\runtime') -Filter 'python*._pth' | "
                 "ForEach-Object { Add-Content -LiteralPath $_.FullName -Value '../../code' -Encoding ASCII }; "
                 "foreach($name in @('queue','accepted','responses','secrets')) { "
                 "New-Item -ItemType Directory -Force -Path ($agentRoot+'\\os\\'+$name) | Out-Null }")
        self.program(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            ['-NoProfile', '-NonInteractive', '-Command', setup])
        for name in ('analysis_agent.py', 'analysis_runtime.py', 'desktop_monitor.py', 'ghidra_operations.py', 'production_operations.py',
                     'archive_ops.py', 'guest_agent.py', 'uia_operations.py', 'uia_worker.ps1', 'analysis_archive.py',
                     'dynamic_operations.py'):
            self.guest('copyFileFromHostToGuest', str(PACKAGE / 'guest' / name), root + '\\code\\' + name)
        # snapshotのGhidra環境には依存せず、配置したPythonでOS機能だけ起動する。
        self.wait_for_login()
        self.start_agent(root + '\\transfer\\runtime\\python.exe',
            [root + '\\code\\analysis_agent.py', '--root', root, '--role', 'os', '--keep-awake'], interactive=True)
        self.connect_bridge()

    # Agentの配置方式に依存せず、Host受付を一度だけ作成する。
    def connect_bridge(self):
        root = self.settings.guest_root
        self.state.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        (self.state / 'pipe.key').write_bytes(key)
        self.bridge = Bridge(self.config, self.state, root)
        from console_input import ConsoleInput
        from visual_controller import VisualController
        self.bridge.visual = VisualController(ConsoleInput(self.console_lease.port), self.state / 'frames', self.analysis_id)
        self.bridge.control_handler = self.finish_request
        self.bridge.request_gate = self.gate
        self.listener = Listener(self.pipe, family='AF_PIPE', authkey=key)
        threading.Thread(target=self.accept, daemon=True).start()
        self.os_generation = self.request('os', 'health')['generation']
        self.generation = self.os_generation
        self.bridge.start_desktop_monitor(self.analysis_id, self.os_generation)
        self.request('os', 'screen_observe')

    # 再起動後は同じHost受付を維持し、Guestの世代とMCPの束縛だけを更新する。
    def restore_after_boot(self, status, changed):
        self.console_lease.verify()
        # 復帰監視から長いログオン待機を呼ばない。ログオン時タスクが起動する
        # 対話Agentのhealthを短い照会で確認し、未準備なら次の監視周期へ戻す。
        self.restoring = True
        try:
            generation = self.request('os', 'health')['generation']
        finally:
            self.restoring = False
        if generation != self.os_generation:
            self.bridge.stop_desktop_monitor()
            self.os_generation = self.generation = generation
            binding = json.loads(self.binding.read_text(encoding='utf-8'))
            binding.update(generation=generation, os_generation=generation)
            temporary = self.binding.with_suffix('.tmp')
            temporary.write_text(json.dumps(binding), encoding='utf-8')
            temporary.replace(self.binding)
            self.bridge.start_desktop_monitor(self.analysis_id, generation)

    # Agent起動前から記録し、準備中の画面も利用者が後で確認できるようにする。
    def start_screen_recording(self):
        options = self.dynamic.settings['llm_control']
        if not options.get('screenshot_recording_enabled', False) or self.screen_recorder is not None:
            return
        from vm_screen_recorder import ScreenRecorder
        output = Path(options['screenshot_output_dir']).expanduser()
        if not output.is_absolute():
            output = self.settings_dir / output
        recorder = ScreenRecorder(self.console_lease.port, output, options['screenshot_interval_seconds'], self.dynamic.id)
        try:
            recorder.start()
        except OSError as error:
            print('ユーザー用画面記録を開始できません: ' + str(error))
            return
        self.screen_recorder = recorder
        print('ユーザー用VM画面の保存先: ' + str(recorder.directory))

    # 定期撮影はMCPと独立しているため、異常終了経路でも明示的に止める。
    def disconnect(self):
        recorder = getattr(self, 'screen_recorder', None)
        try:
            if recorder is not None:
                recorder.stop()
                self.screen_recorder = None
        finally:
            super().disconnect()

    # 転送済み対象を固定し、モデルが別検体や別権限設定を指定できないようにする。
    def bind_sample(self, sample, digest, password=None):
        self.sample_path, self.sha256 = sample, digest
        # 非対話転送のACLをGUIユーザーが読めるとは限らないため、対象1ファイルだけRXを付ける。
        quoted_sample = sample.replace("'", "''")
        access = ("$ErrorActionPreference='Stop'; $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
                  "& icacls.exe '" + quoted_sample + "' /grant ('*'+$sid+':RX') | Out-Null; "
                  "if ($LASTEXITCODE -ne 0) { throw 'Guest sample read/execute permissions failed' }")
        import base64
        self.program(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            ['-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(access.encode('utf-16le')).decode()])
        options = self.dynamic.settings['llm_control']
        policy = {'phase': 'dynamic', 'analysis_id': self.analysis_id, 'sample_path': sample,
                  'sha256': digest, 'allow_guest_elevation': options['allow_guest_elevation']}
        local = self.state / 'dynamic-session.json'
        local.write_text(json.dumps(policy), encoding='utf-8')
        self.guest('copyFileFromHostToGuest', str(local), self.settings.guest_root + '\\dynamic-session.json')
        reference = self.bridge.register_archive_secret(self.analysis_id, password) if password is not None else None
        self.binding = self.state / 'session.json'
        self.binding.write_text(json.dumps(dict(policy, project=self.analysis_id, generation=self.generation,
            os_generation=self.os_generation, protected_host_path=str(self.source.resolve()), zip_password_ref=reference)), encoding='utf-8')

    # Host側でも観測開始前・終了後の入力や起動を拒み、モデルの判断だけに依存しない。
    def gate(self, role, request):
        if getattr(self, 'reviewing_instructions', False):
            raise RuntimeError('Tools are disabled during instruction review')
        if role != 'os' or request.get('analysis_id') != self.analysis_id:
            raise ValueError('Dynamic session mismatch')
        recovery = getattr(getattr(self, 'dynamic', None), 'recovery', None)
        if recovery and recovery.state != 'ready' and not getattr(self, 'restoring', False):
            if request.get('action') not in ('recovery_status', 'request_followup', 'screen_observe', 'finish_investigation'):
                raise RuntimeError('Guest recovery in progress; do not replay commands: ' + json.dumps(recovery.status()))
        if request.get('action') in ('health', 'process_status', 'screen_observe', 'desktop_status', 'desktop_events', '_desktop_picture', '_review_stall'):
            return
        if request.get('action') in ('recovery_status', 'request_followup') and not self.closed:
            return
        if request.get('action') == 'finish_investigation' and self.completion is not None:
            return
        if self.closed or self.completion is not None or self.deadline is None or time.monotonic() >= self.deadline:
            raise RuntimeError('Dynamic operation window is not open')

    # 完了通知はモデルの文章から推測せず、冪等なMCP操作として記録する。
    def finish_request(self, request):
        if request.get('action') == 'recovery_status':
            recovery = getattr(self.dynamic, 'recovery', None)
            return {'ok': True, 'result': recovery.status(request.get('after_sequence', 0)) if recovery else {'enabled': False}}
        if request.get('action') == 'request_followup':
            from dynamic_followup import validate_request
            self.review_request = validate_request(request, self.dynamic.settings.get('recovery', {}))
            return {'ok': True, 'result': {'accepted': True, 'request': self.review_request,
                                          'instruction': 'Call finish_investigation; Host will process the request.'}}
        if self.completion is not None:
            return {'ok': True, 'result': dict(self.completion, investigation_finished=True)}
        summary = request.get('summary')
        unresolved = request.get('unresolved', [])
        if not isinstance(summary, str) or not summary.strip() or not isinstance(unresolved, list) or any(not isinstance(v, str) for v in unresolved):
            raise ValueError('summary and a string array unresolved are required')
        self.completion = {'summary': summary, 'unresolved': unresolved, 'completed_utc': time.time()}
        return {'ok': True, 'result': dict(self.completion, investigation_finished=True)}

    # 準備・Hook確認の時間を除き、実際の観測開始から上限を数える。
    def begin(self):
        self.dynamic.begin_investigation()
        self.deadline = time.monotonic() + self.dynamic.settings['llm_control']['max_duration_seconds']
        self.dynamic.start_recovery(self.restore_after_boot)

    # 動的専用テンプレートへ信頼できる設定とユーザー指示を埋め込む。
    def prompt(self, language):
        from string import Template
        options = self.dynamic.settings['llm_control']
        path = Path(__file__).resolve().parent / 'prompts/dynamic_analysis.md'
        return Template(path.read_text(encoding='utf-8')).substitute(language=language, analysis_id=self.analysis_id,
            sample_path=self.sample_path, sample_sha256=self.sha256, protected_host_path=str(self.source.resolve()),
            allow_guest_elevation=options['allow_guest_elevation'], max_duration_seconds=options['max_duration_seconds'],
            instructions=self.instructions, guest_root=self.settings.guest_root,
            archive_path=self.archive_path or 'ZIP入力なし')

    # 画像のBase64を会話ログへ重複保存せず、操作時刻・要求・結果を後続の解析へ渡す。
    def export_interactions(self):
        import sqlite3
        from contextlib import closing
        import shutil

        # MCP画像本体だけを省き、座標・フレームID・操作結果は保持する。
        def without_images(value):
            if isinstance(value, dict):
                return {key: without_images(item) for key, item in value.items() if key != 'image'}
            if isinstance(value, list):
                return [without_images(item) for item in value]
            return value

        with closing(sqlite3.connect(self.bridge.db)) as database, \
                (self.dynamic.output / 'dynamic_actions.jsonl').open('w', encoding='utf-8') as output:
            for identity, request, state, response in database.execute('SELECT id,request,state,response FROM requests ORDER BY rowid'):
                output.write(json.dumps({'id': identity, 'request': json.loads(request), 'state': state,
                    'response': without_images(json.loads(response)) if response else None}, ensure_ascii=False) + '\n')
        for source in (self.state / 'frames').glob('*.png'):
            shutil.copy2(source, self.dynamic.output / ('dynamic_screen_' + source.name))

    # エラー時も起動結果を回収し、Host側の対話記録を検体原本とは分けて保存する。
    def finalize(self, failure=None, failure_details=None):
        if getattr(self.dynamic, 'recovery', None) is not None:
            try:
                self.dynamic.close_recovery()
            except Exception as error:
                failure = (failure or '') + '; recovery finalization: ' + str(error)
        self.closed = True
        jobs = []
        failures = [failure_details] if failure_details else []
        try:
            marker = self.state / 'closed.json'
            marker.write_text('{}', encoding='utf-8')
            self.guest('copyFileFromHostToGuest', str(marker), self.settings.guest_root + '\\closed.json')
            self.bridge.close_intake(timeout=30)
            jobs = self.request('os', 'process_status')['result']['jobs']
        except Exception as error:
            failure = (failure or '') + '; process status: ' + str(error)
            failures.append(error_details(error))
        try:
            self.export_interactions()
        except Exception as error:
            failure = (failure or '') + '; interaction export: ' + str(error)
            failures.append(error_details(error))
        sample_jobs = [job for job in jobs if job.get('sample')]
        execution = {'started': any(job.get('started') for job in sample_jobs), 'mode': 'llm',
                     'reason': 'investigation_finished' if self.completion and not failure else 'investigation_incomplete',
                     'jobs': jobs, 'completion': self.completion, 'error': failure,
                     'error_details': {'vmrun_errors': [entry for item in failures for entry in item.get('vmrun_errors', [])]},
                     'tracking': 'direct jobs only; correlate descendants and injection with Sysmon'}
        (self.dynamic.output / 'dynamic_interaction.json').write_text(json.dumps(execution, ensure_ascii=False, indent=2), encoding='utf-8')
        try:
            self.dynamic.end_investigation(execution)
        except Exception:
            if getattr(self.dynamic, 'recovery', None) is None:
                raise
        finally:
            self.disconnect()
