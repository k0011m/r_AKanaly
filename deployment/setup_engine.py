"""GUI/CLI共通の初期構築・修復エンジン。署名済みGuest配布を適用する。"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import time
import uuid
import zipfile
import tempfile
from contextlib import nullcontext
from . import credentials, releases
from .storage import atomic_json, digest, installation_lock
from .vm import VMware, REMOTE, quote
from .payload import HOOK_FILES, require_files
from . import external_tools, guest_downloads
from vmrun_errors import VmrunError


# 通信障害や構文エラーを保護設定の再試行と混同しないための構造化例外。
class ProtectionVerificationError(RuntimeError):
    def __init__(self, message, security):
        super().__init__(message)
        self.security = security


# 変更前にHost・配布内容・入力値をまとめて検査する。
def preflight(plan, release_root):
    require_files(release_root, HOOK_FILES)
    if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise ValueError("Windows x64 Host is required")
    for key in ("vmrun", "vmx"):
        if not Path(plan[key]).is_file():
            raise ValueError(key + " not found")
    if plan.get('host_procmon') and not Path(plan['host_procmon']).is_file():
        raise ValueError('Host Procmon not found')
    if plan["mode"] not in ("existing", "copy") or not plan["username"].strip():
        raise ValueError("Invalid VM mode / username")
    if plan.get('registry_profile','existing') not in ('existing','analysis','official_api','manual_registry','group_policy'):
        raise ValueError('Unsupported Guest protection profile')
    if plan.get('registry_profile') in ('manual_registry','group_policy') and not str(plan.get('base_snapshot') or '').strip():
        raise ValueError('Manual registry setup requires a prepared baseline snapshot')
    if plan["mode"] == "copy" and (not Path(plan["clone_path"]).is_absolute() or Path(plan["clone_path"]).suffix.lower() != '.vmx'):
        raise ValueError("Clone path must be an absolute .vmx path")
    for name in ("guest.zip", "guest-manifest.json", "r_AKanaly_setting.example.json", 'sysinternals-downloads.json', 'r_AKanaly_guard.exe', 'r_AKanaly_ghidra_mcp.exe'):
        if not (Path(release_root) / name).is_file():
            raise ValueError("Release setup payload missing: " + name)
    external_tools.load_downloads(release_root, plan.get('accept_sysinternals_license'))
    guest_downloads.load(release_root)
    manifest = json.loads((Path(release_root) / "guest-manifest.json").read_text())
    if manifest.get("schema") != 1 or digest(Path(release_root) / "guest.zip") != manifest.get("sha256"):
        raise ValueError("Guest bundle hash/schema mismatch")
    for key in ("install_dir", "output_dir"):
        path = Path(plan[key])
        if not path.is_absolute():
            raise ValueError(key + " must be absolute")
        while not path.exists():
            path = path.parent
        if shutil.disk_usage(path).free < manifest.get("required_free_bytes", 10 * 1024**3):
            raise ValueError("Insufficient disk space: " + key)
    return manifest


# 個人用設定を使わず、画面で指定されたVMだけを構築する。
class SetupEngine:
    # 認証情報は進捗に含めず、構築内容のハッシュだけで再開先を照合する。
    def __init__(self, plan, secret, manifest, report=print, vm_factory=VMware, request_action=None):
        self.plan, self.secret, self.manifest, self.report = plan, secret, manifest, report
        self.root = Path(plan["install_dir"]).resolve()
        self.release = self.root / "versions" / manifest["version"]
        self.vm_factory = vm_factory
        self.request_action = request_action
        self.state_file = self.root / ("setup-state-" + manifest['version'] + ".json")
        self.plan_hash = hashlib.sha256(json.dumps({"plan": plan, "release": manifest["sha256"]}, sort_keys=True).encode()).hexdigest()

    # 保存点を復元してもHost側の進捗と秘密値を混ぜない。
    def checkpoint(self, phase):
        self.state["completed"] = phase
        atomic_json(self.state_file, self.state)
        self.report(phase + ": complete")

    # 未導入VMにも先に電源設定を適用し、大容量転送や構築中の自動サスペンドを防ぐ。
    def boot_guest(self):
        self.vm.boot()
        self.report('Guest power: disabling and verifying automatic sleep/hibernate (UAC may be required)')
        result = self.vm.prepare_setup_power()
        atomic_json(self.root / 'setup-reports' / 'power.json', result)

    # 手動設定待ちの間は復元せず、再開後も同じGuestの実状態を確認する。
    def verify_manual_common(self):
        if self.request_action is None:
            raise RuntimeError('Manual Guest setup required; resume with the Setup GUI. Guest state has been preserved.')
        while True:
            if not self.request_action({'kind':'manual_registry','vmx':self.vm.vmx}):
                raise RuntimeError('Manual setup paused; Guest state has been preserved.')
            self.vm.boot()
            try:
                self.guest_phase('verify-common')
                return
            except RuntimeError as error:
                self.report(str(error))
                # 失敗後も基点へ戻さず、ユーザーが修正したGuestを次の確認に使う。

    # Agent配置前に署名済み配布物の読取り専用検証を実行し、起点の実効状態を記録する。
    def verify_manual_baseline(self):
        self.report('Guest baseline: verifying prepared registry and effective protection before deployment (UAC may be required)')
        with zipfile.ZipFile(self.release/'guest.zip') as archive:
            script=archive.read('dynamic/defender_gate.ps1').decode('utf-8-sig')
        # 長いスクリプトをEncodedCommandへ埋め込むとWindowsの引数上限を超えるため、検証用ファイルだけを一時転送する。
        remote=REMOTE+'\\baseline-check-'+uuid.uuid4().hex+'.ps1'
        try:
            with tempfile.TemporaryDirectory(prefix='rAK-baseline-') as directory:
                local=Path(directory)/'baseline-check.ps1'
                local.write_text(script,encoding='utf-8-sig')
                self.vm.upload(local,remote)
                option=' -GroupPolicy' if self.plan.get('registry_profile')=='group_policy' else ''
                result=self.vm.query('. '+quote(remote)+'; Confirm-GuestManualProtection'+option,elevated=True,timeout=300)
        finally:
            try:self.vm.ps('Remove-Item -LiteralPath '+quote(remote)+' -Force -ErrorAction SilentlyContinue')
            except Exception:self.report('Guest baseline diagnostic cleanup could not be confirmed')
        valid=isinstance(result,dict) and result.get('success') is True
        checks=result.get('registry_checks',[]) if isinstance(result,dict) else []
        configured=any(row.get('read_success') is True and row.get('kind') in ('DWord','QWord') and type(row.get('value')) is int and row['value']==1 for row in checks)
        if self.plan.get('registry_profile')=='group_policy':
            # ポリシー方式はレジストリ値で判定せず、読み取った四項目の証拠を照合する。
            from guest_protection import valid_group_policy_evidence
            configured=valid_group_policy_evidence(result)
        atomic_json(self.root/'setup-reports'/'verify-baseline.json',{'snapshot':self.plan['base_snapshot'],'security':result,'complete':bool(valid and configured)})
        if not valid or not configured:
            reason=result.get('error') if isinstance(result,dict) else 'Invalid Guest response'
            if not reason and self.plan.get('registry_profile')=='group_policy':
                reason='Group Policy effective-state evidence is incomplete or invalid'
            after=result.get('after',{}) if isinstance(result,dict) else {}
            raise ProtectionVerificationError('Prepared baseline verification failed: '+str(reason or 'DisableAntiSpyware integer value 1 was not found')+'; state='+json.dumps(after,ensure_ascii=False)+'; Guest preserved; no tools or Agents installed', result)

    # UAC結果を受け取ってから次へ進み、標準ユーザー実行で成功としない。
    def guest_phase(self, phase):
        # UAC承認を求める前に、実際のGuest PowerShellで配布スクリプトを構文検査する。
        self.vm.ps("$ErrorActionPreference='Stop'; $files=@(Get-ChildItem -LiteralPath " + quote(REMOTE + "\\payload") + " -Filter *.ps1 -Recurse); foreach($f in $files){$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$t,[ref]$e)|Out-Null;if($e.Count){throw ($f.FullName+': '+($e.Message -join '; '))}}", timeout=300)
        self.report("Guest " + phase + " (UAC approval may be required)")
        body = "& " + quote(REMOTE + "\\payload\\provision.ps1") + " -Phase " + quote(phase) + " -User " + quote(self.plan["username"])
        # Guestの検証失敗も構造化して回収し、再起動後の実状態を失わない。
        body = "try { " + body + " } catch { @{complete=$false;error=$_.Exception.Message;security=$_.Exception.Data['security']} }"
        result = self.vm.query(body, elevated=True, timeout=1800)
        if not isinstance(result, dict) or result.get("complete") is not True:
            failure = result if isinstance(result, dict) else {"complete": False, "error": "Invalid Guest response"}
            failure = dict(failure, phase=phase)
            # 失敗本文にも資格情報を残さず、成功レポートとは別に保存する。
            error = str(failure.get('error') or 'Guest phase did not report completion')
            for secret in (self.secret.get('guest_password'), self.secret.get('vm_password')):
                if secret:
                    error = error.replace(secret, '[REDACTED]')
            failure['error'] = error
            atomic_json(self.root / 'setup-reports' / (phase + '-failed.json'), failure)
            if isinstance(failure.get('security'), dict):
                raise ProtectionVerificationError(phase + ': ' + error, failure['security'])
            raise RuntimeError(phase + ': ' + error)
        # 一方のキーで完了条件を満たしても、他方の書込み拒否を進捗から隠さない。
        for entry in (result.get('registry') or {}).get('keys', []):
            if not entry.get('success'):
                self.report('Guest registry warning: ' + entry['path'] + ': ' + entry.get('error', 'readback mismatch'))
        atomic_json(self.root / "setup-reports" / (phase + ".json"), result)

    # 共通基点にも配置パッケージを残し、分岐後の再転送を不要にする。
    def stage_guest(self):
        self.report("Guest payload: transferring and verifying SHA-256")
        self.vm.upload(self.release / "guest.zip", REMOTE + "\\guest.zip")
        self.report("Guest payload: extracting verified archive")
        self.vm.ps("$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath " + quote(REMOTE + "\\guest.zip") + " -DestinationPath " + quote(REMOTE + "\\payload") + " -Force", timeout=1800)
        # 第三者ツールは署名済み製品ZIPと分離し、利用者のHostで取得・照合したものを転送する。
        self.report("Guest external tools: transferring and verifying SHA-256")
        self.vm.upload(self.downloaded_guest_tools, REMOTE + '\\guest-tools.zip')
        self.report("Guest external tools: extracting verified archive")
        self.vm.ps("$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath " + quote(REMOTE + '\\guest-tools.zip') + " -DestinationPath " + quote(REMOTE + '\\payload') + " -Force", timeout=1800)
        self.report("Guest external tools: extracted; deploying Sysinternals and setup choices")
        # 利用者が公式サイトから取得したツールを、Guestの構築資材として転送する。
        for name, path in self.external_paths.items():
            self.vm.upload(path, REMOTE + "\\payload\\" + name)
        # 非秘密の構築選択だけをGuestへ渡す。配布側のチェック処理が再検証する。
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "choices.json"
            atomic_json(path, {"tools": self.plan.get("guest_tools", {}), "registry_profile": self.plan.get("registry_profile", "existing")})
            self.vm.upload(path, REMOTE + "\\payload\\choices.json")

    # 設定後の再起動と実状態確認を必ず保存点作成より先に行う。
    def save_snapshot(self, name):
        if name == self.plan.get('base_snapshot') or name in self.vm.snapshots():
            raise RuntimeError('Existing snapshot is protected; refusing to reuse name: ' + name)
        self.vm.shutdown()
        self.vm.isolate(self.state["segment"])
        self.vm.run("snapshot", self.vm.vmx, name, timeout=600)

    # 修正はユーザーへ依頼し、完了後の読取り検証と保存点更新だけを自動化する。
    def verify_with_repair(self, check, source, rebuild=None):
        pending = getattr(self, 'state', {}).get('registry_recovery', {}).get(source)
        resuming = bool(pending and pending.get('status') == 'waiting_for_user')
        diagnostic = {}
        if not resuming:
            try:
                check()
                return
            except ProtectionVerificationError as error:
                if self.plan.get('registry_profile') not in ('manual_registry','group_policy'):
                    raise
                diagnostic = {'message': str(error), 'security': error.security}
        if self.request_action is None:
            raise RuntimeError('Manual Guest repair required; open Setup GUI. Guest preserved.')
        if self.vm.snapshots().count(source) != 1:
            raise RuntimeError('Recovery source must exist uniquely: ' + source)
        if resuming:
            # 中断後は現在の手動修正を維持し、元の保存点へ戻さない。
            recovery = pending
            failed = recovery['failed_snapshot']
        else:
            failed = 'r_AKanaly_failed_' + uuid.uuid4().hex
            recovery = {'source_snapshot': source, 'failed_snapshot': failed,
                        'phase': self.state['completed'], 'status': 'preparing_manual',
                        'diagnostic': diagnostic}
            self.state.setdefault('registry_recovery', {})[source] = recovery
            atomic_json(self.state_file, self.state)
            self.save_snapshot(failed)
            self.vm.run('revertToSnapshot', self.vm.vmx, source, timeout=600)
            self.vm.isolate(self.state['segment'])
            self.vm.boot()
        while True:
            recovery['status'] = 'waiting_for_user'
            atomic_json(self.state_file, self.state)
            if not self.request_action({'kind': 'manual_registry_recovery', 'vmx': self.vm.vmx,
                                        'source_snapshot': source, 'failed_snapshot': failed,
                                        'original_vmx': self.state.get('source_vmx', self.plan.get('vmx', '')),
                                        'original_snapshot': self.state.get('source_snapshot', self.plan.get('base_snapshot', '')),
                                        'diagnostic': recovery.get('diagnostic', {})}):
                raise RuntimeError('Manual repair paused; Guest preserved; source: ' + source)
            # ユーザーが再起動・確認・シャットダウンを終えるまで電源操作をしない。
            if self.vm.running():
                self.report('Guest is still running. Please shut it down after manual verification.')
                continue
            self.vm.boot()
            try:
                self.verify_manual_baseline()
            except ProtectionVerificationError as error:
                # 再確認で変わった状態も保存し、再開時に古い原因を案内しない。
                recovery['diagnostic'] = {'message': str(error), 'security': error.security}
                self.report(str(error))
                continue
            # 起動後の実状態を検証してから正常停止し、停止状態を保存する。
            self.vm.shutdown()
            from .snapshot_recovery import clone_snapshot
            replacement = clone_snapshot(self.vm, source,
                self.root / 'setup-reports' / ('snapshot-recovery-' + uuid.uuid4().hex + '.json'),
                {'failed_snapshot': failed, 'phase': self.state['completed']})
            self.state.setdefault('snapshot_clones', {})[source] = replacement['recovery_snapshot']
            for key, value in self.state.get('snapshots', {}).items():
                if value == source:
                    self.state['snapshots'][key] = replacement['recovery_snapshot']
            recovery.update(status='complete', replacement=replacement)
            atomic_json(self.state_file, self.state)
            self.vm.boot()
            if rebuild is not None:
                rebuild()
            check()
            return

    # 起点修復後は共通配置をやり直してから同じ検証へ戻る。
    def rebuild_common(self):
        self.boot_guest()
        self.stage_guest()
        self.guest_phase('common')
        self.configure_login()
        self.vm.shutdown()
        self.boot_guest()

    # 起点修復後に解析種別固有の設定を再適用し、再起動後の検証へ渡す。
    def rebuild_analysis(self, phase):
        self.guest_phase(phase)
        self.vm.shutdown()
        self.boot_guest()

    # 元の選択を保存したまま、Setup内だけで修正済み分岐を参照する。
    def effective_snapshot(self, name):
        seen = set()
        clones = self.state.get('snapshot_clones', {})
        while name in clones:
            if name in seen:
                raise RuntimeError('Snapshot clone mapping contains a cycle')
            seen.add(name)
            name = clones[name]
        return name

    # 自動クローン失敗時だけ手動作成を案内し、元VMへ切り替えて続行しない。
    def create_working_clone(self, destination):
        destination = Path(destination).resolve()
        attempt = self.state.get('clone_attempt')
        if attempt:
            if attempt['destination'] != str(destination) or attempt['source'] != self.vm.vmx or attempt['snapshot'] != self.plan['base_snapshot']:
                raise RuntimeError('Clone attempt differs from the original setup inputs')
        else:
            if destination.exists():
                raise ValueError('Clone destination already exists; no files were overwritten')
            attempt = {'destination': str(destination), 'source': self.vm.vmx,
                       'snapshot': self.plan['base_snapshot'], 'status': 'automatic'}
            self.state['clone_attempt'] = attempt
            atomic_json(self.state_file, self.state)
        if attempt['status'] == 'automatic':
            try:
                self.vm.clone_from_snapshot(destination, self.plan['base_snapshot'])
                attempt['status'] = 'created'
                atomic_json(self.state_file, self.state)
                return
            except VmrunError as error:
                attempt.update(status='manual', error=str(error))
                atomic_json(self.state_file, self.state)
                self.report('Automatic full clone failed; manual VMware clone required. Original VM preserved.')
        if self.request_action is None:
            raise RuntimeError('Manual full clone required; open Setup GUI. Original VM preserved.')
        while True:
            if not self.request_action({'kind': 'manual_vm_clone', 'vmx': self.vm.vmx,
                                        'source_snapshot': self.plan['base_snapshot'], 'destination': str(destination),
                                        'error': attempt.get('error', '')}):
                raise RuntimeError('Manual clone paused; original VM preserved')
            try:
                if self.vm.running():
                    raise ValueError('Original VM must remain powered off')
                clone = self.vm_factory(self.plan['vmrun'], str(destination), self.plan['username'],
                                        self.secret['guest_password'], self.secret.get('vm_password', ''))
                if clone.running():
                    raise ValueError('Shut down the new clone before continuing')
                from .clone_validation import verify_full_clone
                result = verify_full_clone(self.vm.vmx, destination)
                # クローン用認証と保存点一覧を読み取り、読めないVMを構築対象にしない。
                if clone.snapshots():
                    raise ValueError('A newly created full clone without existing snapshots is required')
                atomic_json(self.root / 'setup-reports' / 'manual-clone.json', result)
            except (ValueError, RuntimeError, OSError) as error:
                attempt.update(status='manual', error=str(error))
                atomic_json(self.state_file, self.state)
                self.report('Manual clone verification failed: ' + str(error))
                continue
            attempt['status'] = 'created'
            atomic_json(self.state_file, self.state)
            return

    # 登録済み保存点から検証できた状態だけを通常解析へ公開する。
    def apply(self, locked=False):
        self.root.mkdir(parents=True, exist_ok=True)
        with (nullcontext() if locked else installation_lock(self.root)):
            releases.verify_files(self.release, self.manifest)
            self.guest_manifest = preflight(self.plan, self.release)
            self.external_paths = external_tools.prepare(self.release, self.root, self.plan.get('accept_sysinternals_license'), self.report)
            self.downloaded_guest_tools = guest_downloads.prepare(self.release, self.root, self.report)
            if self.state_file.exists():
                self.state = json.loads(self.state_file.read_text(encoding="utf-8"))
                if self.state["plan_hash"] != self.plan_hash:
                    raise ValueError("Another setup state exists; use its original inputs or a new installation directory")
            else:
                tag = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
                self.state = {"plan_hash": self.plan_hash, "completed": "none", "segment": str(uuid.uuid4()),
                              "snapshots": {key: "r_AKanaly_" + key + "_" + tag for key in ("before_setup", "common", "dynamic", "static")}}
                if (self.root / 'current.json').exists():
                    pointer=json.loads((self.root/'current.json').read_text(encoding='utf-8'))
                    previous=json.loads((self.root/pointer['settings']).read_text(encoding='utf-8'))
                    if Path(previous['vmware']['vmx_path']).resolve() != Path(self.plan['vmx']).resolve():
                        raise ValueError('Update must target the installed VM')
                    self.state['previous_snapshots']={'dynamic':previous['vmware']['snapshot_name'],'static':previous['static_vm']['snapshot_name']}
                atomic_json(self.state_file, self.state)
            self.vm = self.vm_factory(self.plan["vmrun"], self.plan["vmx"], self.plan["username"], self.secret["guest_password"], self.secret.get("vm_password", ""))
            manual=self.plan.get('registry_profile') in ('manual_registry','group_policy')
            names = self.state["snapshots"]
            if self.state["completed"] == "none":
                if self.vm.running():
                    raise RuntimeError("Selected VM is running. Shut it down before setup; no snapshot was reverted.")
                if manual and self.vm.snapshots().count(self.plan.get('base_snapshot'))!=1:
                    raise ValueError('Prepared baseline snapshot must exist uniquely in selected VM')
                if manual:
                    # 手動方式では「既存VMを使用」の入力でも元VMを変更せず完全クローンを使用する。
                    destination = (Path(self.state['clone_attempt']['destination']) if self.state.get('clone_attempt') else
                                   (Path(self.plan['clone_path']) if self.plan['mode'] == 'copy'
                                    else self.root / 'vm' / uuid.uuid4().hex / 'r_AKanaly.vmx'))
                    self.report('Creating full VM clone from selected snapshot; original VM will not be modified')
                    self.create_working_clone(destination)
                    self.state['source_vmx'] = self.vm.vmx
                    self.state['source_snapshot'] = self.plan['base_snapshot']
                    self.vm.vmx = str(destination.resolve())
                    self.state['owned_full_clone'] = True
                    # 完全クローンは元の保存点ツリーを持たないため、クローン内の開始保存点を使う。
                    self.state.setdefault('snapshot_clones', {})[self.plan['base_snapshot']] = names['before_setup']
                elif self.plan["mode"] == "copy":
                    if Path(self.plan['clone_path']).exists():
                        raise ValueError('Clone destination already exists; no files were overwritten')
                    from .vm_copy import copy_stopped_vm
                    copy_stopped_vm(self.vm.vmx, self.plan['clone_path'], self.vm.running, self.report)
                    self.vm.vmx = self.plan["clone_path"]
                self.state["vmx"] = self.vm.vmx
                self.vm.run("snapshot", self.vm.vmx, names["before_setup"], timeout=600)
                self.checkpoint("prepared")
            self.vm.vmx = self.state["vmx"]
            if manual and (not self.state.get('owned_full_clone')
                           or Path(self.vm.vmx).resolve() == Path(self.plan['vmx']).resolve()):
                raise RuntimeError('Legacy setup state targets the original VM. Use a new installation directory to create a protected full clone. No source VM operation was performed.')
            # 保存工程の分岐より先に手動待ちを復帰し、再実行で修正状態を復元により失わない。
            for source, recovery in list(self.state.get('registry_recovery', {}).items()):
                if recovery.get('status') == 'waiting_for_user':
                    rebuild = self.rebuild_common if self.state['completed'] == 'common_ready' else None
                    self.verify_with_repair(self.verify_manual_baseline, source, rebuild)
            if self.state["completed"] == "prepared":
                self.report("Guest common: restoring baseline, isolating network and waiting for startup")
                self.vm.shutdown()
                self.vm.run("revertToSnapshot", self.vm.vmx, self.effective_snapshot(self.plan.get("base_snapshot") or names["before_setup"]), timeout=600)
                self.vm.isolate(self.state["segment"])
                if manual:
                    # 起点検証が失敗しても、再試行時に手動修正を上書きしない。
                    self.vm.boot()
                    self.checkpoint('baseline_ready')
                else:
                    self.checkpoint('baseline_verified')
            if self.state['completed']=='baseline_ready':
                self.vm.boot()
                self.verify_with_repair(self.verify_manual_baseline, self.effective_snapshot(self.plan['base_snapshot']))
                self.checkpoint('baseline_verified')
            if self.state['completed']=='baseline_verified':
                self.boot_guest()
                self.stage_guest()
                self.guest_phase("common")
                self.configure_login()
                self.vm.shutdown()
                self.boot_guest()
                self.checkpoint('common_ready')
            if self.state['completed'] == 'common_ready':
                self.vm.boot()
                self.verify_with_repair(lambda: self.guest_phase('verify-common'),
                    self.effective_snapshot(self.plan.get('base_snapshot') or names['before_setup']), self.rebuild_common)
                self.save_snapshot(names["common"])
                self.checkpoint("common")
            for phase, preceding in (("dynamic", "common"), ("static", "dynamic")):
                if self.state["completed"] == preceding:
                    self.report("Guest " + phase + ": restoring baseline and waiting for startup")
                    self.vm.shutdown()
                    baseline=names['common'] if manual else self.state.get('previous_snapshots',{}).get(phase,names['common'])
                    self.vm.run("revertToSnapshot", self.vm.vmx, baseline, timeout=600)
                    self.boot_guest()
                    if 'previous_snapshots' in self.state and not manual:
                        self.stage_guest()
                        self.guest_phase('common')
                        self.configure_login()
                    self.guest_phase(phase)
                    self.vm.shutdown()
                    self.boot_guest()
                    self.verify_with_repair(lambda: self.guest_phase('verify-' + phase),
                        baseline, lambda: self.rebuild_analysis(phase))
                    self.save_snapshot(names[phase])
                    self.checkpoint(phase)
            if self.state["completed"] == "static":
                for phase in ("dynamic", "static"):
                    self.vm.run("revertToSnapshot", self.vm.vmx, names[phase], timeout=600)
                    self.boot_guest()
                    self.verify_with_repair(lambda: self.guest_phase('verify-' + phase), names[phase])
                    self.vm.shutdown()
                self.checkpoint("verified")
            if self.state["completed"] == "verified":
                self.commit()
                self.checkpoint("complete")
                pending=self.root/'pending-update.json'
                if pending.exists() and json.loads(pending.read_text()).get('version') == self.manifest['version']:
                    pending.unlink()
            self.report("Setup complete; no malware was executed")

    # 合意されたGuest自動ログインはGuestだけに適用し、Hostログには値を返さない。
    def configure_login(self):
        key = r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        body = "$p=" + quote(key) + "; Set-ItemProperty -Path $p -Name AutoAdminLogon -Value '1'; Set-ItemProperty -Path $p -Name DefaultUserName -Value " + quote(self.plan["username"]) + "; Set-ItemProperty -Path $p -Name DefaultPassword -Value " + quote(self.secret["guest_password"]) + "; Set-ItemProperty -Path $p -Name DefaultDomainName -Value $env:COMPUTERNAME; @{complete=$true}"
        self.vm.query(body, elevated=True)

    # 設定を世代別に保存してから、版と保存点の組を原子的に切り替える。
    def commit(self):
        current_file = self.root / "current.json"
        if current_file.exists():
            current = json.loads(current_file.read_text(encoding="utf-8"))
            settings = json.loads((self.root / current["settings"]).read_text(encoding="utf-8"))
        else:
            settings = json.loads((self.release / "r_AKanaly_setting.example.json").read_text(encoding="utf-8"))
            settings["malware_transfer"]["host_path"] = None
            settings["malware_transfer"]["guest_path"] = r"C:\Users\Public\r_AKanaly\samples\sample.exe"
            settings["full_auto"]["enabled"] = False
        settings["vmware"].update(vmx_path=self.vm.vmx, vmrun_path=self.plan["vmrun"], snapshot_name=self.state["snapshots"]["dynamic"], encrypted_vm_password_required=bool(self.secret.get("vm_password")))
        settings["guest"].update(username=self.plan["username"], prompt_username=False)
        settings["credentials"]["env_file_path"] = None
        settings["static_vm"].update(enabled=True, snapshot_name=self.state["snapshots"]["static"], guest_root=r"C:\Users\Public\CodexGuestAgent\analysis_bench", guest_python=r"C:\Users\Public\r_AKanaly\runtime\python\pythonw.exe")
        settings['static_vm']['security_strategy']={'official_api':'official_api_v1','manual_registry':'manual_registry_v1','group_policy':'group_policy_v1'}.get(self.plan.get('registry_profile'),'legacy_snapshot')
        selected_python = self.plan.get('guest_tools', {}).get('Python (Ghidra / PyGhidra)', {})
        if selected_python.get('reuse'):
            settings['static_vm']['guest_python'] = selected_python['path']
        settings["dynamic_analysis"]["guest_root"] = r"C:\Users\Public\r_AKanaly\dynamic"
        settings["llm"]["analysis_output_dir"] = self.plan["output_dir"]
        settings["llm"]["codex_project_dir"] = str(self.root / "config/analysis_project")
        settings["output_directories"].update(use_common_output_dir=True, common_output_dir=self.plan["output_dir"])
        settings["dynamic_analysis"]["host_procmon_path"] = self.plan.get('host_procmon') or str(self.external_paths['Procmon64.exe'])
        settings["developer_variables"]["dev_var"] = False
        settings["developer_variables"]["codex_app_full_path"] = None
        path = self.root / "config" / (self.state["snapshots"]["common"] + ".json")
        atomic_json(path, settings)
        Path(self.plan["output_dir"]).mkdir(parents=True, exist_ok=True)
        credentials.save(self.root, {"R_AKANALY_GUEST_OS_PASSWORD": self.secret["guest_password"], "R_AKANALY_VMWARE_PASSWORD": self.secret.get("vm_password", "")})
        releases.activate(self.root, self.manifest, path, self.manifest["guest_revision"])
        atomic_json(self.root / 'installed-setup-plan.json', self.plan)
        # 正常導入先だけを登録し、失敗時は完了にせず同じ設定で再試行できるようにする。
        from .user_environment import register_installation
        environment = register_installation(self.root)
        atomic_json(self.root / 'setup-reports' / 'user-environment.json', environment)
        self.report('User environment registered; reopen Terminal to use r_AKanaly from PATH')
