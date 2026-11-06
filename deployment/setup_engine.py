"""GUI/CLI共通の初期構築・修復エンジン。署名済みGuest配布を適用する。"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import time
import uuid
from contextlib import nullcontext
from . import credentials, releases
from .storage import atomic_json, digest, installation_lock
from .vm import VMware, REMOTE, quote
from .payload import HOOK_FILES, require_files
from . import external_tools, guest_downloads


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
    if plan.get('registry_profile','existing') not in ('existing','analysis','official_api'):
        raise ValueError('Unsupported Guest protection profile')
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
    def __init__(self, plan, secret, manifest, report=print, vm_factory=VMware):
        self.plan, self.secret, self.manifest, self.report = plan, secret, manifest, report
        self.root = Path(plan["install_dir"]).resolve()
        self.release = self.root / "versions" / manifest["version"]
        self.vm_factory = vm_factory
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
        self.vm.shutdown()
        self.vm.isolate(self.state["segment"])
        self.vm.run("snapshot", self.vm.vmx, name, timeout=600)

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
            names = self.state["snapshots"]
            if self.state["completed"] == "none":
                if self.vm.running():
                    raise RuntimeError("Selected VM is running. Shut it down before setup; no snapshot was reverted.")
                if self.plan["mode"] == "copy":
                    if Path(self.plan['clone_path']).exists():
                        raise ValueError('Clone destination already exists; no files were overwritten')
                    from .vm_copy import copy_stopped_vm
                    copy_stopped_vm(self.vm.vmx, self.plan['clone_path'], self.vm.running, self.report)
                    self.vm.vmx = self.plan["clone_path"]
                self.state["vmx"] = self.vm.vmx
                self.vm.run("snapshot", self.vm.vmx, names["before_setup"], timeout=600)
                self.checkpoint("prepared")
            self.vm.vmx = self.state["vmx"]
            if self.state["completed"] == "prepared":
                self.report("Guest common: restoring baseline, isolating network and waiting for startup")
                self.vm.shutdown()
                self.vm.run("revertToSnapshot", self.vm.vmx, self.plan.get("base_snapshot") or names["before_setup"], timeout=600)
                self.vm.isolate(self.state["segment"])
                self.boot_guest()
                self.stage_guest()
                self.guest_phase("common")
                self.configure_login()
                self.vm.shutdown()
                self.boot_guest()
                self.guest_phase("verify-common")
                self.save_snapshot(names["common"])
                self.checkpoint("common")
            for phase, preceding in (("dynamic", "common"), ("static", "dynamic")):
                if self.state["completed"] == preceding:
                    self.report("Guest " + phase + ": restoring baseline and waiting for startup")
                    self.vm.shutdown()
                    baseline=self.state.get('previous_snapshots',{}).get(phase,names['common'])
                    self.vm.run("revertToSnapshot", self.vm.vmx, baseline, timeout=600)
                    self.boot_guest()
                    if 'previous_snapshots' in self.state:
                        self.stage_guest()
                        self.guest_phase('common')
                        self.configure_login()
                    self.guest_phase(phase)
                    self.vm.shutdown()
                    self.boot_guest()
                    self.guest_phase("verify-" + phase)
                    self.save_snapshot(names[phase])
                    self.checkpoint(phase)
            if self.state["completed"] == "static":
                for phase in ("dynamic", "static"):
                    self.vm.run("revertToSnapshot", self.vm.vmx, names[phase], timeout=600)
                    self.boot_guest()
                    self.guest_phase("verify-" + phase)
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
        settings['static_vm']['security_strategy']='official_api_v1' if self.plan.get('registry_profile')=='official_api' else 'legacy_snapshot'
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
