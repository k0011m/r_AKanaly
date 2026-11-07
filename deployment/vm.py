"""セットアップ専用Guest Operations。個人用設定を読み込まない。"""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
from vmrun_errors import decode_output, VmrunError
from vmrun_transfer import run_staged

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
REMOTE = r"C:\Users\Public\r_AKanaly\installer"

# PowerShellの単一引用符文字列だけを生成する。
def quote(value):
    return "'" + str(value).replace("'", "''") + "'"

class VMware:
    # 元VMを復元・起動せず、指定保存点から独立した完全クローンを作る。
    def clone_from_snapshot(self, destination, snapshot):
        destination = Path(destination).resolve()
        if destination.exists() or destination.parent.is_relative_to(Path(self.vmx).resolve().parent):
            raise ValueError('Clone destination must be new and outside the source VM directory')
        if self.running() or self.snapshots().count(snapshot) != 1:
            raise RuntimeError('Clone requires a stopped source VM and a unique snapshot')
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.run('clone', self.vmx, str(destination), 'full', '-snapshot=' + snapshot,
                 '-cloneName=r_AKanaly Setup', timeout=7200)
        if not destination.is_file():
            raise RuntimeError('Full clone did not create the destination VMX; source preserved')

    # vmrunの件数ヘッダーを除き、復元に使用する保存点名を読み取る。
    def snapshots(self):
        output=self.run('listSnapshots',self.vmx)
        return [line.strip() for line in output.splitlines()[1:] if line.strip()]

    # 認証はメモリ内に限定し、コマンドラインを診断出力へ含めない。
    def __init__(self, vmrun, vmx, username, password, encryption="", runner=subprocess.run):
        self.vmrun, self.vmx, self.username = str(vmrun), str(vmx), username
        self.password, self.encryption, self.runner = password, encryption, runner

    # 終了コードと表示文を分離し、例外から秘密値を除く。
    def run(self, *args, guest=False, timeout=180):
        command = [self.vmrun, "-T", "ws"]
        if self.encryption:
            command += ["-vp", self.encryption]
        if guest:
            command += ["-gu", self.username, "-gp", self.password]
        command += list(map(str, args))
        try:
            response = run_staged(command, self.runner, capture_output=True, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired:
            raise VmrunError(None, operation=str(args[0]), timed_out=True) from None
        stdout, stderr = decode_output(response.stdout), decode_output(response.stderr)
        if response.returncode:
            # 一覧のVMパス等を壊さないよう、機械判定用の成功応答は加工しない。
            for secret in sorted({self.password, self.encryption, self.username}, key=len, reverse=True):
                if secret:
                    stdout = stdout.replace(secret, "[REDACTED]")
                    stderr = stderr.replace(secret, "[REDACTED]")
            raise VmrunError(response.returncode, stdout, operation=str(args[0]), stderr=stderr)
        return stdout + stderr

    # VMの稼働とGuestの応答は別々に確認する。
    def running(self):
        return str(Path(self.vmx).resolve()).casefold() in {line.strip().casefold() for line in self.run("list").splitlines()[1:]}

    # 準備完了までの待機に上限を設ける。
    def boot(self):
        if not self.running():
            self.run("start", self.vmx, "nogui")
        deadline = time.monotonic() + 300
        while True:
            try:
                self.run("listProcessesInGuest", self.vmx, guest=True, timeout=30)
                return
            except RuntimeError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(3)

    # Agent未導入の転送中からGuestの自動スリープを防ぎ、保存点にも同じ電源設定を残す。
    def prepare_setup_power(self):
        body = r"""
$powercfg=Join-Path $env:WINDIR 'System32\powercfg.exe'
foreach($setting in @('standby-timeout-ac','standby-timeout-dc','hibernate-timeout-ac','hibernate-timeout-dc')) {
    & $powercfg /change $setting 0 | Out-Null
    if($LASTEXITCODE -ne 0) { throw ('Guest power setting failed: '+$setting) }
}
$values=@{}
foreach($setting in @('STANDBYIDLE','HIBERNATEIDLE')) {
    $lines=& $powercfg /query SCHEME_CURRENT SUB_SLEEP $setting
    if($LASTEXITCODE -ne 0) { throw ('Guest power readback failed: '+$setting) }
    # 出力言語に依存せず末尾のAC/DC設定値を読み、未反映を成功扱いしない。
    $hex=@([regex]::Matches(($lines -join "`n"),'(?im)0x([0-9a-f]+)\s*$') | ForEach-Object {$_.Groups[1].Value})
    if($hex.Count -lt 2) { throw ('Guest power values missing: '+$setting) }
    $ac=[Convert]::ToUInt32($hex[-2],16); $dc=[Convert]::ToUInt32($hex[-1],16)
    if($ac -ne 0 -or $dc -ne 0) { throw ('Guest idle timeout remains enabled: '+$setting) }
    $values[$setting]=@{ac_seconds=$ac;dc_seconds=$dc}
}
@{complete=$true;idle_timeouts=$values}
"""
        result = self.query(body, elevated=True, timeout=180)
        if not isinstance(result, dict) or result.get('complete') is not True:
            raise RuntimeError('Guest power preparation did not report completion')
        return result

    # ハード停止へ勝手に切り替えず、正常停止を待って保存可能にする。
    def shutdown(self):
        if self.running():
            try:
                self.run("stop", self.vmx, "soft")
            except VmrunError:
                if self.running():
                    # Toolsの状態変更スクリプトが詰まっても、Windows自身の通常停止を試す。
                    # /fやハード電源断は使わず、Guestが応答しなければ失敗を返す。
                    self.run("runProgramInGuest", self.vmx, "-noWait", r"C:\Windows\System32\shutdown.exe", "/s", "/t", "0", guest=True, timeout=30)
        deadline = time.monotonic() + 180
        while self.running():
            if time.monotonic() > deadline:
                raise RuntimeError("Guest shutdown timed out")
            time.sleep(2)

    # 固定スクリプトはUTF-16で渡し、空白や日本語をシェル再解釈させない。
    def ps(self, script, no_wait=False, timeout=180):
        encoded = base64.b64encode(script.encode("utf-16le")).decode()
        return self.run("runProgramInGuest", self.vmx, *(["-noWait", "-interactive"] if no_wait else []), POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded, guest=True, timeout=timeout)

    # 転送の前後でSHA-256を照合し、パス不存在と破損を区別する。
    def upload(self, source, destination):
        from .storage import digest
        self.ps("New-Item -ItemType Directory -Force -Path (Split-Path -Parent " + quote(destination) + ") | Out-Null")
        self.run("copyFileFromHostToGuest", self.vmx, source, destination, guest=True, timeout=1800)
        self.ps("$ErrorActionPreference='Stop'; if((Get-FileHash -LiteralPath " + quote(destination) + ").Hash -ne " + quote(digest(source)) + "){throw 'Transfer hash mismatch'}")

    # GuestからのJSONは要求IDを照合し、以前の成功結果を誤用しない。
    def query(self, body, elevated=False, timeout=900):
        nonce = uuid.uuid4().hex
        target = REMOTE + "\\result-" + nonce + ".json"
        script = "$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force -Path " + quote(REMOTE) + " | Out-Null; $r=@{id=" + quote(nonce) + ";ok=$false}; try {$r.value=& {" + body + "}; $r.ok=$true} catch {$r.error=$_.Exception.Message}; $r | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath " + quote(target) + " -Encoding UTF8"
        if elevated:
            # 非対話Guest Operationsの既存トークンを調べ、昇格済みなら同じ経路を維持する。
            administrator = self.query("@{administrator=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}", timeout=60)
            if administrator.get('administrator') is True:
                self.ps(script, timeout=timeout)
            else:
                self._request_elevation(script, nonce, target)
        else:
            self.ps(script, timeout=timeout)
        return self._wait_response(nonce, target, timeout)

    # 未昇格の対話セッションだけ標準UACを要求し、起動拒否も結果として返す。
    def _request_elevation(self, script, nonce, target):
        encoded = base64.b64encode(script.encode("utf-16le")).decode()
        # 標準UACはGuestで承認する。署名検証済み配置スクリプトを実行する間だけ実行ポリシーを指定する。
        # MachinePolicy/UserPolicyを変更せず、Guest全体に許可設定を残さない。
        # Guest Operationsが既に管理者トークンを持つ場合、不可視セッションで再昇格を要求しない。
        principal = "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        launch = "Start-Process powershell.exe -Verb RunAs -ErrorAction Stop -ArgumentList " + quote("-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded)
        failure = "$r=@{id=" + quote(nonce) + ";ok=$false;error=$_.Exception.Message}; $r | ConvertTo-Json | Set-Content -LiteralPath " + quote(target) + " -Encoding UTF8"
        self.ps("try { if(" + principal + "){ & {" + script + "} } else {" + launch + "} } catch {" + failure + "}", no_wait=True)

    # 応答の要求IDを確認し、秘密値を伏せて成功または失敗を呼出し元へ渡す。
    def _wait_response(self, nonce, target, timeout):
        deadline = time.monotonic() + timeout
        with tempfile.TemporaryDirectory(prefix="rAK-guest-") as temp:
            local = Path(temp) / "result.json"
            while time.monotonic() < deadline:
                try:
                    self.run("copyFileFromGuestToHost", self.vmx, target, local, guest=True, timeout=30)
                    result = json.loads(local.read_text(encoding="utf-8-sig"))
                    if result.get("id") != nonce:
                        raise ValueError("Guest response identity mismatch")
                    if not result.get("ok"):
                        error = str(result.get("error"))
                        for secret in (self.password, self.encryption):
                            if secret:
                                error = error.replace(secret, "[REDACTED]")
                        raise ValueError(error)
                    self.ps("Remove-Item -LiteralPath " + quote(target) + " -Force")
                    return result.get("value")
                except RuntimeError:
                    time.sleep(3)
        raise RuntimeError("Guest response timed out; check Guest UAC / setup status")

    # ツールパスの存在・版とGuest種別を、設定変更なしで取得する。
    def inventory(self, paths):
        encoded = base64.b64encode(json.dumps(paths).encode()).decode()
        return self.query("$paths=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(" + quote(encoded) + ")) | ConvertFrom-Json; $tools=@{}; foreach($p in $paths.PSObject.Properties){$f=Get-Item -LiteralPath $p.Value -ErrorAction SilentlyContinue; $tools[$p.Name]=@{path=$p.Value;exists=($null -ne $f -and -not $f.PSIsContainer);version=$f.VersionInfo.FileVersion}}; @{manufacturer=(Get-CimInstance Win32_ComputerSystem).Manufacturer;architecture=(Get-CimInstance Win32_OperatingSystem).OSArchitecture;tools=$tools}")

    # 停止中だけNICを隔離LANへ変更し、その他のVMX設定を保持する。
    def isolate(self, segment):
        import re
        if self.running():
            raise RuntimeError("VM must be stopped before changing network")
        path = Path(self.vmx)
        original = path.read_text(encoding="utf-8")
        # VMwareが保存する16バイト表記へ合わせ、通常のUUID文字列を直接書かない。
        parts = [f'{value:02x}' for value in uuid.UUID(segment).bytes]
        pvn_id = ' '.join(parts[:8]) + '-' + ' '.join(parts[8:])
        prefixes = re.findall(r'(?mi)^\s*(ethernet\d+)\.present\s*=\s*"TRUE"', original)
        settings = {"isolation.tools.copy.disable": "TRUE", "isolation.tools.paste.disable": "TRUE", "isolation.tools.hgfs.disable": "TRUE", "sharedFolder.maxNum": "0"}
        for prefix in prefixes:
            settings.update({prefix + ".connectionType": "pvn", prefix + ".pvnID": pvn_id})
        for key, value in settings.items():
            pattern = rf'(?mi)^\s*{re.escape(key)}\s*=.*$'
            line = f'{key} = "{value}"'
            original = re.sub(pattern, lambda match: line, original) if re.search(pattern, original) else original + "\n" + line
        temporary = path.with_suffix(".vmx.setup-tmp")
        temporary.write_text(original, encoding="utf-8")
        temporary.replace(path)
