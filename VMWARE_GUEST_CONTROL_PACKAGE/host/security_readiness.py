"""インストール済みGuestの公式API方式を、検体転送前にHostから実行・検証する。"""
import base64
import json
import uuid


# 固定タスクへ再適用を要求し、古いタスク結果ではなく新規照会の実状態を採用する。
def prepare_security(session):
    identity=uuid.uuid4().hex
    session.state.mkdir(parents=True,exist_ok=True)
    guest_result=session.settings.guest_root+'\\code\\security-'+identity+'.json'
    local_result=session.state/'security-readiness.json'
    target="'"+guest_result.replace("'","''")+"'"
    script=r"""
$ErrorActionPreference='Stop'
$root='C:\Users\Public\r_AKanaly\dynamic'
$result=@{request_id='IDENTITY';complete=$false}
try {
    $markerPath=Join-Path $root 'guest-install-marker.json'
    $marker=if(Test-Path -LiteralPath $markerPath){Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json}else{$null}
    if(-not $marker.security_strategy) {
        $result.complete=$true;$result.strategy='legacy_snapshot'
    } elseif($marker.security_strategy -eq 'official_api_v1') {
        $result.strategy='official_api_v1'
        & "$env:WINDIR\System32\schtasks.exe" /Run /TN r_AKanaly_PrepareSecurity | Out-Null
        if($LASTEXITCODE -ne 0){throw 'Guest security preparation task could not be started'}
        $result.security=& (Join-Path $root 'prepare_analysis_security.ps1') -TimeoutSeconds 180
        $result.complete=($result.security.success -eq $true -and $result.security.bypass -eq $false)
        if(-not $result.complete){$result.error='Guest effective protection settings were not confirmed'}
    } elseif($marker.security_strategy -eq 'manual_registry_v1') {
        $result.strategy='manual_registry_v1'
        . (Join-Path $root 'defender_gate.ps1')
        $result.security=Confirm-GuestManualProtection
        $result.complete=($result.security.success -eq $true)
        if(-not $result.complete){$result.error=$result.security.error}
    } else {throw 'Unsupported Guest security strategy'}
} catch {$result.error=$_.Exception.Message}
$result | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath TARGET -Encoding UTF8
""".replace('IDENTITY',identity).replace('TARGET',target)
    previous=session.config['vmrun_timeout_seconds']
    try:
        session.config['vmrun_timeout_seconds']=max(previous,210)
        session.program(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                        ['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',
                         base64.b64encode(script.encode('utf-16le')).decode()])
        session.guest('copyFileFromGuestToHost',guest_result,str(local_result))
        result=json.loads(local_result.read_text(encoding='utf-8-sig'))
        if result.get('request_id')!=identity:
            raise RuntimeError('Guest security response identity mismatch')
        expected=getattr(session.settings,'security_strategy','legacy_snapshot')
        if expected!='legacy_snapshot' and result.get('strategy')!=expected:
            raise RuntimeError('Required Guest security strategy is missing: '+expected)
        if result.get('complete') is not True:
            raise RuntimeError('Guest security preparation failed: '+str(result.get('error','invalid response')))
        return result
    finally:
        session.config['vmrun_timeout_seconds']=previous
