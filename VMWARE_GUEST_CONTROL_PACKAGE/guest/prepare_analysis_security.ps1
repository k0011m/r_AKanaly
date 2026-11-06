param([switch]$Apply,[ValidateRange(10,300)][int]$TimeoutSeconds=120)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
# 固定の解析Guestだけで公式APIを使う。Hostや別VMへの適用を拒否する。
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'VMware') { throw 'VMware Guest only' }
$marker=Get-Content -LiteralPath (Join-Path $root 'guest-install-marker.json') -Raw | ConvertFrom-Json
if($marker.security_strategy -ne 'official_api_v1') { throw 'Official API security strategy is not installed' }
if(@(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')).Count) { throw 'Guest must be isolated' }
if($Apply) {
    $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Guest administrator approval required' }
}
. (Join-Path $root 'defender_gate.ps1')
$result=Confirm-GuestDefenderDisabled -TimeoutSeconds $TimeoutSeconds -Apply ([bool]$Apply) -RequireEffectiveState $true
$result.boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
$result.utc=[DateTime]::UtcNow.ToString('o')
# タスクからの適用結果は診断用。Hostは別途その場でCheckを行い、古い成功結果を採用しない。
if($Apply) {
    $target=Join-Path $root 'security-apply.json'
    $result | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath ($target+'.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($target+'.tmp') -Destination $target -Force
}
$result
