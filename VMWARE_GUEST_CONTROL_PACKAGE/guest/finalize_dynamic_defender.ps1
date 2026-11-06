param([string]$Root='C:\Users\Public\r_AKanaly\dynamic', [Parameter(Mandatory=$true)][string]$SampleDirectory)
$ErrorActionPreference='Stop'
if ((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'VMware') { throw 'Guest only' }
if (-not (Test-Path -LiteralPath (Join-Path $Root 'guest-install-marker.json'))) { throw 'Guest marker missing' }
$setup=Get-Content -LiteralPath (Join-Path $Root 'setup-result.json') -Raw | ConvertFrom-Json
if (-not $setup.complete) { throw 'Finish ALL Guest setup before changing Defender' }
# このスクリプトはUAC承認と設定完了後にHostから明示実行する。通常セットアップでは呼ばない。
$result=@{complete=$false;errors=@();excluded_directory=$SampleDirectory}
try {
    Add-MpPreference -ExclusionPath $SampleDirectory
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -DisableBlockAtFirstSeen $true -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
    $state=Get-MpComputerStatus
    $preferences=Get-MpPreference
    $result.state=@{RealTimeProtectionEnabled=$state.RealTimeProtectionEnabled;BehaviorMonitorEnabled=$state.BehaviorMonitorEnabled;IoavProtectionEnabled=$state.IoavProtectionEnabled;IsTamperProtected=$state.IsTamperProtected}
    $result.preferences=@{DisableScriptScanning=$preferences.DisableScriptScanning;DisableBlockAtFirstSeen=$preferences.DisableBlockAtFirstSeen;MAPSReporting=[int]$preferences.MAPSReporting;SubmitSamplesConsent=[int]$preferences.SubmitSamplesConsent}
    $result.exclusion_present=@($preferences.ExclusionPath) -contains $SampleDirectory
    $result.complete=($result.exclusion_present -and -not $state.RealTimeProtectionEnabled -and -not $state.BehaviorMonitorEnabled -and -not $state.IoavProtectionEnabled -and $preferences.DisableScriptScanning -and $preferences.DisableBlockAtFirstSeen)
    if (-not $result.complete) { throw 'Requested settings were not fully applied; user interaction may be required (Tamper Protection/policy)' }
} catch { $result.errors += $_.Exception.Message }
finally {
    $result.utc=[DateTime]::UtcNow.ToString('o')
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Root 'defender-result.json') -Encoding UTF8
}
if (-not $result.complete) { throw ($result.errors -join '; ') }
