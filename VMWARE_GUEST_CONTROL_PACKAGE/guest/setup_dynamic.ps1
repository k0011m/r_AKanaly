param([string]$Root='C:\Users\Public\r_AKanaly\dynamic', [Parameter(Mandatory=$true)][string]$GuestUser, [string]$SysmonPath)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this setup after approving Guest UAC' }
# Guest専用配置のマーカーがなければ、Hostへの誤適用を拒否する。
if (-not (Test-Path -LiteralPath (Join-Path $Root 'guest-install-marker.json'))) { throw 'Guest deployment marker is missing' }
if ((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'VMware') { throw 'This installer is restricted to the VMware Guest' }
$result=@{complete=$false;defender_changed=$false;errors=@()}
try {
    # ローカル名はドメイン探索へ渡さず、Guest自身のアカウント一覧からSIDを確定する。
    if ($GuestUser -notmatch '[\\@]') {
        $matchesLocal = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Where-Object Name -eq $GuestUser)
        if ($matchesLocal.Count -ne 1) { throw 'Guest local account could not be identified uniquely' }
        $sid = [string]$matchesLocal[0].SID
    } else {
        $sid = (New-Object Security.Principal.NTAccount($GuestUser)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    # SIDの確定はSysmon変更やタスク登録より前に済ませる。
    $result.guest_user = $GuestUser
    $result.guest_sid = $sid
    $procmon=Join-Path $Root 'tools\Procmon64.exe'
    if ((Get-AuthenticodeSignature -LiteralPath $procmon).Status -ne 'Valid') { throw 'Procmon signature invalid' }
    if (-not (Test-Path -LiteralPath "$env:WINDIR\System32\wpr.exe")) { throw 'Windows WPR is missing; repair/install Windows Performance Toolkit before continuing' }
    # 既存のSysmonを再利用し、ログ設定だけを更新する。
    # 個人プロファイルを参照せず、配置先または明示された実体を使用する。
    $sysmon=if ($SysmonPath) { $SysmonPath } else { Join-Path $Root 'tools\Sysmon64.exe' }
    if (-not (Test-Path -LiteralPath $sysmon)) { throw 'Existing Sysmon executable is missing' }
    if (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue) {
        & $sysmon -accepteula -c (Join-Path $Root 'sysmon.xml')
    } else { & $sysmon -accepteula -i (Join-Path $Root 'sysmon.xml') }
    if ($LASTEXITCODE -ne 0) { throw 'Sysmon configuration failed' }
    & wevtutil.exe sl Microsoft-Windows-Sysmon/Operational /ms:268435456
    if ($LASTEXITCODE -ne 0) { throw 'Sysmon channel configuration failed' }
    # 管理タスクは固定スクリプトだけを実行し、検体起動には使用しない。
    $action=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$Root+'\dynamic_capture.ps1" -Root "'+$Root+'"')
    $owner=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $options=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'r_AKanaly_DynamicCapture' -Action $action -Principal $owner -Settings $options -Force | Out-Null
    # Defender操作は後の明示指示専用タスクに分離し、ここでは実行しない。
    $marker=Get-Content -LiteralPath (Join-Path $Root 'guest-install-marker.json') -Raw | ConvertFrom-Json
    $finalAction=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$Root+'\finalize_dynamic_defender.ps1" -Root "'+$Root+'" -SampleDirectory "'+$marker.sample_directory+'"')
    Register-ScheduledTask -TaskName 'r_AKanaly_DynamicFinalize' -Action $finalAction -Principal $owner -Settings $options -Force | Out-Null
    $scheduler=New-Object -ComObject Schedule.Service
    $scheduler.Connect()
    $task=$scheduler.GetFolder('\').GetTask('r_AKanaly_DynamicCapture')
    # 通常のGuestユーザーにはタスクの読取りと起動だけを許可する。
    $task.SetSecurityDescriptor(('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;'+$sid+')'),0)
    $scheduler.GetFolder('\').GetTask('r_AKanaly_DynamicFinalize').SetSecurityDescriptor(('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;'+$sid+')'),0)
    foreach ($path in Get-ChildItem -LiteralPath $Root -File) {
        if ($path.Extension -in @('.ps1','.wprp','.xml')) {
            & icacls.exe $path.FullName /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' ('*'+$sid+':(RX)') | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Could not protect Guest control scripts' }
        }
    }
    # ファイルにフォルダ専用の継承フラグを渡すと空DACLになるため、明示的に分ける。
    & icacls.exe (Join-Path $Root 'tools') /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' ('*'+$sid+':(OI)(CI)(RX)') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect logger directory' }
    foreach ($tool in Get-ChildItem -LiteralPath (Join-Path $Root 'tools') -File) {
        & icacls.exe $tool.FullName /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' ('*'+$sid+':(RX)') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not protect logger file' }
    }
    # 検体用は管理用と別の制限付きタスクにし、ログオン画面でも起動可能にする。
    $sampleAction=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$Root+'\sample_runner.ps1" -Root "'+$Root+'"')
    $sampleOwner=New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME+'\'+$GuestUser) -LogonType S4U -RunLevel Limited
    Register-ScheduledTask -TaskName 'r_AKanaly_DynamicSample' -Action $sampleAction -Principal $sampleOwner -Settings $options -Force | Out-Null
    $scheduler.GetFolder('\').GetTask('r_AKanaly_DynamicSample').SetSecurityDescriptor(('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;'+$sid+')'),0)
    $result.complete=$true
} catch { $result.errors += $_.Exception.Message }
finally {
    $result.utc=[DateTime]::UtcNow.ToString('o')
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Root 'setup-result.json') -Encoding UTF8
}
if (-not $result.complete) { throw ($result.errors -join '; ') }
Write-Host 'Guest setup complete. Defender has NOT been changed. Return to Codex before finalization.'
