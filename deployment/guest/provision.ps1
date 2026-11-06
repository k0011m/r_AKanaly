param([ValidateSet('common','dynamic','static','verify-common','verify-dynamic','verify-static')][string]$Phase,[Parameter(Mandatory=$true)][string]$User)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root='C:\Users\Public\r_AKanaly'
$dynamic=Join-Path $root 'dynamic'
$bench='C:\Users\Public\CodexGuestAgent\analysis_bench'
$payload=$PSScriptRoot
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'VMware') { throw 'VMware Guest only' }
if(-not [Environment]::Is64BitOperatingSystem) { throw 'Windows x64 Guest required' }
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Guest administrator approval required' }
$choices=Get-Content -LiteralPath (Join-Path $payload 'choices.json') -Raw | ConvertFrom-Json

# 固定の配布ツリーだけを所定の配置先へコピーする。
function Copy-Tree([string]$Name,[string]$Destination) {
    $source=Join-Path $payload $Name
    if(-not (Test-Path -LiteralPath $source -PathType Container)) { throw "Missing payload: $Name" }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Copy-Item -Path (Join-Path $source '*') -Destination $Destination -Recurse -Force
}

# ユーザー指定の既存ツールはGuest上で検査し、未導入なら同梱版を選ぶ。
function Tool-Path([string]$Name,[string]$Default) {
    $property=$choices.tools.PSObject.Properties[$Name]
    if($property -and $property.Value.reuse) {
        $candidate=[string]$property.Value.path
        if(-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Existing Guest tool missing: $Name" }
        return $candidate
    }
    if(-not (Test-Path -LiteralPath $Default -PathType Leaf)) { throw "Bundled tool missing: $Name" }
    return $Default
}

# 管理コマンドの終了を確認し、コマンド実行だけで成功としない。
function Invoke-Checked([string]$Exe,[string[]]$Arguments) {
    $previousPreference=$ErrorActionPreference
    try {
        # PowerShell 5.1では標準エラーもErrorRecordになるため、終了コードと一緒に回収する。
        $ErrorActionPreference='Continue'
        $output=(& $Exe @Arguments 2>&1 | Out-String)
        $code=$LASTEXITCODE
    } finally { $ErrorActionPreference=$previousPreference }
    if($code -ne 0) {
        if($output.Length -gt 4096) { $output=$output.Substring($output.Length-4096) }
        throw "Tool execution failed: $Exe (exit $code): $output"
    }
}

# 専用ランタイムのDLLを更新する前に、再起動元のタスクとサービスを先に止める。
function Stop-InstalledAgents {
    foreach($name in @('r_AKanaly_OSAgent','r_AKanaly_LifecycleMonitor','r_AKanaly_Static_os','r_AKanaly_Static_ghidra','r_AKanaly_PrepareSecurity')) {
        $task=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if($task) { Disable-ScheduledTask -InputObject $task | Out-Null; Stop-ScheduledTask -InputObject $task }
    }
    $service=Get-Service r_AKanaly_Lifecycle -ErrorAction SilentlyContinue
    if($service -and $service.Status -ne 'Stopped') { Stop-Service -InputObject $service; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
    $prefixes=@((Join-Path $dynamic 'agent\runtime\'),(Join-Path $root 'runtime\python\'))
    foreach($process in Get-CimInstance Win32_Process) {
        if($process.ProcessId -eq $PID -or -not $process.ExecutablePath) { continue }
        foreach($prefix in $prefixes) {
            if($process.ExecutablePath.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
                Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $process.ProcessId -Timeout 30 -ErrorAction SilentlyContinue
                break
            }
        }
    }
    # タスク停止直前に生成された子も確認し、列挙時点の競合でDLL使用中のままコピーしない。
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Seconds 2
        $remaining=@(Get-CimInstance Win32_Process | Where-Object {
            $path=$_.ExecutablePath
            $path -and @($prefixes | Where-Object {$path.StartsWith($_,[StringComparison]::OrdinalIgnoreCase)}).Count
        })
        foreach($process in $remaining){Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue}
        if($remaining.Count -and [DateTime]::UtcNow -gt $deadline){throw 'Installed Agent processes did not stop'}
    } while($remaining.Count)
}

# 確認時には設定値と実稼働状態を別々に記録する。
function Verify-Security {
    if($choices.registry_profile -eq 'manual_registry') {
        . (Join-Path $dynamic 'defender_gate.ps1')
        $report=Confirm-GuestManualProtection
        if($report.success -ne $true) {
            $exception=New-Object System.InvalidOperationException 'Guest manual protection verification failed'
            $exception.Data['security']=$report
            throw $exception
        }
        return $report
    }
    if($choices.registry_profile -eq 'official_api') {
        # 起動のたびにHostの検証工程から固定タスクへ指示する。自動起動トリガーは作らない。
        Start-ScheduledTask -TaskName r_AKanaly_PrepareSecurity
        $report=& (Join-Path $dynamic 'prepare_analysis_security.ps1') -TimeoutSeconds 180
        if($report.success -ne $true -or $report.bypass -ne $false) {
            $errorRecord=New-Object System.InvalidOperationException 'Guest official API protection verification failed'
            $errorRecord.Data['security']=$report
            throw $errorRecord
        }
        return $report
    }
    $state=Get-MpComputerStatus -ErrorAction Stop
    $values=@()
    foreach($key in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender','HKLM:\SOFTWARE\Microsoft\Windows Defender')) {
        $item=Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
        $value=if($item){$item.GetValue('DisableAntiSpyware')}else{$null}
        $kind=if($item -and $null -ne $value){$item.GetValueKind('DisableAntiSpyware').ToString()}else{$null}
        $values+=@{path=$key;value=$value;kind=$kind}
    }
    # 不一致でも実測値をHostへ返し、設定消失と保護状態を別々に診断できるようにする。
    $report=@{registry=$values;mode=$state.AMRunningMode;realtime=$state.RealTimeProtectionEnabled;behavior=$state.BehaviorMonitorEnabled;ioav=$state.IoavProtectionEnabled;tamper=$state.IsTamperProtected}
    $errors=@()
    if($choices.registry_profile -eq 'analysis' -and -not @($values | Where-Object {$_.path -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -and $_.value -eq 1 -and $_.kind -in @('DWord','QWord')}).Count) { $errors+='Policies DisableAntiSpyware DWORD/QWORD=1 was not retained' }
    if($choices.registry_profile -eq 'analysis' -and ($state.RealTimeProtectionEnabled -or $state.BehaviorMonitorEnabled -or $state.IoavProtectionEnabled -or $state.IsTamperProtected)) {
        $errors+='Guest protection remains active; check policy/Tamper Protection before saving snapshot'
    }
    if($errors.Count) {
        $errorRecord=New-Object System.InvalidOperationException ($errors -join '; ')
        $errorRecord.Data['security']=$report
        throw $errorRecord
    }
    return $report
}

if($Phase -eq 'common') {
    Stop-InstalledAgents
    foreach($directory in @($root,$dynamic,$bench,(Join-Path $root 'samples'))) { New-Item -ItemType Directory -Force -Path $directory | Out-Null }
    $existingPython=$choices.tools.PSObject.Properties['Python (OS Agent)']
    if($existingPython -and $existingPython.Value.reuse) {
        $existing=Tool-Path 'Python (OS Agent)' ''
        New-Item -ItemType Directory -Force -Path (Join-Path $dynamic 'agent\runtime') | Out-Null
        Copy-Item -Path (Join-Path (Split-Path $existing) '*') -Destination (Join-Path $dynamic 'agent\runtime') -Recurse -Force
    } else { Copy-Tree 'runtime' (Join-Path $dynamic 'agent\runtime') }
    Copy-Tree 'agent' (Join-Path $dynamic 'agent\code')
    Copy-Tree 'agent' (Join-Path $bench 'code')
    Copy-Tree 'dynamic' $dynamic
    foreach($pth in Get-ChildItem -LiteralPath (Join-Path $dynamic 'agent\runtime') -Filter 'python*._pth') {
        $lines=Get-Content -LiteralPath $pth.FullName
        if($lines -notcontains '../code') { Add-Content -LiteralPath $pth.FullName -Value '../code' -Encoding ASCII }
    }
    $marker=@{guest_only=$true;sample_directory=(Join-Path $root 'samples')}
    if($choices.registry_profile -eq 'official_api') { $marker.security_strategy='official_api_v1' }
    if($choices.registry_profile -eq 'manual_registry') { $marker.security_strategy='manual_registry_v1' }
    $marker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dynamic 'guest-install-marker.json') -Encoding UTF8
    & (Join-Path $dynamic 'setup_lifecycle.ps1') -Root $dynamic -GuestUser $User | Out-Null
    if($choices.registry_profile -eq 'official_api') {
        # 管理者承認は初回配置で行い、通常解析ではユーザーが固定タスクを起動するだけにする。
        foreach($file in @('prepare_analysis_security.ps1','defender_gate.ps1','guest-install-marker.json')) {
            Invoke-Checked "$env:WINDIR\System32\icacls.exe" @((Join-Path $dynamic $file),'/inheritance:r','/grant:r','*S-1-5-18:(F)','*S-1-5-32-544:(F)','*S-1-5-32-545:(RX)')
        }
        $action=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+(Join-Path $dynamic 'prepare_analysis_security.ps1')+'" -Apply')
        $owner=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        $options=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName r_AKanaly_PrepareSecurity -Action $action -Principal $owner -Settings $options -Force | Out-Null
        $account=New-Object Security.Principal.NTAccount ($env:COMPUTERNAME+'\'+$User)
        $sid=$account.Translate([Security.Principal.SecurityIdentifier]).Value
        $scheduler=New-Object -ComObject Schedule.Service
        $scheduler.Connect()
        $scheduler.GetFolder('\').GetTask('r_AKanaly_PrepareSecurity').SetSecurityDescriptor(('D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;'+$sid+')'),0)
    }
    if($choices.registry_profile -eq 'analysis') {
        if(@(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')).Count) { throw 'Guest must be isolated before protection configuration' }
        if((Get-MpComputerStatus).IsTamperProtected) { throw 'Guest Tamper Protection needs user action; no bypass is performed' }
        $registryScript=Join-Path $dynamic 'configure_registry.ps1'
        Copy-Item -LiteralPath (Join-Path $payload 'configure_registry.ps1') -Destination $registryScript -Force
        Invoke-Checked "$env:WINDIR\System32\icacls.exe" @($registryScript,'/inheritance:r','/grant:r','*S-1-5-18:(F)','*S-1-5-32-544:(F)','*S-1-5-32-545:(RX)')
        $requestId=[Guid]::NewGuid().ToString('N')
        $action=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$registryScript+'" -RequestId '+$requestId)
        $owner=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName r_AKanaly_SetupRegistry -Action $action -Principal $owner -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3)) -Force | Out-Null
        try {
            Start-ScheduledTask -TaskName r_AKanaly_SetupRegistry
            $resultFile=Join-Path $dynamic ('registry-'+$requestId+'.json')
            $deadline=[DateTime]::UtcNow.AddSeconds(180)
            while(-not (Test-Path -LiteralPath $resultFile)) {
                if([DateTime]::UtcNow -gt $deadline) { throw 'Registry task timed out' }
                Start-Sleep -Seconds 1
            }
            $registryResult=Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
            if($registryResult.id -ne $requestId -or -not $registryResult.complete) { throw ('Registry configuration failed: '+($registryResult | ConvertTo-Json -Depth 5 -Compress)) }
        } finally { Unregister-ScheduledTask -TaskName r_AKanaly_SetupRegistry -Confirm:$false }

    }
} elseif($Phase -eq 'dynamic') {
    New-Item -ItemType Directory -Force -Path (Join-Path $dynamic 'tools') | Out-Null
    Copy-Item -LiteralPath (Join-Path $payload 'Procmon64.exe') -Destination (Join-Path $dynamic 'tools\Procmon64.exe') -Force
    Copy-Item -LiteralPath (Join-Path $payload 'Sysmon64.exe') -Destination (Join-Path $dynamic 'tools\Sysmon64.exe') -Force
    $sysmon=Tool-Path 'Sysmon' (Join-Path $dynamic 'tools\Sysmon64.exe')
    $procmon=Tool-Path 'Procmon' (Join-Path $dynamic 'tools\Procmon64.exe')
    if($procmon -ne (Join-Path $dynamic 'tools\Procmon64.exe')) { Copy-Item -LiteralPath $procmon -Destination (Join-Path $dynamic 'tools\Procmon64.exe') -Force }
    & (Join-Path $payload 'setup_dynamic_portable.ps1') -Root $dynamic -GuestUser $User -SysmonPath $sysmon | Out-Null
    # .NET Frameworkは既存機能を優先し、必要なら同梱のOS一致SxSから導入する。
    if((Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State -ne 'Enabled') {
        $sxs=Join-Path $payload 'sxs'
        if(-not (Test-Path -LiteralPath $sxs)) {
            # 同梱資材がない場合は、接続済みWindows媒体のビルドを照合して利用する。
            # 候補が複数ある場合や版が異なる場合は勝手に選ばず、隔離を維持して失敗させる。
            $media=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=5' | Where-Object { Test-Path -LiteralPath ($_.DeviceID+'\sources\sxs') })
            if($media.Count -ne 1) { throw '.NET Framework 3.5 requires bundled SxS or exactly one matching Windows installation disc' }
            $images=@(Get-ChildItem -LiteralPath ($media[0].DeviceID+'\sources') -File | Where-Object { $_.Name -in @('install.wim','install.esd') })
            if($images.Count -ne 1) { throw 'Windows installation image could not be identified uniquely' }
            $image=Get-WindowsImage -ImagePath $images[0].FullName -Index 1
            $os=Get-CimInstance Win32_OperatingSystem
            if(([version]$image.Version).Build -ne [int]$os.BuildNumber) { throw 'Windows installation disc build does not match Guest' }
            $sxs=$media[0].DeviceID+'\sources\sxs'
        }
        Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -Source $sxs -LimitAccess -NoRestart | Out-Null
    }
} elseif($Phase -eq 'static') {
    Copy-Tree 'ghidra-runtime' (Join-Path $root 'runtime\python')
    Copy-Tree 'jdk' (Join-Path $root 'runtime\jdk')
    Copy-Tree 'ghidra' (Join-Path $root 'tools\ghidra')
    $python=Tool-Path 'Python (Ghidra / PyGhidra)' (Join-Path $root 'runtime\python\python.exe')
    # 同梱の埋込みPythonはスクリプト配置先を自動検索しないため、専用Agentコードを登録する。
    foreach($pth in Get-ChildItem -LiteralPath (Join-Path $root 'runtime\python') -Filter 'python*._pth') {
        $agentCode=Join-Path $bench 'code'
        if((Get-Content -LiteralPath $pth.FullName) -notcontains $agentCode) {
            Add-Content -LiteralPath $pth.FullName -Value $agentCode -Encoding UTF8
        }
    }
    $java=Tool-Path 'Java JDK' (Join-Path $root 'runtime\jdk\bin\java.exe')
    $ghidra=Tool-Path 'Ghidra' (Join-Path $root 'tools\ghidra\ghidraRun.bat')
    $environment=@{python=$python;java_home=(Split-Path (Split-Path $java));ghidra_home=(Split-Path $ghidra)}
    $environment | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'environment.json') -Encoding UTF8
    Copy-Tree 'static-tool-packages' (Join-Path $root 'static-tool-packages')
    Invoke-Checked $python @((Join-Path $payload 'guest_install_static_tools.py'),'--root',$root)
    # 既存CLIの選択を実際のAgent用設定にも反映する。
    $toolfile=Join-Path $root 'static-tools.json'
    $tools=Get-Content -LiteralPath $toolfile -Raw | ConvertFrom-Json
    foreach($pair in @(@('Detect It Easy','diec'),@('FLOSS','floss'),@('capa','capa'))) {
        $tools.paths.($pair[1])=Tool-Path $pair[0] $tools.paths.($pair[1])
    }
    $tools | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $toolfile -Encoding UTF8
    $owner=New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME+'\'+$User) -LogonType Interactive -RunLevel Limited
    $options=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
    foreach($role in @('os','ghidra')) {
        $action=New-ScheduledTaskAction -Execute $python -Argument ('"'+$bench+'\code\analysis_agent.py" --root "'+$bench+'" --role '+$role)
        Register-ScheduledTask -TaskName ('r_AKanaly_Static_'+$role) -Action $action -Principal $owner -Settings $options -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $owner.UserId) -Force | Out-Null
    }
} else {
    # 起動直後のNot runningを採用せず、初期化猶予の後にも実状態を確認する。
    $boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $remaining=90-((Get-Date)-$boot).TotalSeconds
    if($remaining -gt 0) { Start-Sleep -Seconds ([int][Math]::Ceiling($remaining)) }
    $security=Verify-Security
    if($choices.registry_profile -eq 'analysis') { Start-Sleep -Seconds 10; $security=Verify-Security }
    if((Get-Service r_AKanaly_Lifecycle).Status -ne 'Running') { throw 'Lifecycle service not running' }
    if(-not (Get-Process explorer -ErrorAction SilentlyContinue)) { throw 'Interactive logon is not ready' }
    Invoke-Checked (Join-Path $dynamic 'agent\runtime\python.exe') @('-c','import pyzipper; import ctypes; print(1)')
    Invoke-Checked (Join-Path $dynamic 'agent\runtime\python.exe') @((Join-Path $payload 'agent_healthcheck.py'),'--python',(Join-Path $dynamic 'agent\runtime\python.exe'),'--code',(Join-Path $dynamic 'agent\code'))
    if($Phase -eq 'verify-dynamic') {
        if(-not (Get-Service -Name 'Sysmon*' | Where-Object Status -eq 'Running')) { throw 'Sysmon service is not running' }
        Get-ScheduledTask -TaskName r_AKanaly_DynamicCapture -ErrorAction Stop | Out-Null
        Invoke-Checked "$env:WINDIR\System32\wpr.exe" @('-profiles')
        if((Get-AuthenticodeSignature -LiteralPath (Join-Path $dynamic 'tools\Procmon64.exe')).Status -ne 'Valid') { throw 'Procmon signature invalid' }
    }
    if($Phase -eq 'verify-static') {
        $environment=Get-Content -LiteralPath (Join-Path $root 'environment.json') -Raw | ConvertFrom-Json
        $env:JAVA_HOME=$environment.java_home
        $env:GHIDRA_INSTALL_DIR=$environment.ghidra_home
        Invoke-Checked $environment.python @('-c','import pyghidra; pyghidra.start(); from ghidra.framework import Application; print(Application.getApplicationVersion())')
        Invoke-Checked $environment.python @((Join-Path $payload 'agent_healthcheck.py'),'--python',$environment.python,'--code',(Join-Path $bench 'code'),'--static')
        $tools=Get-Content -LiteralPath (Join-Path $root 'static-tools.json') -Raw | ConvertFrom-Json
        foreach($property in $tools.paths.PSObject.Properties) { if(-not (Test-Path -LiteralPath $property.Value)) { throw ('Missing tool: '+$property.Name) } }
    }
}
@{complete=$true;phase=$Phase;utc=[DateTime]::UtcNow.ToString('o');security=$security;registry=$registryResult}
