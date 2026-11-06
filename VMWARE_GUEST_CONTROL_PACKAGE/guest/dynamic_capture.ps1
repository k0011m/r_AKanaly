param([string]$Root = 'C:\Users\Public\r_AKanaly\dynamic')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$mutex = New-Object Threading.Mutex($false, 'Global\r_AKanaly_DynamicCapture')
if (-not $mutex.WaitOne(0)) { exit 2 }
$run = $null
$procmonStarted = $false
$etwStarted = $false
$capture = @{success=$false; errors=@(); observation_complete=$false}
$bootId=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ')
$capture.boot_id=$bootId
$segment=[Guid]::NewGuid().ToString('N')

# 応答は一時ファイルから置換し、Hostが書きかけを読まないようにする。
function Write-State([string]$Name, $Data) {
    $Data.analysis_id = $id
    $path = Join-Path $run $Name
    $Data | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath ($path + '.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($path + '.tmp') -Destination $path -Force
}

# 外部ツールの終了コードを収集状態に反映する。
function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Exe
    $info.Arguments=($Arguments | ForEach-Object { '"' + $_.Replace('"','\"') + '"' }) -join ' '
    $info.UseShellExecute=$false
    $info.CreateNoWindow=$true
    $process=[Diagnostics.Process]::Start($info)
    if (-not $process.WaitForExit(120000)) { $process.Kill(); throw "$Exe command timeout; output may be incomplete" }
    if ($process.ExitCode -ne 0) { throw "$Exe exited with $($process.ExitCode)" }
}

# イベントがない場合だけ0を返し、権限やチャネルの異常を隠さない。
function Get-LastRecord {
    try { return [long](Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop).RecordId }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return 0L }
        throw
    }
}

# Hostと同じ判定をSYSTEM側でも使い、古い保存点や未初期化を成功扱いしない。
function Confirm-RealtimeDisabled([int]$TimeoutSeconds) {
    . (Join-Path $Root 'defender_gate.ps1')
    $result=Confirm-GuestDefenderDisabled -TimeoutSeconds $TimeoutSeconds -Apply $true
    if ($result.success) { return $result }
    $script:defenderReadiness=$result
    throw $result.error
}

try {
    $id = (Get-Content -LiteralPath (Join-Path $Root 'active.json') -Raw | ConvertFrom-Json).analysis_id
    if ($id -notmatch '^[a-f0-9]{32}$') { throw 'Invalid analysis ID' }
    $run = Join-Path $Root ('runs\' + $id)
    $request = Get-Content -LiteralPath (Join-Path $run 'request.json') -Raw | ConvertFrom-Json
    if ($request.analysis_id -ne $id) { throw 'Request ID mismatch' }
    if (Test-Path -LiteralPath (Join-Path $run 'stop.json')) { throw 'Completed run cannot be restarted' }
    # 前の起動区間のマニフェストを最終結果として回収させない。
    Remove-Item -LiteralPath (Join-Path $run 'manifest.json') -ErrorAction SilentlyContinue
    $procmon = Join-Path $Root 'tools\Procmon64.exe'
    $wpr = "$env:WINDIR\System32\wpr.exe"
    $setup=Get-Content -LiteralPath (Join-Path $Root 'setup-result.json') -Raw | ConvertFrom-Json
    if (-not $setup.complete) { throw 'Guest setup is not complete' }
    if (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) { throw 'Guest has an IPv4 default route' }
    if (Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue) { throw 'Guest has an IPv6 default route' }
    if ($request.require_defender_disabled) {
        $defenderReadiness = Confirm-RealtimeDisabled ([int]$request.ready_timeout_seconds)
    }
    $drive = Get-PSDrive -Name ([IO.Path]::GetPathRoot($run).Substring(0,1))
    if ($drive.Free -lt $request.min_free_bytes) { throw 'Insufficient Guest disk space' }
    if ($request.sysmon_enabled) {
        $service = Get-Service -Name 'Sysmon*' | Where-Object Status -eq 'Running'
        if (-not $service) { throw 'Sysmon is not running' }
        $null = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
    }
    if ($request.procmon_enabled) {
        if (-not (Test-Path -LiteralPath $procmon)) { throw 'Procmon is missing' }
        if (Get-Process -Name Procmon,Procmon64,Procmon64a -ErrorAction SilentlyContinue) { throw 'An unrelated Procmon process is already running' }
    }
    if ($request.etw_enabled -and -not (Test-Path -LiteralPath $wpr)) { throw 'WPR is missing' }
    Write-State 'prepared.json' @{success=$true; controller_pid=$PID; defender=$defenderReadiness}
    $deadline = [DateTime]::UtcNow.AddSeconds(600)
    while (-not (Test-Path -LiteralPath (Join-Path $run 'begin.json'))) {
        if ((Test-Path -LiteralPath (Join-Path $run 'stop.json')) -or [DateTime]::UtcNow -gt $deadline) { throw 'Preparation cancelled or expired' }
        Start-Sleep -Milliseconds 250
    }
    if ($request.procmon_enabled) {
        # 管理タスク内でだけキャプチャを開始し、Hostでは行わない。
        $pml = Join-Path $run $(if($request.recovery.enabled){'procmon_'+$segment+'.pml'}else{'procmon.pml'})
        $process = Start-Process -FilePath $procmon -ArgumentList @('/AcceptEula','/Quiet','/Minimized','/BackingFile',('"'+$pml+'"')) -PassThru
        $procmonStarted = $true
        Invoke-Checked $procmon @('/WaitForIdle')
        if (-not (Test-Path -LiteralPath $pml)) { throw 'Procmon backing file is missing' }
    }
    if ($request.etw_enabled) {
        $temp=Join-Path $run $(if($request.recovery.enabled){'etw-temp-'+$segment}else{'etw-temp'})
        New-Item -ItemType Directory -Path $temp -Force | Out-Null
        Invoke-Checked $wpr @('-start', ((Join-Path $Root 'dynamic.wprp')+'!Dynamic'), '-filemode', '-recordtempto', $temp)
        $etwStarted = $true
    }
    # エージェントやロガーの準備が完了してからSysmonの範囲を区切る。
    $capture.start_utc = [DateTime]::UtcNow.ToString('o')
    $boundary=Join-Path $run 'observation-boundary.json'
    if(Test-Path -LiteralPath $boundary) {
        $original=Get-Content -LiteralPath $boundary -Raw | ConvertFrom-Json
        $capture.start_record=[long]$original.start_record
    } else {
        $capture.start_record = if ($request.sysmon_enabled) { Get-LastRecord } else { 0 }
        Write-State 'observation-boundary.json' @{start_record=$capture.start_record;start_utc=$capture.start_utc}
    }
    Write-State 'ready.json' @{success=$true; boot_id=$bootId; start_record=$capture.start_record; start_utc=$capture.start_utc}
    # OS終了でfinallyまで実行されなくても、この区間の存在と未完了を残す。
    $capture.enabled = @{sysmon=$request.sysmon_enabled;procmon=$request.procmon_enabled;etw=$request.etw_enabled}
    Write-State ('capture_'+$segment+'.json') $capture
    $deadline = [DateTime]::UtcNow.AddSeconds($request.execution_timeout_seconds + 90)
    while (-not (Test-Path -LiteralPath (Join-Path $run 'stop.json'))) {
        $shutdown=Join-Path $Root 'lifecycle-shutdown.json'
        if(Test-Path -LiteralPath $shutdown) {
            try { $notice=Get-Content -LiteralPath $shutdown -Raw | ConvertFrom-Json } catch { $notice=$null }
            if($notice -and [DateTime]::Parse($notice.utc) -ge [DateTime]::Parse($capture.start_utc)) {
                $capture.errors+='OS shutdown interrupted observation'; break
            }
        }
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Controller observation deadline exceeded' }
        $bytes = (Get-ChildItem -LiteralPath $run -File -Recurse | Measure-Object Length -Sum).Sum
        $free = (Get-PSDrive -Name ([IO.Path]::GetPathRoot($run).Substring(0,1))).Free
        if ($bytes -gt $request.max_log_bytes -or $free -lt $request.min_free_bytes) { throw 'Capture stopped at disk/size limit' }
        Start-Sleep -Milliseconds 500
    }
    $capture.observation_complete = Test-Path -LiteralPath (Join-Path $run 'stop.json')
    $capture.success = $capture.observation_complete
} catch {
    $capture.errors += $_.Exception.Message
    if ($run) {
        # 上限・障害で収集が先に止まった場合、起動監視側にも終了を通知する。
        if (-not (Test-Path -LiteralPath (Join-Path $run 'stop.json'))) { Write-State 'stop.json' @{reason='collector_finalizing'} }
        if (-not (Test-Path -LiteralPath (Join-Path $run 'prepared.json'))) { Write-State 'prepared.json' @{success=$false;error=$_.Exception.Message;defender=$defenderReadiness} }
        if (-not (Test-Path -LiteralPath (Join-Path $run 'ready.json'))) { Write-State 'ready.json' @{success=$false;error=$_.Exception.Message} }
    }
} finally {
    if ($run) {
        $capture.end_utc = [DateTime]::UtcNow.ToString('o')
        if ($request.sysmon_enabled -and $capture.ContainsKey('start_record')) {
            try {
                $capture.end_record = Get-LastRecord
                if ($capture.end_record -lt $capture.start_record) { throw 'Sysmon log was reset during capture' }
                $oldest=(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -Oldest -MaxEvents 1).RecordId
                if ($oldest -gt ($capture.start_record + 1)) {
                    $capture.success=$false
                    $capture.errors += 'Sysmon events were overwritten before export'
                }
                $query = '*[System[(EventRecordID > ' + $capture.start_record + ') and (EventRecordID <= ' + $capture.end_record + ')]]'
                Invoke-Checked 'wevtutil.exe' @('epl','Microsoft-Windows-Sysmon/Operational',(Join-Path $run 'sysmon.evtx'),('/q:'+$query),'/ow:true')
            } catch { $capture.success=$false; $capture.errors += $_.Exception.Message }
        }
        if ($procmonStarted) {
            try { Invoke-Checked $procmon @('/Terminate','/Quiet') }
            catch { $capture.success=$false; $capture.errors += $_.Exception.Message }
        }
        if ($etwStarted) {
            try {
                $capture.etw_status_before_stop=(& $wpr -status collectors -details 2>&1 | Out-String)
                $etlName=if($request.recovery.enabled){'etw_'+$segment+'.etl'}else{'etw.etl'}
                Invoke-Checked $wpr @('-stop',(Join-Path $run $etlName),'-skipPdbGen')
            }
            catch { $capture.success=$false; $capture.errors += $_.Exception.Message }
        }
        $capture.enabled = @{sysmon=$request.sysmon_enabled;procmon=$request.procmon_enabled;etw=$request.etw_enabled}
        $capture.missing_raw=@()
        foreach ($logger in @('sysmon','procmon','etw')) {
            $extension=@{sysmon='evtx';procmon='pml';etw='etl'}[$logger]
            $present=(Test-Path -LiteralPath (Join-Path $run ($logger+'.'+$extension))) -or @(Get-ChildItem -LiteralPath $run -Filter ($logger+'_*.'+$extension)).Count -gt 0
            if ($request.($logger+'_enabled') -and -not $present) {
                $capture.success=$false
                $capture.missing_raw += $logger
            }
        }
        $capture.limits = @{max_log_bytes=$request.max_log_bytes;min_free_bytes=$request.min_free_bytes}
        Write-State 'capture.json' $capture
        Write-State ('capture_'+$segment+'.json') $capture
        # 停止要求元・タスク実行履歴も原本として回収する。未記録はエラーとして残す。
        foreach($entry in @(@('System','system.evtx'),@('Microsoft-Windows-TaskScheduler/Operational','tasks.evtx'))) {
            try { Invoke-Checked 'wevtutil.exe' @('epl',$entry[0],(Join-Path $run $entry[1]),'/ow:true') }
            catch { $capture.errors+=('Event export: '+$entry[0]); $capture.success=$false }
        }
        $files = @()
        $names=@('sysmon.evtx','procmon.pml','etw.etl','system.evtx','tasks.evtx','execution.json','configuration_baseline.json')
        $names+=@(Get-ChildItem -LiteralPath $run -File | Where-Object { $_.Name -match '^(procmon|etw|capture)_[a-f0-9]{32}\.(pml|etl|json)$|^(configuration|processes|shutdown)_[0-9]{8}T[0-9]{13}Z\.(json|jsonl)$' } | Select-Object -ExpandProperty Name)
        foreach ($name in $names) {
            $path = Join-Path $run $name
            if (Test-Path -LiteralPath $path) {
                try {
                    $file = Get-Item -LiteralPath $path
                    $files += @{name=$name;size=$file.Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
                } catch { $capture.success=$false; $capture.errors += "Cannot hash $name" }
            }
        }
        Write-State 'capture.json' $capture
        $path=Join-Path $run 'capture.json'
        $files += @{name='capture.json';size=(Get-Item -LiteralPath $path).Length;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
        # シャットダウン中の途中結果は区間原本だけ残し、Host終了要求後に一覧を確定する。
        if(Test-Path -LiteralPath (Join-Path $run 'stop.json')) {
            Write-State 'manifest.json' @{files=@($files);boot_id=$bootId}
        }
    }
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
