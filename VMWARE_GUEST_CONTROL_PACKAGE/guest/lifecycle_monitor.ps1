param([string]$Root='C:\Users\Public\r_AKanaly\dynamic')
$ErrorActionPreference='Stop'
$mutex=New-Object Threading.Mutex($false,'Global\r_AKanaly_LifecycleMonitor')
if (-not $mutex.WaitOne(0)) { exit 0 }
# 起動準備の進捗を残し、CIMプロバイダーの無応答と監視未起動を区別する。
'boot-query' | Set-Content -LiteralPath (Join-Path $Root 'lifecycle-startup.txt') -Encoding UTF8
$boot=(Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15).LastBootUpTime.ToUniversalTime()
$bootId=$boot.ToString('yyyyMMddTHHmmssfffffffZ')
$watcher=$null
$run=$null
$lastSnapshot=[DateTime]::MinValue
$lastCapture=[DateTime]::MinValue

# 完成した状態だけ公開し、Hostが書込み途中のJSONを採用しない。
function Write-Atomic($Path,$Value) {
    $Value | ConvertTo-Json -Depth 16 -Compress | Set-Content -LiteralPath ($Path+'.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($Path+'.tmp') -Destination $Path -Force
}

# PowerShellのPSDrive/PSProvider参照をJSONへ展開せず、レジストリの実値だけを残す。
function Read-RegistryValues([string]$Path,[string[]]$Names=@()) {
    $key=Get-Item -LiteralPath $Path
    $result=@{}
    foreach($name in $key.GetValueNames()) {
        if($Names.Count -eq 0 -or $name -in $Names) { $result[$name]=$key.GetValue($name) }
    }
    return $result
}

# 設定の取得失敗を空の設定と混同せず、証拠に欠損を残す。
function Get-Configuration {
    $result=@{utc=[DateTime]::UtcNow.ToString('o');boot_id=$bootId;errors=@();tasks=@();services=@();registry=@();startup=@()}
    try { $result.tasks=@(Get-ScheduledTask | ForEach-Object { @{name=$_.TaskPath+$_.TaskName;xml=(Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath)} }) } catch { $result.errors+=('tasks: '+$_.Exception.Message) }
    try { $result.services=@(Get-CimInstance Win32_Service | Select-Object Name,PathName,StartMode,StartName,State) } catch { $result.errors+=('services: '+$_.Exception.Message) }
    foreach($hive in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE','Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node')) {
        foreach($suffix in @('Microsoft\Windows\CurrentVersion\Run','Microsoft\Windows\CurrentVersion\RunOnce','Microsoft\Windows NT\CurrentVersion\Winlogon')) {
            $path=$hive+'\'+$suffix
            if(Test-Path -LiteralPath $path) {
                try {
                    # Winlogonには自動ログイン秘密もあるため、永続化に関係する値だけ残す。
                    $values=if($suffix -like '*Winlogon') { Read-RegistryValues $path @('Shell','Userinit','Taskman') } else { Read-RegistryValues $path }
                    $result.registry+=@{path=$path;values=$values}
                } catch { $result.errors+=('registry: '+$path) }
            }
        }
    }
    foreach($user in @(Get-ChildItem Registry::HKEY_USERS)) {
        foreach($suffix in @('Software\Microsoft\Windows\CurrentVersion\Run','Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
            $path='Registry::'+$user.Name+'\'+$suffix
            if(Test-Path -LiteralPath $path) { try { $result.registry+=@{path=$path;values=(Read-RegistryValues $path)} } catch { $result.errors+=('registry: '+$path) } }
        }
    }
    foreach($profile in @(Get-CimInstance Win32_UserProfile | Where-Object LocalPath)) {
        $folder=Join-Path $profile.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        if(Test-Path -LiteralPath $folder) { $result.startup+=@(Get-ChildItem -LiteralPath $folder -Force | Select-Object FullName,Length,LastWriteTimeUtc) }
    }
    $common=Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'
    if(Test-Path -LiteralPath $common) { $result.startup+=@(Get-ChildItem -LiteralPath $common -Force | Select-Object FullName,Length,LastWriteTimeUtc) }
    return $result
}

# 全プロセスの開始時刻を保存し、PID再利用を区別する基準を作る。
function Save-Processes {
    $items=@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CreationDate,ExecutablePath,CommandLine,Name)
    @{kind='snapshot';boot_id=$bootId;utc=[DateTime]::UtcNow.ToString('o');processes=$items} | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath (Join-Path $run ('processes_'+$bootId+'.jsonl')) -Encoding UTF8
}

try {
    'process-events' | Set-Content -LiteralPath (Join-Path $Root 'lifecycle-startup.txt') -Encoding UTF8
    Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier 'rak-process-start' | Out-Null
    Register-WmiEvent -Class Win32_ProcessStopTrace -SourceIdentifier 'rak-process-stop' | Out-Null
    $query=New-Object Diagnostics.Eventing.Reader.EventLogQuery('System',[Diagnostics.Eventing.Reader.PathType]::LogName,'*[System[EventID=1074]]')
    $watcher=New-Object Diagnostics.Eventing.Reader.EventLogWatcher($query)
    Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -SourceIdentifier 'rak-shutdown-event' | Out-Null
    $watcher.Enabled=$true
    'monitor-loop' | Set-Content -LiteralPath (Join-Path $Root 'lifecycle-startup.txt') -Encoding UTF8
    while($true) {
        $active=$null
        try { $active=Get-Content -LiteralPath (Join-Path $Root 'recovery-active.json') -Raw | ConvertFrom-Json } catch {}
        if($active -and $active.enabled -eq $true -and $active.analysis_id -match '^[a-f0-9]{32}$' -and [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt $active.expires_utc) {
            $next=Join-Path $Root ('runs\'+$active.analysis_id)
            if(Test-Path -LiteralPath (Join-Path $next 'recovery-closed.json')) {
                if($run) {
                    Write-Atomic (Join-Path $run ('configuration_'+$bootId+'.json')) (Get-Configuration)
                    Write-Atomic (Join-Path $run 'recovery-closed-ready.json') @{analysis_id=$active.analysis_id;success=$true}
                }
                $active=$null; $run=$null
            }
            elseif($next -ne $run) {
                $run=$next
                New-Item -ItemType Directory -Force -Path $run | Out-Null
                $configuration=Get-Configuration
                $baseline=Join-Path $run 'configuration_baseline.json'
                if(-not (Test-Path -LiteralPath $baseline)) { Write-Atomic $baseline $configuration }
                Write-Atomic (Join-Path $run ('configuration_'+$bootId+'.json')) $configuration
                Save-Processes
            }
        } else { $run=$null }
        $notice=$null
        $saved=$null
        try {
            $saved=Get-Content -LiteralPath (Join-Path $Root 'lifecycle-shutdown.json') -Raw | ConvertFrom-Json
            if([DateTime]::Parse($saved.utc).ToUniversalTime() -ge $boot) { $notice=$saved }
        } catch {}
        foreach($event in @(Get-Event -ErrorAction SilentlyContinue)) {
            if($run) {
                if($event.SourceIdentifier -eq 'rak-shutdown-event') {
                    $record=$event.SourceEventArgs.EventRecord
                    if($record) { @{utc=[DateTime]::UtcNow.ToString('o');boot_id=$bootId;xml=$record.ToXml()} | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $run ('shutdown_'+$bootId+'.jsonl')) -Encoding UTF8; $record.Dispose() }
                } else {
                    $e=$event.SourceEventArgs.NewEvent
                    @{kind=$event.SourceIdentifier;boot_id=$bootId;utc=[DateTime]::UtcNow.ToString('o');pid=$e.ProcessID;parent_pid=$e.ParentProcessID;name=$e.ProcessName;event_time=$e.TIME_CREATED;exit_status=$e.ExitStatus} | ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $run ('processes_'+$bootId+'.jsonl')) -Encoding UTF8
                }
            }
            Remove-Event -EventIdentifier $event.EventIdentifier
        }
        if($run) {
            $interval=[int]$active.process_snapshot_seconds
            if($interval -lt 1) { throw 'Invalid process snapshot interval' }
            if(([DateTime]::UtcNow-$lastSnapshot).TotalSeconds -ge $interval) { Save-Processes; $lastSnapshot=[DateTime]::UtcNow }
            # 起動後も同じ観測を継続するが、検体の再実行は一切行わない。
            if((Test-Path -LiteralPath (Join-Path $run 'begin.json')) -and -not (Test-Path -LiteralPath (Join-Path $run 'stop.json')) -and -not $notice) {
                if(([DateTime]::UtcNow-$lastCapture).TotalSeconds -ge 10) {
                    Start-ScheduledTask -TaskName 'r_AKanaly_DynamicCapture'
                    $lastCapture=[DateTime]::UtcNow
                }
            }
        }
        Write-Atomic (Join-Path $Root 'lifecycle-status.json') @{version=1;boot_id=$bootId;utc=[DateTime]::UtcNow.ToString('o');analysis_id=$(if($run){$active.analysis_id}else{$null});shutdown_notice=$notice;previous_shutdown_notice=$(if(-not $notice){$saved}else{$null});monitor_pid=$PID;baseline_ready=[bool]$run}
        Start-Sleep -Seconds 1
    }
} catch {
    @{utc=[DateTime]::UtcNow.ToString('o');error=$_.ToString();stack=$_.ScriptStackTrace} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'lifecycle-error.json') -Encoding UTF8
    throw
} finally {
    if($watcher) { $watcher.Dispose() }
    Get-EventSubscriber | Unregister-Event
    $mutex.ReleaseMutex(); $mutex.Dispose()
}
