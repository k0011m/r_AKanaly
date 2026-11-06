param([string]$RunRoot, [string]$Root='C:\Users\Public\r_AKanaly\dynamic')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Guest上でPE/COFFヘッダーだけを読み、DLLを通常EXEとして起動しないための情報を返す。
function Get-SamplePeInfo([string]$Path) {
    $stream=$null
    $reader=$null
    try {
        $stream=[IO.File]::OpenRead($Path)
        $reader=[IO.BinaryReader]::new($stream)
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw 'Missing DOS header' }
        $stream.Position=60
        $offset=$reader.ReadUInt32()
        if ($offset -lt 64 -or $offset -gt ($stream.Length-26)) { throw 'Invalid PE header offset' }
        $stream.Position=$offset
        if ($reader.ReadUInt32() -ne 0x4550) { throw 'Missing PE signature' }
        $machine=$reader.ReadUInt16()
        $stream.Position=$offset+22
        $flags=$reader.ReadUInt16()
        return @{format='PE';machine=$machine;characteristics=$flags;is_dll=[bool]($flags -band 0x2000)}
    } catch { return @{format='unknown';is_dll=$null;error=$_.Exception.Message} }
    finally { if ($reader) { $reader.Dispose() }; if ($stream) { $stream.Dispose() } }
}
# 登録タスクから現在の解析IDを読み、別runへの起動を防ぐ。
if (-not $RunRoot) {
    $activeId=(Get-Content -LiteralPath (Join-Path $Root 'active.json') -Raw | ConvertFrom-Json).analysis_id
    if ($activeId -notmatch '^[a-f0-9]{32}$') { throw 'Invalid active analysis ID' }
    $RunRoot=Join-Path $Root ('runs\'+$activeId)
}
$request = Get-Content -LiteralPath (Join-Path $RunRoot 'request.json') -Raw | ConvertFrom-Json
$sample = Get-Content -LiteralPath (Join-Path $RunRoot 'sample.json') -Raw | ConvertFrom-Json
$result = @{analysis_id=$request.analysis_id;started=$false;reason='launch_failed';tracking='CIM polling; short-lived descendants may be missed; correlate with Sysmon'}
try {
    if ($sample.analysis_id -ne $request.analysis_id) { throw 'Sample request ID mismatch' }
    if ((Get-FileHash -LiteralPath $sample.sample -Algorithm SHA256).Hash -ne $sample.sha256) { throw 'Sample hash mismatch before execution' }
    $result.pe=Get-SamplePeInfo $sample.sample
    if ($result.pe.is_dll -eq $true) {
        $result.reason='unsupported_direct_launch'
        $result.error_code='sample_is_dll'
        throw 'DLL属性の検体は通常EXEとして直接起動できません。DLLの自動実行は行いません。'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    # 権限を理由に起動を拒否せず、起動元トークンを解析条件として記録する。
    $result.launch_context = @{
        user=$identity.Name
        is_administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        integrity_sid=$null
        integrity_level='unknown'
        source='sample_runner token; child token not independently measured'
    }
    try {
        $groups = (& "$env:WINDIR\System32\whoami.exe" /groups /fo csv 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { throw 'whoami groups query failed' }
        $integrity = [regex]::Match($groups, 'S-1-16-\d+')
        if (-not $integrity.Success) { throw 'Integrity SID not found' }
        $result.launch_context.integrity_sid=$integrity.Value
        $levels=@{'S-1-16-4096'='low';'S-1-16-8192'='medium';'S-1-16-8448'='medium_plus';'S-1-16-12288'='high';'S-1-16-16384'='system'}
        if ($levels.ContainsKey($integrity.Value)) { $result.launch_context.integrity_level=$levels[$integrity.Value] }
    } catch { $result.launch_context.observation_error=$_.Exception.Message }
    # 登録タスクの現在の権限で直接起動する。必要時だけ自動昇格する方式ではない。
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $sample.sample
    $info.WorkingDirectory = Split-Path -LiteralPath $sample.sample
    $info.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($info)
    $result.started=$true
    $result.pid=$process.Id
    $result.start_utc=[DateTime]::UtcNow.ToString('o')
    $result.sample=$sample.sample
    $result.sha256=$sample.sha256
    $known=@{}
    $known[[int]$process.Id]=$process.StartTime.ToUniversalTime()
    $quiet=$null
    $deadline=[DateTime]::UtcNow.AddSeconds($request.execution_timeout_seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath (Join-Path $RunRoot 'stop.json')) { $result.reason='controller_stop'; break }
        $all=@(Get-CimInstance Win32_Process)
        # 親を終了後も識別できるよう保持するが、PID再利用の古いプロセスは除外する。
        foreach ($entry in $all) {
            $parent=[int]$entry.ParentProcessId
            if ($known.ContainsKey($parent) -and $entry.CreationDate.ToUniversalTime() -ge $known[$parent]) {
                $known[[int]$entry.ProcessId]=$entry.CreationDate.ToUniversalTime()
            }
        }
        $active=@($all | Where-Object { $known.ContainsKey([int]$_.ProcessId) -and [Math]::Abs(($_.CreationDate.ToUniversalTime()-$known[[int]$_.ProcessId]).TotalSeconds) -lt 1 })
        if ($active.Count -eq 0) {
            if ($null -eq $quiet) { $quiet=[DateTime]::UtcNow }
            if (([DateTime]::UtcNow-$quiet).TotalSeconds -ge $request.post_exit_seconds) { $result.reason='process_tree_exited'; break }
        } else { $quiet=$null }
        Start-Sleep -Milliseconds 500
    }
    if ($result.reason -eq 'launch_failed') { $result.reason='observation_timeout' }
    if ($process.HasExited) { $result.exit_code=$process.ExitCode }
    $result.observed_pids=@($known.Keys)
} catch { $result.error=$_.Exception.Message }
finally {
    $result.end_utc=[DateTime]::UtcNow.ToString('o')
    $path=Join-Path $RunRoot 'execution.json'
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath ($path+'.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($path+'.tmp') -Destination $path -Force
}
