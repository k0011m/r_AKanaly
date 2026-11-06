param([Parameter(Mandatory=$true)][string]$RunRoot,
      [Parameter(Mandatory=$true)][string]$AnalysisId,
      [Parameter(Mandatory=$true)][string]$Token)
$ErrorActionPreference = 'Stop'
if ($AnalysisId -notmatch '^[a-f0-9]{32}$' -or $Token -notmatch '^[a-f0-9]{32}$') { throw 'Invalid run/token' }
$result = @{analysis_id=$AnalysisId;token=$Token;format='gzip';success=$false;files=@()}
$watch = [Diagnostics.Stopwatch]::StartNew()

# PowerShellのモジュール探索設定に依存せず、大きな原本をストリームで照合する。
function Get-StreamHash([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose(); $stream.Dispose() }
}

try {
    $manifest = Get-Content -LiteralPath (Join-Path $RunRoot 'manifest.json') -Raw | ConvertFrom-Json
    if ($manifest.analysis_id -ne $AnalysisId) { throw 'Manifest belongs to another run' }
    $allowed = @('sysmon.evtx','procmon.pml','etw.etl','execution.json','capture.json')
    $seen = @{}
    foreach ($item in $manifest.files) {
        $name = [string]$item.name
        $extra=$name -cmatch '^(system|tasks)\.evtx$|^configuration_baseline\.json$|^procmon_[a-f0-9]{32}\.pml$|^etw_[a-f0-9]{32}\.etl$|^capture_[a-f0-9]{32}\.json$|^configuration_[0-9]{8}T[0-9]{13}Z\.json$|^(processes|shutdown)_[0-9]{8}T[0-9]{13}Z\.jsonl$'
        if (($name -cnotin $allowed -and -not $extra) -or $seen.ContainsKey($name)) { throw 'Unexpected raw file' }
        $seen[$name] = $true
        $sourcePath = Join-Path $RunRoot $name
        $sourceInfo = Get-Item -LiteralPath $sourcePath
        if (($sourceInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse point is not a raw log' }
        if ($sourceInfo.Length -ne $item.size -or (Get-StreamHash $sourcePath) -ne $item.sha256) {
            throw ('Raw log changed: ' + $name)
        }
        $archiveName = $name + '.gz'
        $archivePath = Join-Path $RunRoot $archiveName
        $temporary = $archivePath + '.' + $Token + '.tmp'
        $source = $null; $target = $null; $gzip = $null
        try {
            # Compress-Archiveのサイズ制限を避け、3GB超のPMLも一定メモリで処理する。
            $source = [IO.File]::OpenRead($sourcePath)
            $target = [IO.File]::Create($temporary)
            $gzip = New-Object IO.Compression.GZipStream($target, [IO.Compression.CompressionLevel]::Fastest, $true)
            $source.CopyTo($gzip, 1048576)
        } finally {
            if ($gzip) { $gzip.Dispose() }
            if ($target) { $target.Dispose() }
            if ($source) { $source.Dispose() }
        }
        Move-Item -LiteralPath $temporary -Destination $archivePath -Force
        $result.files += @{name=$name;size=[long]$item.size;sha256=$item.sha256;archive=$archiveName;
            compressed_size=(Get-Item -LiteralPath $archivePath).Length;
            compressed_sha256=(Get-StreamHash $archivePath)}
    }
    if (-not $seen.ContainsKey('capture.json')) { throw 'Capture status missing' }
    $result.success = $true
} catch {
    $result.error = $_.Exception.Message
    if ($temporary -and (Test-Path -LiteralPath $temporary)) { Remove-Item -LiteralPath $temporary -Force }
} finally {
    # 完成した応答だけを公開し、Hostは要求tokenと原本目録を再照合する。
    $result.seconds = $watch.Elapsed.TotalSeconds
    $response = Join-Path $RunRoot ('transport_' + $Token + '.json')
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath ($response + '.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($response + '.tmp') -Destination $response -Force
}
