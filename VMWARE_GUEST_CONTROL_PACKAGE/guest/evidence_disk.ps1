param([Parameter(Mandatory=$true)][string]$RequestPath,[Parameter(Mandatory=$true)][string]$ResponsePath)
$ErrorActionPreference='Stop'
$request=Get-Content -LiteralPath $RequestPath -Raw|ConvertFrom-Json
$result=@{success=$false;id=$request.id;request_id=$request.request_id}

# OSディスク・別のディスクを誤初期化しないよう、候補を一意に限定する。
function Find-EvidenceDisk {
    if($request.phase -eq 'initialize') {
        $locationPattern='^PCI Slot '+[regex]::Escape([string]$request.pci_slot)+' :.* : Port 2$'
        $disks=@(Get-Disk|Where-Object { $_.Size -eq ([int64]$request.settings.size_mb*1MB) -and $_.PartitionStyle -eq 'RAW' -and $_.FriendlyName -eq 'VMware Virtual SATA Hard Drive' -and $_.Location -match $locationPattern })
    } else { $disks=@(Get-Disk|Where-Object UniqueId -eq $request.unique_id) }
    if($disks.Count -ne 1 -or $disks[0].IsBoot -or $disks[0].IsSystem){throw 'Dedicated evidence disk is not uniquely identified'}
    return $disks[0]
}

# リパースポイント経由の別ボリューム・共有先へのコピーを避ける。
function Assert-LocalFile([string]$Path) {
    if($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':')){throw 'Only local files are accepted'}
    $item=Get-Item -LiteralPath $Path -Force
    if($item.PSIsContainer){throw 'Directories are not collected recursively'}
    $cursor=$item
    while($null -ne $cursor) {
        if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse points are not accepted'}
        $cursor=if($cursor -is [IO.FileInfo]){$cursor.Directory}else{$cursor.Parent}
    }
    return $item
}

# コピー中に検体が追記し続けても、指定容量以上を証拠ディスクへ書かない。
function Copy-Bounded([string]$Source,[string]$Destination,[int64]$Limit) {
    $inputStream=$null;$outputStream=$null
    try {
        $inputStream=[IO.File]::Open($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $outputStream=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $buffer=New-Object byte[] 1048576;$copied=[int64]0
        while(($count=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0){
            $copied+=$count;if($copied -gt $Limit){throw 'Copy byte limit exceeded'}
            $outputStream.Write($buffer,0,$count)
        }
        $outputStream.Flush($true)
    } finally {if($outputStream){$outputStream.Dispose()};if($inputStream){$inputStream.Dispose()}}
}

try {
    $disk=Find-EvidenceDisk
    # 観測中はオフラインで保持し、回収・読取りの要求時だけ同じディスクを戻す。
    if($request.phase -ne 'initialize') {
        if($disk.IsOffline){Set-Disk -Number $disk.Number -IsOffline $false}
        if($request.phase -eq 'collect'){Set-Disk -Number $disk.Number -IsReadOnly $false}
    }
    if($request.phase -eq 'initialize') {
        $disk|Initialize-Disk -PartitionStyle GPT -PassThru|New-Partition -UseMaximumSize -AssignDriveLetter|Format-Volume -FileSystem NTFS -NewFileSystemLabel 'RAK_EVIDENCE' -Confirm:$false|Out-Null
    }
    $partition=@(Get-Partition -DiskNumber $disk.Number|Where-Object Type -eq 'Basic')
    if($partition.Count -ne 1){throw 'Evidence partition is not unique'}
    if(-not $partition[0].DriveLetter){$partition[0]|Add-PartitionAccessPath -AssignDriveLetter}
    $partition=Get-Partition -DiskNumber $disk.Number -PartitionNumber $partition[0].PartitionNumber
    $root=([string]$partition.DriveLetter)+':\'
    $result.unique_id=$disk.UniqueId
    $folder=Join-Path $root $request.id
    if($request.phase -eq 'initialize') {
        New-Item -ItemType Directory -Path $folder|Out-Null
        [IO.File]::WriteAllText((Join-Path $folder 'identity.txt'),$request.id)
        Write-VolumeCache -DriveLetter $partition.DriveLetter
        Set-Disk -Number $disk.Number -IsReadOnly $true
        Set-Disk -Number $disk.Number -IsOffline $true
        $protected=Get-Disk -Number $disk.Number
        if(-not $protected.IsOffline -or -not $protected.IsReadOnly){throw 'Evidence disk protection confirmation failed'}
        $result.protected=$true
    } else {
        if([IO.File]::ReadAllText((Join-Path $folder 'identity.txt')) -ne $request.id){throw 'Evidence run identity mismatch'}
    }
    if($request.phase -eq 'collect') {
        $items=@();$total=[int64]0;$index=0
        foreach($source in $request.sources) {
            $index++;if($index -gt $request.settings.max_files){throw 'Candidate count exceeds limit'}
            $entry=@{source=$source.source;reason=$source.reason;process_guid=$source.process_guid;utc=$source.utc;status='failed';artifact_id=('artifact_{0:d4}' -f $index)}
            $target=$null
            try {
                $file=Assert-LocalFile $source.source
                if($total+$file.Length -gt ([int64]$request.settings.max_total_mb*1MB)){throw 'Collection byte limit exceeded'}
                $before=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                $name=$entry.artifact_id+'.bin';$target=Join-Path $folder $name
                Copy-Bounded $file.FullName $target (([int64]$request.settings.max_total_mb*1MB)-$total)
                $hash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
                $after=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                if($hash -ne $before -or $hash -ne $after){throw 'Source changed while copying'}
                $total+=(Get-Item -LiteralPath $target).Length
                $entry.sha256=$hash;$entry.size=$file.Length;$entry.disk_name=$name;$entry.status='saved'
                $entry.saved_utc=[DateTime]::UtcNow.ToString('o')
            } catch {
                $entry.error=$_.Exception.Message
                # 今回の固定名ファイルだけを除去し、失敗したコピーで容量を消費し続けない。
                if($target -and (Test-Path -LiteralPath $target)){Remove-Item -LiteralPath $target -Force}
            }
            $items+=,$entry
        }
        $result.items=$items
        $items|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $folder 'manifest.json') -Encoding UTF8
        # ボリュームキャッシュを同期してからOS正常停止へ引き渡す。
        Write-VolumeCache -DriveLetter $partition.DriveLetter
    } elseif($request.phase -eq 'import') {
        Set-Disk -Number $disk.Number -IsReadOnly $true
        if(-not (Get-Disk -Number $disk.Number).IsReadOnly){throw 'Read-only disk confirmation failed'}
        if(Test-Path -LiteralPath $request.destination){throw 'Static evidence destination already exists'}
        New-Item -ItemType Directory -Path $request.destination -Force|Out-Null
        $items=@()
        foreach($entry in $request.items) {
            if($entry.status -ne 'saved'){$items+=,$entry;continue}
            if($entry.disk_name -notmatch '^artifact_[0-9]+\.bin$'){throw 'Invalid evidence filename'}
            $source=Join-Path $folder $entry.disk_name
            $null=Assert-LocalFile $source
            if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $entry.sha256){throw 'Evidence disk hash mismatch'}
            $target=Join-Path $request.destination $entry.disk_name
            Copy-Item -LiteralPath $source -Destination $target
            if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $entry.sha256){throw 'Static evidence copy hash mismatch'}
            $entry|Add-Member -NotePropertyName guest_path -NotePropertyValue $target -Force
            $items+=,$entry
        }
        $result.items=$items
    } elseif($request.phase -ne 'initialize'){throw 'Unknown evidence operation'}
    $result.success=$true
} catch {$result.error=$_.Exception.Message}
finally {
    # 回収失敗時も書込み可能な証拠ディスクをGuestに残さない。
    if($disk -and $request.phase -eq 'collect') {
        try {
            Set-Disk -Number $disk.Number -IsReadOnly $true
            Set-Disk -Number $disk.Number -IsOffline $true
            $protected=Get-Disk -Number $disk.Number
            if(-not $protected.IsOffline -or -not $protected.IsReadOnly){throw 'Evidence disk protection confirmation failed'}
            $result.protected=$true
        } catch {$result.success=$false;$result.protection_error=$_.Exception.Message}
    }
    $result|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $ResponsePath -Encoding UTF8
}
