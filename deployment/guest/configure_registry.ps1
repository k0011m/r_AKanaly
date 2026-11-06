param([Parameter(Mandatory=$true)][string]$RequestId,[string]$Root='C:\Users\Public\r_AKanaly\dynamic')
$ErrorActionPreference='Stop'
if($RequestId -notmatch '^[a-f0-9]{32}$') { throw 'Invalid registry request ID' }
if((Get-CimInstance Win32_ComputerSystem).Manufacturer -notmatch 'VMware') { throw 'VMware Guest only' }
if(-not (Test-Path -LiteralPath (Join-Path $Root 'guest-install-marker.json'))) { throw 'Guest marker missing' }
if(@(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')).Count) { throw 'Guest must be isolated' }
$result=@{id=$RequestId;complete=$true;keys=@()}
# 開発用保存点の整備記録に合わせ、Policies側だけを変更する。
# 非Policies側、所有権、ACL、改ざん防止の設定は変更しない。
foreach($key in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender')) {
    $row=@{path=$key;success=$false}
    try {
        if((Get-MpComputerStatus).IsTamperProtected) { throw 'Tamper Protection needs user action' }
        if(-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -LiteralPath $key -Name DisableAntiSpyware -PropertyType DWord -Value 1 -Force | Out-Null
        $item=Get-Item -LiteralPath $key
        $row.value=$item.GetValue('DisableAntiSpyware')
        $row.kind=$item.GetValueKind('DisableAntiSpyware').ToString()
        $row.immediate_value=$row.value
        $row.immediate_kind=$row.kind
        # 書込み直後だけ値が存在するケースを成功扱いしない。再起動後の検証も別途必須。
        Start-Sleep -Seconds 5
        $item=Get-Item -LiteralPath $key
        $row.value=$item.GetValue('DisableAntiSpyware')
        $row.kind=if($null -ne $row.value){$item.GetValueKind('DisableAntiSpyware').ToString()}else{$null}
        $row.checked_utc=[DateTime]::UtcNow.ToString('o')
        $row.success=($row.value -eq 1 -and $row.kind -eq 'DWord')
        if(-not $row.success) { throw 'Registry readback mismatch' }
    } catch { $row.error=$_.Exception.Message }
    $result.keys+=$row
}
# Policies側の読戻し成功だけを、この設定処理の完了条件とする。
$result.complete=(@($result.keys | Where-Object success).Count -gt 0)
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Root ('registry-'+$RequestId+'.json')) -Encoding UTF8
