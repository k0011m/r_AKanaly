param(
    [Parameter(Mandatory=$true)][string]$AnalysisId,
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$true)][string]$Phase,
    [Parameter(Mandatory=$true)][string]$Destination,
    [Parameter(Mandatory=$true)][int]$TimeoutSeconds,
    [switch]$Apply
)

$ErrorActionPreference='Stop'
$base='C:\Users\Public\r_AKanaly\dynamic'
$runs=[System.IO.Path]::GetFullPath((Join-Path $base 'runs'))
$target=[System.IO.Path]::GetFullPath($Destination)

# Hostから任意の保存先を指定できないよう、解析run配下だけを応答先として認める。
if (-not $target.StartsWith($runs + [System.IO.Path]::DirectorySeparatorChar,[System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Defender response destination is outside the dynamic run root'
}

. (Join-Path $base 'defender_gate.ps1')
$markerPath=Join-Path $base 'guest-install-marker.json'
$marker=if(Test-Path -LiteralPath $markerPath){Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json}else{$null}
if($marker.security_strategy -eq 'official_api_v1') {
    # Hostの転送前要求を、初回導入で承認済みの固定管理タスクへ渡す。
    if($Apply) {
        & "$env:WINDIR\System32\schtasks.exe" /Run /TN r_AKanaly_PrepareSecurity | Out-Null
        if($LASTEXITCODE -ne 0){throw 'Guest security preparation task could not be started'}
    }
    $result=Confirm-GuestDefenderDisabled -TimeoutSeconds $TimeoutSeconds -Apply $false -RequireEffectiveState $true
} else {
    $result=Confirm-GuestDefenderDisabled -TimeoutSeconds $TimeoutSeconds -Apply ([bool]$Apply)
}
$result.analysis_id=$AnalysisId
$result.token=$Token
$result.phase=$Phase
$result.utc=[DateTime]::UtcNow.ToString('o')
$temporary=$target + '.tmp'
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
Move-Item -LiteralPath $temporary -Destination $target -Force
