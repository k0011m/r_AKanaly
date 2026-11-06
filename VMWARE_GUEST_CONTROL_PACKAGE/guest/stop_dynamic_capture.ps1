param([string]$Root='C:\Users\Public\r_AKanaly\dynamic')
$ErrorActionPreference='Stop'
# 旧BATからの終了要求も、現在の解析IDに限定する。
$id=(Get-Content -LiteralPath (Join-Path $Root 'active.json') -Raw | ConvertFrom-Json).analysis_id
if ($id -notmatch '^[a-f0-9]{32}$') { throw 'Invalid analysis ID' }
$path=Join-Path $Root ('runs\'+$id+'\stop.json')
@{analysis_id=$id;reason='compatibility_stop'} | ConvertTo-Json | Set-Content -LiteralPath ($path+'.tmp') -Encoding UTF8
Move-Item -LiteralPath ($path+'.tmp') -Destination $path -Force
