param([string]$Root='C:\Users\Public\r_AKanaly\dynamic', [Parameter(Mandatory=$true)][string]$GuestUser)
$ErrorActionPreference='Stop'
# 昇格はWindows標準のUAC画面でユーザーが承認する。自動承認や回避はしない。
$arguments='-NoProfile -NoExit -ExecutionPolicy Bypass -File "'+$Root+'\setup_dynamic.ps1" -Root "'+$Root+'" -GuestUser "'+$GuestUser+'"'
Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -ArgumentList $arguments
