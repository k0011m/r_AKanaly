# SmartScreenの公式ポリシーと、ログイン済みユーザーのStoreアプリ設定を確認する。
function Get-GuestSmartScreenSettings([bool]$Apply) {
    $targets=@(
        @{path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';name='EnableSmartScreen'},
        @{path='HKLM:\SOFTWARE\Policies\Microsoft\Edge';name='SmartScreenEnabled'},
        @{path='HKLM:\SOFTWARE\Policies\Microsoft\Edge';name='SmartScreenPuaEnabled'}
    )
    $profiles=@(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { $_.Loaded -and -not $_.Special })
    if ($profiles.Count -eq 0) { throw 'No loaded Guest user profile for SmartScreen verification' }
    foreach ($profile in $profiles) {
        $targets+=@{path=('Registry::HKEY_USERS\'+$profile.SID+'\Software\Microsoft\Windows\CurrentVersion\AppHost');name='EnableWebContentEvaluation'}
    }
    $items=@()
    foreach ($target in $targets) {
        if ($Apply) {
            # 同一キー内の別の値を消さないよう、存在するキーは作り直さない。
            if (-not (Test-Path -LiteralPath $target.path)) {
                New-Item -Path $target.path -Force -ErrorAction Stop | Out-Null
            }
            New-ItemProperty -Path $target.path -Name $target.name -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        $value=Get-ItemPropertyValue -Path $target.path -Name $target.name -ErrorAction Stop
        $items+=@{path=$target.path;name=$target.name;value=$value;verification='configured_value_only'}
    }
    return $items
}

# Defenderがポリシーまたは実効状態ですでに停止済みかを、従来ゲートより先に確認する。
function Get-GuestDefenderBypassState {
    $targets=@(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender'
    )
    $result=@{bypass=$false;bypass_reasons=@();defender_status=@{read_success=$false;AMRunningMode=$null;error=$null};registry_checks=@()}
    try {
        $state=Get-MpComputerStatus -ErrorAction Stop
        $mode=[string]$state.AMRunningMode
        $result.defender_status=@{read_success=$true;AMRunningMode=$mode;error=$null}
        if ($mode -eq 'Not running') { $result.bypass_reasons+=@('am_running_mode_not_running') }
    } catch {
        $result.defender_status.error=$_.Exception.Message
    }
    foreach ($path in $targets) {
        $check=@{path=$path;name='DisableAntiSpyware';read_success=$false;exists=$false;value=$null;kind=$null;error=$null;disables_defender=$false}
        try {
            if (-not (Test-Path -LiteralPath $path)) {
                $check.read_success=$true
            } else {
                $key=Get-Item -LiteralPath $path -ErrorAction Stop
                if (-not ($key.GetValueNames() -contains 'DisableAntiSpyware')) {
                    $check.read_success=$true
                } else {
                    $check.exists=$true
                    $check.value=$key.GetValue('DisableAntiSpyware',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $check.kind=[string]$key.GetValueKind('DisableAntiSpyware')
                    $check.read_success=$true
                    $check.disables_defender=($check.kind -eq 'DWord' -and $check.value -eq 1)
                    if ($check.disables_defender) { $result.bypass_reasons+=@('disable_antispyware_dword_1:'+ $path) }
                }
            }
        } catch {
            # 型不一致や読取り不能は成功条件にせず、従来の厳格なゲートへ戻す。
            $check.error=$_.Exception.Message
        }
        $result.registry_checks+=@($check)
    }
    $result.bypass=($result.bypass_reasons.Count -gt 0)
    return $result
}

# 事前停止を確認できない場合だけ、初期化と無効化設定が安定するまで待つ。
function Confirm-GuestDefenderDisabled([int]$TimeoutSeconds, [bool]$Apply = $false, [bool]$RequireEffectiveState = $false) {
    # 新規インストールの公式API方式では、レジストリ値だけの確認省略を使わない。
    $markerPath=Join-Path $PSScriptRoot 'guest-install-marker.json'
    if(Test-Path -LiteralPath $markerPath) {
        $marker=Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop | ConvertFrom-Json
        if($marker.security_strategy -eq 'official_api_v1') { $RequireEffectiveState=$true }
    }
    $result=@{success=$false;checks=@();stable_checks=0;apply_requested=$Apply;policy_version=3;
        bypass=$false;bypass_reason=$null;bypass_reasons=@();traditional_check_performed=$false}
    $precheck=Get-GuestDefenderBypassState
    $result.defender_status=$precheck.defender_status
    $result.registry_checks=@($precheck.registry_checks)
    $result.bypass_reasons=@($precheck.bypass_reasons)
    if ($precheck.bypass -and -not $RequireEffectiveState) {
        $result.success=$true
        $result.bypass=$true
        $result.bypass_reason=($precheck.bypass_reasons -join ';')
        return $result
    }
    $result.traditional_check_performed=$true
    $expected=@{DisableRealtimeMonitoring=$true;DisableBehaviorMonitoring=$true;DisableIOAVProtection=$true;
        DisableScriptScanning=$true;DisableBlockAtFirstSeen=$true;MAPSReporting=0;SubmitSamplesConsent=2;
        EnableControlledFolderAccess=0;PUAProtection=0;EnableNetworkProtection=0}
    $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $attempted=$false
    do {
        $entry=@{utc=[DateTime]::UtcNow.ToString('o'); initialized=$false}
        try {
            $state=Get-MpComputerStatus -ErrorAction Stop
            $entry.state=$state | Select-Object AMRunningMode,AMServiceEnabled,AMEngineVersion,AntivirusSignatureVersion,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected
            $preferences=Get-MpPreference -ErrorAction Stop
            $entry.preferences=@{}
            foreach ($key in $expected.Keys) { $entry.preferences[$key]=$preferences.$key }
            $entry.asr_ids=@($preferences.AttackSurfaceReductionRules_Ids | Where-Object { $null -ne $_ })
            $entry.asr_actions=@($preferences.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
            $entry.initialized=($state.AMRunningMode -eq 'Normal' -and $state.AMServiceEnabled -eq $true -and
                -not [string]::IsNullOrWhiteSpace($state.AMEngineVersion) -and $state.AMEngineVersion -ne '0.0.0.0' -and
                -not [string]::IsNullOrWhiteSpace($state.AntivirusSignatureVersion))
            if (-not $result.ContainsKey('before')) { $result.before=$entry.state }
            $result.after=$entry.state
            $result.preferences=$entry.preferences
            $result.initialized=$entry.initialized
            # 改ざん防止は正規の事前整備でOFFにする。ON・取得不能なら設定変更も検体投入も進めない。
            if ($entry.initialized -and $state.IsTamperProtected -ne $false) {
                $result.stable_checks=0
                $entry.error='Tamper protection must be OFF in Guest Windows Security before analysis (state ON or unavailable)'
                $result.error=$entry.error
                $result.checks += $entry
                return $result
            }
            # 解析ごとに一度、各設定を個別適用する。1項目の拒否で残りの指定を省略しない。
            if ($Apply -and $entry.initialized -and -not $attempted) {
                if ((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Manufacturer -notmatch 'VMware') { throw 'Defender configuration is restricted to the VMware Guest' }
                $attempted=$true
                $entry.apply_errors=@()
                foreach ($key in $expected.Keys) {
                    try { $parameter=@{ErrorAction='Stop'}; $parameter[$key]=$expected[$key]; Set-MpPreference @parameter }
                    catch { $entry.apply_errors+=($key+': '+$_.Exception.Message) }
                }
                # API直後だけ0に見えて後から監査へ戻る場合もあるため、公式ADMXの指定と後続照合を併用する。
                try {
                    $puaPolicy='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
                    if (-not (Test-Path -LiteralPath $puaPolicy)) {
                        New-Item -Path $puaPolicy -Force -ErrorAction Stop | Out-Null
                    }
                    New-ItemProperty -Path $puaPolicy -Name PUAProtection -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                    $entry.pua_policy_requested=0
                } catch { $entry.apply_errors+=('PUA policy: '+$_.Exception.Message) }
                try {
                    $ids=@($preferences.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
                    if ($ids.Count) { Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions @($ids | ForEach-Object { 0 }) -ErrorAction Stop }
                    $null=Get-GuestSmartScreenSettings -Apply $true
                } catch { $entry.apply_errors+=$_.Exception.Message }
                $result.checks+=$entry
                Start-Sleep -Seconds 2
                continue
            }
            $entry.smart_screen=@(Get-GuestSmartScreenSettings -Apply $false)
            $result.smart_screen=$entry.smart_screen
            $result.asr_ids=$entry.asr_ids
            $result.asr_actions=$entry.asr_actions
            $settingsOff=$true
            foreach ($key in $expected.Keys) {
                if ($null -eq $preferences.$key -or $preferences.$key -ne $expected[$key]) { $settingsOff=$false }
            }
            $asrOff=($entry.asr_ids.Count -eq $entry.asr_actions.Count -and @($entry.asr_actions | Where-Object { $null -eq $_ -or $_ -ne 0 }).Count -eq 0)
            $smartOff=(@($entry.smart_screen | Where-Object { $null -eq $_.value -or $_.value -ne 0 }).Count -eq 0)
            $disabled=($entry.initialized -and $settingsOff -and $asrOff -and $smartOff -and $state.IoavProtectionEnabled -eq $false -and $state.RealTimeProtectionEnabled -eq $false -and
                $state.IsTamperProtected -eq $false -and $state.BehaviorMonitorEnabled -eq $false -and $preferences.DisableRealtimeMonitoring -eq $true -and
                $preferences.DisableBehaviorMonitoring -eq $true)
            if ($disabled) { $result.stable_checks++ }
            else {
                $result.stable_checks=0
            }
        } catch {
            $result.stable_checks=0
            $entry.error=$_.Exception.Message
            $result.last_attempt_error=$_.Exception.Message
        }
        $result.checks += $entry
        if ($result.stable_checks -ge 2) { $result.success=$true; return $result }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    $result.error='Guest protection policy OFF verification failed; inspect checks for missing or rejected settings'
    return $result
}
