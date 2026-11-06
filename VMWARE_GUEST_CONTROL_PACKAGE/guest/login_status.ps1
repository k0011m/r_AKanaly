param([Parameter(Mandatory=$true)][string]$OutputPath,
      [Parameter(Mandatory=$true)][string]$RequestId)
$ErrorActionPreference = 'Stop'
# Guest Operationsの実行ユーザーとコンソール利用者をSIDで照合する。
$result = @{ request_id=$RequestId; ready=$false; state='waiting_for_login' }
try {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class LoginSessionProbe {
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, uint session, int info, out IntPtr buffer, out uint bytes);
    [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr buffer);
    // ネイティブ側のバッファは成功・失敗を問わず解放する。
    public static string Query(uint session, int info) {
        IntPtr buffer = IntPtr.Zero; uint bytes;
        try {
            if (!WTSQuerySessionInformationW(IntPtr.Zero, session, info, out buffer, out bytes))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return info == 8 ? Marshal.ReadInt32(buffer).ToString() : Marshal.PtrToStringUni(buffer);
        } finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
    }
}
'@
    $session = [LoginSessionProbe]::WTSGetActiveConsoleSessionId()
    $result.session_id = $session
    if ($session -ne [uint32]::MaxValue) {
        $user = [LoginSessionProbe]::Query($session, 5)
        $domain = [LoginSessionProbe]::Query($session, 7)
        $connection = [int][LoginSessionProbe]::Query($session, 8)
        $result.connection_state = $connection
        if ($user) {
            $account = New-Object System.Security.Principal.NTAccount($domain, $user)
            $sid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $result.user_matches = ($sid -eq [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
            $result.ready = ($result.user_matches -and $connection -eq 0)
            if ($result.ready) { $result.state = 'session_active' }
            elseif (-not $result.user_matches) { $result.state = 'different_console_user' }
        }
    }
} catch {
    $result.state = 'probe_error'
    $result.error = $_.Exception.Message
}
# 毎回の要求IDを返し、前回成功のファイルを準備完了と誤認しない。
$result.checked_at = [DateTime]::UtcNow.ToString('o')
$json = $result | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText($OutputPath + '.tmp', $json, (New-Object System.Text.UTF8Encoding($false)))
Move-Item -LiteralPath ($OutputPath + '.tmp') -Destination $OutputPath -Force
