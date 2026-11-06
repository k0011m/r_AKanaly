param(
    [Parameter(Mandatory = $true)]
    [string]$Request,
    [Parameter(Mandatory = $true)]
    [string]$Response
)

$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class GuestGuiNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct INPUT {
        public UInt32 type;
        public INPUTUNION U;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUTUNION {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MOUSEINPUT {
        public Int32 dx;
        public Int32 dy;
        public UInt32 mouseData;
        public UInt32 dwFlags;
        public UInt32 time;
        public UIntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEYBDINPUT {
        public UInt16 wVk;
        public UInt16 wScan;
        public UInt32 dwFlags;
        public UInt32 time;
        public UIntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError=true)]
    public static extern UInt32 SendInput(UInt32 nInputs, INPUT[] pInputs, Int32 cbSize);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool SetCursorPos(Int32 X, Int32 Y);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern Int32 GetWindowText(IntPtr hWnd, StringBuilder lpString, Int32 nMaxCount);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern Int32 GetClassName(IntPtr hWnd, StringBuilder lpClassName, Int32 nMaxCount);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern int GetSystemMetrics(int nIndex);

    public static void SendUnicodeText(string text) {
        foreach (char ch in text) {
            INPUT down = new INPUT();
            down.type = 1;
            down.U.ki.wVk = 0;
            down.U.ki.wScan = ch;
            down.U.ki.dwFlags = 0x0004;
            INPUT up = new INPUT();
            up.type = 1;
            up.U.ki.wVk = 0;
            up.U.ki.wScan = ch;
            up.U.ki.dwFlags = 0x0004 | 0x0002;
            INPUT[] inputs = new INPUT[] { down, up };
            UInt32 sent = SendInput((UInt32)inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
            if (sent != inputs.Length) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
    }

    public static void Click(int x, int y) {
        if (!SetCursorPos(x, y)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        INPUT down = new INPUT();
        down.type = 0;
        down.U.mi.dwFlags = 0x0002;
        INPUT up = new INPUT();
        up.type = 0;
        up.U.mi.dwFlags = 0x0004;
        INPUT[] inputs = new INPUT[] { down, up };
        UInt32 sent = SendInput((UInt32)inputs.Length, inputs, Marshal.SizeOf(typeof(INPUT)));
        if (sent != inputs.Length) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public static void Key(UInt16 vk, bool up) {
        INPUT input = new INPUT();
        input.type = 1;
        input.U.ki.wVk = vk;
        input.U.ki.dwFlags = up ? (UInt32)0x0002 : 0;
        UInt32 sent = SendInput(1, new INPUT[] { input }, Marshal.SizeOf(typeof(INPUT)));
        if (sent != 1) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
"@

$VkCodes = @{
    ENTER = 0x0D; RETURN = 0x0D; ESC = 0x1B; ESCAPE = 0x1B; TAB = 0x09
    SPACE = 0x20; BACKSPACE = 0x08; DELETE = 0x2E; CTRL = 0x11; CONTROL = 0x11
    ALT = 0x12; SHIFT = 0x10; WIN = 0x5B; LEFT = 0x25; UP = 0x26
    RIGHT = 0x27; DOWN = 0x28; F1 = 0x70; F2 = 0x71; F3 = 0x72
    F4 = 0x73; F5 = 0x74; F6 = 0x75; F7 = 0x76; F8 = 0x77
    F9 = 0x78; F10 = 0x79; F11 = 0x7A; F12 = 0x7B
}

# Role: send a key chord in press order and release it in reverse order.
function Invoke-PressKey {
    param([object]$Keys)

    if ($Keys -is [string]) {
        $parts = $Keys -replace '\+', ' ' -split '\s+' | Where-Object { $_ }
    } else {
        $parts = @($Keys)
    }

    $codes = foreach ($part in $parts) {
        $key = [string]$part
        $upper = $key.ToUpperInvariant()
        if ($key.Length -eq 1) {
            [uint16][char]$upper
        } elseif ($VkCodes.ContainsKey($upper)) {
            [uint16]$VkCodes[$upper]
        } else {
            throw "Unknown key: $key"
        }
    }

    foreach ($code in $codes) {
        [GuestGuiNative]::Key($code, $false)
    }
    [array]::Reverse($codes)
    foreach ($code in $codes) {
        [GuestGuiNative]::Key($code, $true)
    }
}

# Role: collect current screen and top-level window information.
function Get-GuestObservation {
    $windows = New-Object System.Collections.Generic.List[object]
    $callback = [GuestGuiNative+EnumWindowsProc]{
        param([IntPtr]$Hwnd, [IntPtr]$Lparam)
        $title = New-Object System.Text.StringBuilder 512
        $className = New-Object System.Text.StringBuilder 256
        $rect = New-Object GuestGuiNative+RECT
        [void][GuestGuiNative]::GetWindowText($Hwnd, $title, $title.Capacity)
        [void][GuestGuiNative]::GetClassName($Hwnd, $className, $className.Capacity)
        [void][GuestGuiNative]::GetWindowRect($Hwnd, [ref]$rect)
        if ($title.Length -gt 0) {
            $windows.Add([ordered]@{
                hwnd = $Hwnd.ToInt64()
                title = $title.ToString()
                class = $className.ToString()
                rect = [ordered]@{
                    left = $rect.Left
                    top = $rect.Top
                    right = $rect.Right
                    bottom = $rect.Bottom
                }
            })
        }
        return $true
    }
    [void][GuestGuiNative]::EnumWindows($callback, [IntPtr]::Zero)

    return [ordered]@{
        screen = [ordered]@{
            width = [GuestGuiNative]::GetSystemMetrics(0)
            height = [GuestGuiNative]::GetSystemMetrics(1)
        }
        foreground_hwnd = [GuestGuiNative]::GetForegroundWindow().ToInt64()
        windows = @($windows | Select-Object -First 50)
    }
}

# Role: dispatch a JSON request to a Guest GUI action.
function Invoke-AgentRequest {
    param([object]$Payload)

    switch ($Payload.action) {
        "observe" {
            return Get-GuestObservation
        }
        "launch_app" {
            $process = Start-Process -FilePath $Payload.path -PassThru
            return [ordered]@{ pid = $process.Id; path = $Payload.path }
        }
        "click" {
            [GuestGuiNative]::Click([int]$Payload.x, [int]$Payload.y)
            return [ordered]@{ clicked = @([int]$Payload.x, [int]$Payload.y) }
        }
        "type_text" {
            [GuestGuiNative]::SendUnicodeText([string]$Payload.text)
            return [ordered]@{ typed = ([string]$Payload.text).Length }
        }
        "press_key" {
            Invoke-PressKey -Keys $Payload.keys
            return [ordered]@{ pressed = $Payload.keys }
        }
        "open_url" {
            Start-Process $Payload.url | Out-Null
            return [ordered]@{ opened_url = $Payload.url }
        }
        default {
            throw "Unknown action: $($Payload.action)"
        }
    }
}

$started = Get-Date
try {
    $payload = Get-Content -LiteralPath $Request -Raw -Encoding UTF8 | ConvertFrom-Json
    $result = [ordered]@{
        ok = $true
        request = $payload
        result = Invoke-AgentRequest -Payload $payload
        elapsed_sec = [Math]::Round(((Get-Date) - $started).TotalSeconds, 3)
    }
} catch {
    $result = [ordered]@{
        ok = $false
        error = $_.Exception.GetType().Name
        message = $_.Exception.Message
        elapsed_sec = [Math]::Round(((Get-Date) - $started).TotalSeconds, 3)
    }
}

$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Response -Encoding UTF8
if ($result.ok) {
    exit 0
}
exit 1
