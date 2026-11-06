import argparse
import ctypes
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from ctypes import wintypes
from archive_ops import extract_zip, public_request


user32 = ctypes.WinDLL("user32", use_last_error=True)

INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_ABSOLUTE = 0x8000

VK_CODES = {
    "ENTER": 0x0D,
    "RETURN": 0x0D,
    "ESC": 0x1B,
    "ESCAPE": 0x1B,
    "TAB": 0x09,
    "SPACE": 0x20,
    "BACKSPACE": 0x08,
    "DELETE": 0x2E,
    "CTRL": 0x11,
    "CONTROL": 0x11,
    "ALT": 0x12,
    "SHIFT": 0x10,
    "WIN": 0x5B,
    "LEFT": 0x25,
    "UP": 0x26,
    "RIGHT": 0x27,
    "DOWN": 0x28,
    "F1": 0x70,
    "F2": 0x71,
    "F3": 0x72,
    "F4": 0x73,
    "F5": 0x74,
    "F6": 0x75,
    "F7": 0x76,
    "F8": 0x77,
    "F9": 0x78,
    "F10": 0x79,
    "F11": 0x7A,
    "F12": 0x7B
}


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD)
    ]


class INPUTUNION(ctypes.Union):
    _fields_ = [
        ("mi", MOUSEINPUT),
        ("ki", KEYBDINPUT),
        ("hi", HARDWAREINPUT)
    ]


class INPUT(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("union", INPUTUNION)
    ]


EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
user32.SendInput.argtypes = (wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int)
user32.SendInput.restype = wintypes.UINT
user32.GetSystemMetrics.argtypes = (ctypes.c_int,)
user32.GetSystemMetrics.restype = ctypes.c_int
user32.SetCursorPos.argtypes = (ctypes.c_int, ctypes.c_int)
user32.SetCursorPos.restype = wintypes.BOOL
user32.GetForegroundWindow.restype = wintypes.HWND
user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
user32.GetClassNameW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
user32.GetWindowRect.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.RECT))
user32.EnumWindows.argtypes = (EnumWindowsProc, wintypes.LPARAM)


# HWNDが取得できないセッションでもobserveを失敗させず、診断情報としてnullを返す。
def hwnd_to_int(hwnd):
    return int(hwnd) if hwnd else None


# SendInputの戻り値を確認し、失敗時にWin32エラーを呼び出し元へ返せるようにする。
def send_inputs(inputs):
    array_type = INPUT * len(inputs)
    sent = user32.SendInput(len(inputs), array_type(*inputs), ctypes.sizeof(INPUT))
    if sent != len(inputs):
        raise ctypes.WinError(ctypes.get_last_error())


# Unicode文字を仮想キー配列に依存せず入力する。
def type_text(text, delay=0.01):
    for char in text:
        code = ord(char)
        down = INPUT(type=INPUT_KEYBOARD, union=INPUTUNION(ki=KEYBDINPUT(0, code, KEYEVENTF_UNICODE, 0, None)))
        up = INPUT(type=INPUT_KEYBOARD, union=INPUTUNION(ki=KEYBDINPUT(0, code, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, 0, None)))
        send_inputs([down, up])
        if delay:
            time.sleep(delay)


# Ctrl+Lなどの複合キーを順序付きで押下して解放する。
def press_key(keys):
    if isinstance(keys, str):
        parts = [part.strip() for part in keys.replace("+", " ").split() if part.strip()]
    else:
        parts = keys

    codes = []
    for part in parts:
        key = str(part).upper()
        if len(key) == 1:
            codes.append(ord(key))
        elif key in VK_CODES:
            codes.append(VK_CODES[key])
        else:
            raise ValueError(f"Unknown key: {part}")

    inputs = []
    for code in codes:
        inputs.append(INPUT(type=INPUT_KEYBOARD, union=INPUTUNION(ki=KEYBDINPUT(code, 0, 0, 0, None))))
    for code in reversed(codes):
        inputs.append(INPUT(type=INPUT_KEYBOARD, union=INPUTUNION(ki=KEYBDINPUT(code, 0, KEYEVENTF_KEYUP, 0, None))))
    send_inputs(inputs)


# 画面座標へマウスを移動し、左クリックを送る。
def click(x, y):
    if not user32.SetCursorPos(int(x), int(y)):
        raise ctypes.WinError(ctypes.get_last_error())
    down = INPUT(type=INPUT_MOUSE, union=INPUTUNION(mi=MOUSEINPUT(0, 0, 0, MOUSEEVENTF_LEFTDOWN, 0, None)))
    up = INPUT(type=INPUT_MOUSE, union=INPUTUNION(mi=MOUSEINPUT(0, 0, 0, MOUSEEVENTF_LEFTUP, 0, None)))
    send_inputs([down, up])


# Hostへ返すため、前面ウィンドウと主要トップレベルウィンドウを収集する。
def observe():
    windows = []

    def callback(hwnd, _):
        title_buffer = ctypes.create_unicode_buffer(512)
        class_buffer = ctypes.create_unicode_buffer(256)
        rect = wintypes.RECT()
        user32.GetWindowTextW(hwnd, title_buffer, len(title_buffer))
        user32.GetClassNameW(hwnd, class_buffer, len(class_buffer))
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        title = title_buffer.value
        if title:
            windows.append({
                "hwnd": hwnd_to_int(hwnd),
                "title": title,
                "class": class_buffer.value,
                "rect": {
                    "left": rect.left,
                    "top": rect.top,
                    "right": rect.right,
                    "bottom": rect.bottom
                }
            })
        return True

    user32.EnumWindows(EnumWindowsProc(callback), 0)
    foreground = user32.GetForegroundWindow()
    width = user32.GetSystemMetrics(0)
    height = user32.GetSystemMetrics(1)
    return {
        "screen": {"width": width, "height": height},
        "foreground_hwnd": hwnd_to_int(foreground),
        "windows": windows[:50]
    }


# アプリやファイルをGuest内の通常プロセスとして起動する。
def launch_app(path_or_name, args=None):
    args = args or []
    if os.path.exists(path_or_name):
        if args:
            process = subprocess.Popen([path_or_name] + args)
        else:
            os.startfile(path_or_name)
            process = None
    else:
        process = subprocess.Popen([path_or_name] + args, shell=False)
    return {"pid": process.pid if process else None}


# SendInputが対象アプリに届かない場合でも、Notepad上で内容を確認できるようにファイル経由で開く。
def open_text_in_notepad(text, path=None):
    path = path or r"C:\Users\Public\CodexGuestAgent\hello-world.txt"
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    process = subprocess.Popen(["C:\\Windows\\System32\\notepad.exe", path])
    return {"path": path, "pid": process.pid, "written": len(text)}


# resident agentをブロックしないよう、別プロセスで複数のMessageBoxを順番に表示する。
def spawn_messageboxes(text, title=None, count=3):
    agent_dir = Path(r"C:\Users\Public\CodexGuestAgent")
    script_path = agent_dir / "messagebox_sequence.py"
    title = title or "Codex MessageBox Test"
    count = int(count)
    script = f"""import ctypes

user32 = ctypes.windll.user32
for index in range(1, {count} + 1):
    user32.MessageBoxW(None, {text!r} + " #" + str(index), {title!r}, 0)
"""
    script_path.write_text(script, encoding="utf-8")
    pythonw = agent_dir / "python" / "pythonw.exe"
    process = subprocess.Popen([str(pythonw), str(script_path)])
    return {"pid": process.pid, "script": str(script_path), "count": count}


# JSONリクエストをGuest操作へ割り当て、ZIPは展開だけを行う。
def handle_request(request):
    action = request.get("action")
    if action == "extract_zip":
        return extract_zip(request["archive_path"], request["destination"], request.get("password"),
                           request.get("max_total_bytes", 4 * 1024**3), request.get("max_members", 10000),
                           request.get("max_seconds", 300))
    if action == "observe":
        return observe()
    if action == "launch_app":
        return launch_app(request["path"], request.get("args"))
    if action == "click":
        click(request["x"], request["y"])
        return {"clicked": [request["x"], request["y"]]}
    if action == "type_text":
        type_text(request.get("text", ""), float(request.get("delay", 0.01)))
        return {"typed": len(request.get("text", ""))}
    if action == "press_key":
        press_key(request["keys"])
        return {"pressed": request["keys"]}
    if action == "open_url":
        url = request["url"]
        launch_app("cmd.exe", ["/c", "start", "", url])
        return {"opened_url": url}
    if action == "open_text_in_notepad":
        return open_text_in_notepad(request.get("text", ""), request.get("path"))
    if action == "spawn_messageboxes":
        return spawn_messageboxes(
            request.get("text", "Click OK to continue"),
            request.get("title"),
            request.get("count", 3)
        )
    raise ValueError(f"Unknown action: {action}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--response", required=True)
    args = parser.parse_args()

    started = time.time()
    try:
        with open(args.request, "r", encoding="utf-8") as handle:
            request = json.load(handle)
        if request.get("action") == "extract_zip":
            Path(args.request).unlink()
        result = {
            "ok": True,
            "request": public_request(request),
            "result": handle_request(request),
            "elapsed_sec": round(time.time() - started, 3)
        }
    except Exception as exc:
        result = {
            "ok": False,
            "error": type(exc).__name__,
            "message": str(exc),
            "elapsed_sec": round(time.time() - started, 3)
        }

    with open(args.response, "w", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
