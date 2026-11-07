"""導入先をユーザー環境へ登録する。管理者環境・Guestには触れない。"""
import ctypes
from ctypes import wintypes
import os
from pathlib import Path


# 引用符・末尾区切り・大文字小文字によるPATHの重複登録を防ぐ。
def path_key(value):
    return os.path.normcase(os.path.normpath(os.path.expandvars(value.strip().strip('"'))))


# 既存のユーザーPATHを保持し、導入先だけを末尾に一度追加する。
def append_install_path(current, root):
    if any(path_key(entry) == path_key(root) for entry in current.split(';') if entry.strip()):
        return current
    return current + ('' if not current or current.endswith(';') else ';') + root


# Setup成功後に永続登録し、新規起動アプリへ環境変更を通知する。
def register_installation(root):
    import winreg
    root = str(Path(root).resolve())
    if not (Path(root) / 'current.json').is_file():
        raise RuntimeError('Installation must be activated before environment registration')
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, 'Environment', 0,
                           winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
        try:
            current, kind = winreg.QueryValueEx(key, 'Path')
        except FileNotFoundError:
            current, kind = '', winreg.REG_EXPAND_SZ
        if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(current, str):
            raise ValueError('User Path must be a string registry value')
        updated = append_install_path(current, root)
        winreg.SetValueEx(key, 'R_AKANALY_HOME', 0, winreg.REG_SZ, root)
        if updated != current:
            winreg.SetValueEx(key, 'Path', 0, kind, updated)
    os.environ['R_AKANALY_HOME'] = root
    # 既存Terminalの環境は変更できない。通知失敗も結果として報告する。
    result = ctypes.c_size_t()
    send = ctypes.windll.user32.SendMessageTimeoutW
    send.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM,
                     wintypes.LPCWSTR, wintypes.UINT, wintypes.UINT,
                     ctypes.POINTER(ctypes.c_size_t)]
    send.restype = ctypes.c_ssize_t
    notified = send(
        0xffff, 0x001a, 0, ctypes.c_wchar_p('Environment'), 2, 3000,
        ctypes.byref(result))
    return {'home': root, 'path_added': updated != current, 'notified': bool(notified)}
