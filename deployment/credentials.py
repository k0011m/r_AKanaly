"""現在のWindowsユーザーのDPAPIで資格情報を保管する。"""
import base64
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
from .storage import atomic_json

class Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

# DPAPIを利用し、通常の設定やログに平文を保存しない。
def protect(data, decrypt=False):
    if os.name != "nt":
        raise RuntimeError("Windows DPAPI required")
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    operation = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    operation.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    operation.restype = wintypes.BOOL
    if not operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel = ctypes.WinDLL("kernel32")
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        kernel.LocalFree(target.data)

# 資格情報は専用ファイルへ暗号化して保存する。
def save(root, values):
    atomic_json(Path(root) / "config/credentials.dpapi.json", {"data": base64.b64encode(protect(json.dumps(values).encode())).decode()})

# 子プロセスへ渡す直前にのみ復号する。
def load(root):
    path = Path(root) / "config/credentials.dpapi.json"
    if not path.exists():
        return {}
    return json.loads(protect(base64.b64decode(json.loads(path.read_text())["data"]), decrypt=True))
