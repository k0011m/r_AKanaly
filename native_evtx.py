"""保存済みEVTXをWindows Event Log APIで列挙する。"""
import ctypes as C
from ctypes import wintypes as W


# ハンドルを同じスレッド内で生成・列挙・解放し、途中失敗でも全件閉じる。
def event_xml(path):
    api = C.WinDLL('wevtapi', use_last_error=True)
    api.EvtQuery.argtypes = [W.HANDLE, W.LPCWSTR, W.LPCWSTR, W.DWORD]
    api.EvtQuery.restype = W.HANDLE
    api.EvtNext.argtypes = [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE), W.DWORD, W.DWORD, C.POINTER(W.DWORD)]
    api.EvtNext.restype = W.BOOL
    api.EvtRender.argtypes = [W.HANDLE, W.HANDLE, W.DWORD, W.DWORD, C.c_void_p, C.POINTER(W.DWORD), C.POINTER(W.DWORD)]
    api.EvtRender.restype = W.BOOL
    api.EvtClose.argtypes = [W.HANDLE]
    api.EvtClose.restype = W.BOOL
    query = api.EvtQuery(None, str(path), '*', 2 | 0x100)
    if not query:
        raise C.WinError(C.get_last_error())
    handles = (W.HANDLE * 64)()
    count = W.DWORD()
    used, properties = W.DWORD(), W.DWORD()
    buffer = C.create_unicode_buffer(8192)
    try:
        while True:
            if not api.EvtNext(query, 64, handles, 1000, 0, C.byref(count)):
                error = C.get_last_error()
                if error == 259:
                    break
                raise C.WinError(error)
            try:
                for index in range(count.value):
                    if not api.EvtRender(None, handles[index], 1, C.sizeof(buffer), buffer, C.byref(used), C.byref(properties)):
                        error = C.get_last_error()
                        if error != 122:
                            raise C.WinError(error)
                        buffer = C.create_unicode_buffer((used.value + C.sizeof(C.c_wchar) - 1) // C.sizeof(C.c_wchar))
                        if not api.EvtRender(None, handles[index], 1, C.sizeof(buffer), buffer, C.byref(used), C.byref(properties)):
                            raise C.WinError(C.get_last_error())
                    yield buffer.value
            finally:
                for index in range(count.value):
                    api.EvtClose(handles[index])
    finally:
        api.EvtClose(query)
