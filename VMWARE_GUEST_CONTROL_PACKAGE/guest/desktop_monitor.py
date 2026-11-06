"""Guestの入力先変更を、解析ワーカーとは別スレッドで記録する。"""
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import threading
import time


class DesktopMonitor:
    # 世代を付け、復元前の状態ファイルをHostが誤認しないようにする。
    def __init__(self, path, generation):
        self.path, self.generation = Path(path), generation
        self.stop_event = threading.Event()
        self.events = []
        self.sequence = 0
        self.window = None
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    # Mutex取得後のOSエージェントだけが監視を開始する。
    def start(self):
        self.thread.start()

    # メッセージループを終了させ、フックを解除する。
    def stop(self):
        self.stop_event.set()
        self.thread.join(3)

    # 重複ウィンドウ通知を抑え、デスクトップ通知は一件ずつ保持する。
    def record(self, kind, window):
        if kind == 'foreground' and window == self.window:
            return
        self.window = window
        self.sequence += 1
        self.events.append({'sequence': self.sequence, 'kind': kind,
                            'observed_at': time.time(), 'window': window})
        self.events = self.events[-512:]

    # 心拍と履歴を一つの原子的ファイルにし、転送途中のJSONを避ける。
    def publish(self):
        payload = {'generation': self.generation, 'heartbeat_at': time.time(),
                   'sequence': self.sequence, 'window': self.window,
                   'events': self.events, 'error': self.error}
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
        temporary.replace(self.path)

    # 対象プロセスへ注入しないWinEventフックと独立メッセージループを使う。
    def run(self):
        hooks = []
        try:
            user = ctypes.WinDLL('user32', use_last_error=True)
            callback_type = ctypes.WINFUNCTYPE(None, wintypes.HANDLE, wintypes.DWORD,
                wintypes.HWND, wintypes.LONG, wintypes.LONG, wintypes.DWORD, wintypes.DWORD)
            user.SetWinEventHook.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.HMODULE,
                callback_type, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
            user.SetWinEventHook.restype = wintypes.HANDLE
            user.UnhookWinEvent.argtypes = [wintypes.HANDLE]
            user.GetForegroundWindow.restype = wintypes.HWND
            user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
            user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
            user.PeekMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                                        wintypes.UINT, wintypes.UINT, wintypes.UINT]
            user.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
            user.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]

            # フックから取得可能な構造情報だけを読み、画面は取得しない。
            def window_info():
                hwnd = user.GetForegroundWindow()
                pid = wintypes.DWORD()
                title = ctypes.create_unicode_buffer(1024)
                if hwnd:
                    user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                    user.GetWindowTextW(hwnd, title, len(title))
                return {'hwnd': int(hwnd or 0), 'pid': pid.value, 'title': title.value}

            # コールバック内の例外は監視状態に残し、解析処理は止めない。
            @callback_type
            def callback(hook, event, hwnd, object_id, child_id, thread_id, event_time):
                try:
                    self.record('desktop_switch' if event == 0x0020 else 'foreground', window_info())
                except Exception as error:
                    self.error = str(error)

            for event in (0x0003, 0x0020):
                hook = user.SetWinEventHook(event, event, None, callback, 0, 0, 0)
                if not hook:
                    raise ctypes.WinError(ctypes.get_last_error())
                hooks.append(hook)
            self.window = window_info()
            message = wintypes.MSG()
            last_publish = 0
            while not self.stop_event.is_set():
                while user.PeekMessageW(ctypes.byref(message), None, 0, 0, 1):
                    user.TranslateMessage(ctypes.byref(message))
                    user.DispatchMessageW(ctypes.byref(message))
                if time.monotonic() - last_publish >= 0.5:
                    try:
                        self.publish()
                        self.error = None
                    except OSError as error:
                        # vmrunの読取と置換が競合しても、次の心拍で再試行する。
                        self.error = str(error)
                    last_publish = time.monotonic()
                self.stop_event.wait(0.05)
        except Exception as error:
            self.error = str(error)
            self.publish()
        finally:
            for hook in hooks:
                user.UnhookWinEvent(hook)
