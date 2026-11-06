from __future__ import annotations

import sys
from getpass import getpass


# プロンプト表示と1行入力を明示的に分離し、対話・リダイレクト双方で回答を一度だけ読み取ります。
def read_user_input(prompt: str) -> str:
    # TUI実行中はLive表示を停止できる入力ハンドラへ質問を委譲します。
    try:
        import tui_runtime

        tui_value = tui_runtime.read_input(prompt)
    except ImportError:
        tui_value = None
    if tui_value is not None:
        return tui_value
    sys.stdout.write(prompt)
    sys.stdout.flush()
    line = sys.stdin.readline()
    if line == "":
        raise EOFError
    return line.rstrip("\r\n")


# パスワード入力もTUIと通常CLIで同じ呼び出し口を使用します。
def read_secret(prompt: str) -> str:
    try:
        import tui_runtime

        tui_value = tui_runtime.read_input(prompt, secret=True)
    except ImportError:
        tui_value = None
    if tui_value is not None:
        return tui_value
    if not sys.stdin.isatty():
        # 自動実行のパイプ入力は値を表示せず読む。Windows getwchの無限待機を避ける。
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = sys.stdin.readline()
        if line == '':
            raise EOFError
        return line.rstrip('\r\n')
    return getpass(prompt)


# 待機処理が後続の質問を横取りしないよう、標準入力を消費せずに入力有無だけを確認します。
def user_input_available() -> bool:
    try:
        file_descriptor = sys.stdin.fileno()
    except (AttributeError, OSError, ValueError):
        return False

    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        if sys.stdin.isatty():
            return msvcrt.kbhit()

        available = wintypes.DWORD()
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(file_descriptor))
        succeeded = ctypes.windll.kernel32.PeekNamedPipe(
            handle,
            None,
            0,
            None,
            ctypes.byref(available),
            None,
        )
        return bool(succeeded and available.value > 0)
    except (AttributeError, ImportError, OSError, ValueError):
        return False
