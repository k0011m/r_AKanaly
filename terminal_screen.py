from __future__ import annotations

import ctypes
import re
import shutil
import struct
import time
from dataclasses import dataclass
from typing import TextIO

from rich.cells import cell_len


ALT_SCREEN_ON = "\x1b[?1049h"
ALT_SCREEN_OFF = "\x1b[?1049l"
CLEAR_SCREEN = "\x1b[2J\x1b[H"
CURSOR_HIDE = "\x1b[?25l"
CURSOR_SHOW = "\x1b[?25h"
STYLE_RESET = "\x1b[0m"
MOUSE_TRACKING_ON = "\x1b[?1000h\x1b[?1006h"
MOUSE_TRACKING_OFF = "\x1b[?1006l\x1b[?1000l"


@dataclass(frozen=True)
class ScreenSize:
    width: int
    height: int


# Windows ConsoleでANSIカーソル制御を利用できるようにします。
def enable_windows_virtual_terminal() -> None:
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        handle = ctypes.c_void_p(kernel32.GetStdHandle(-11))
        mode = ctypes.c_uint32()
        if handle not in (0, -1) and kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except (AttributeError, OSError):
        return


# Windowsのマウスイベントを直接受け取り、選択モードによるホイールの横取りを防ぎます。
def enable_windows_virtual_terminal_input() -> tuple[int, int] | None:
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        handle = ctypes.c_void_p(kernel32.GetStdHandle(-10))
        mode = ctypes.c_uint32()
        if handle in (0, -1) or not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return None
        if not kernel32.SetConsoleMode(handle, (mode.value | 0x0010 | 0x0080) & ~(0x0200 | 0x0040 | 0x0002 | 0x0004)):
            return None
        return handle.value, int(mode.value)
    except (AttributeError, OSError):
        return None


# コンソールAPIの固定長レコードを、文字入力と画面移動の共通イベントへ変換する。
def decode_console_record(data: bytes) -> str:
    kind = struct.unpack_from('<H', data, 0)[0]
    if kind == 2 and struct.unpack_from('<I', data, 16)[0] == 4:
        delta = struct.unpack_from('<h', data, 10)[0]
        return 'scroll_up' if delta > 0 else 'scroll_down' if delta < 0 else ''
    if kind != 1 or not struct.unpack_from('<I', data, 4)[0]:
        return ''
    key = struct.unpack_from('<H', data, 10)[0]
    character = data[14:16].decode('utf-16-le', errors='replace')
    if character == '\x03':
        raise KeyboardInterrupt
    if key in (13, 8):
        return 'enter' if key == 13 else 'backspace'
    navigation = {38: 'up', 40: 'down', 33: 'page_up', 34: 'page_down', 36: 'home', 35: 'end'}
    if key in navigation:
        return navigation[key]
    return 'text:' + character if character.isprintable() else ''


# msvcrtでは失われるマウスイベントもReadConsoleInputWで回収する。非コンソールでは従来入力へ戻す。
def read_native_console_event(*, poll: bool = False) -> str | None:
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        handle = ctypes.c_void_p(kernel32.GetStdHandle(-10))
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return None
        count = ctypes.c_uint32()
        if poll:
            if not kernel32.GetNumberOfConsoleInputEvents(handle, ctypes.byref(count)) or not count.value:
                return ''
        record = ctypes.create_string_buffer(20)
        if kernel32.ReadConsoleInputW(handle, record, 1, ctypes.byref(count)) and count.value:
            return decode_console_record(record.raw)
        return ''
    except (AttributeError, OSError):
        return None


# 結果画面で使うキーとSGRマウスホイール入力を共通イベント名へ変換します。
def read_console_navigation_event() -> str:
    import msvcrt

    native = read_native_console_event()
    if native is not None:
        return native
    key = msvcrt.getwch()
    if key == "\x03":
        raise KeyboardInterrupt
    if key in ("\r", "\n"):
        return "enter"
    if key in ("\x00", "\xe0"):
        extended = msvcrt.getwch()
        return {
            "H": "up",
            "P": "down",
            "I": "page_up",
            "Q": "page_down",
            "G": "home",
            "O": "end",
        }.get(extended, "")
    if key != "\x1b":
        return "backspace" if key == "\b" else "text:" + key if key.isprintable() else ""

    # VT入力は複数文字に分かれるため、終端文字まで短時間だけ追加文字を回収します。
    sequence = key
    deadline = time.monotonic() + 0.05
    while len(sequence) < 64 and time.monotonic() < deadline:
        if not msvcrt.kbhit():
            time.sleep(0.001)
            continue
        character = msvcrt.getwch()
        sequence += character
        if character in ("M", "m", "~") or sequence.endswith(("[A", "[B", "[H", "[F")):
            break

    mouse = re.fullmatch(r"\x1b\[<(\d+);\d+;\d+[Mm]", sequence)
    if mouse is not None:
        button = int(mouse.group(1)) & 0x41
        if button == 64:
            return "scroll_up"
        if button == 65:
            return "scroll_down"
    return {
        "\x1b[A": "up",
        "\x1b[B": "down",
        "\x1b[5~": "page_up",
        "\x1b[6~": "page_down",
        "\x1b[H": "home",
        "\x1b[F": "end",
    }.get(sequence, "")


class DifferentialScreen:
    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.active = False
        self.previous_lines: list[str] = []
        self.previous_size: ScreenSize | None = None
        self.live_navigation = False
        self.live_input_mode = None

    # 実行画面だけでホイールを受け付け、質問入力とは入力モードを分離する。
    def start_live_navigation(self) -> None:
        if not self.live_navigation:
            self.live_input_mode = enable_windows_virtual_terminal_input()
            self.live_navigation = True
            self._write(MOUSE_TRACKING_ON)

    # 質問・メニューへ戻る前に端末の入力設定を復元する。
    def stop_live_navigation(self) -> None:
        if self.live_navigation:
            self._write(MOUSE_TRACKING_OFF)
            if self.live_input_mode is not None:
                try:
                    ctypes.windll.kernel32.SetConsoleMode(ctypes.c_void_p(self.live_input_mode[0]), self.live_input_mode[1])
                except (AttributeError, OSError):
                    pass
            self.live_input_mode = None
            self.live_navigation = False

    # 描画スレッドを長く止めないよう、到着済みの入力だけを一件読む。
    def poll_navigation(self) -> str:
        import msvcrt
        native = read_native_console_event(poll=True)
        if native is not None:
            return native
        return read_console_navigation_event() if msvcrt.kbhit() else ''

    # 現在のターミナル寸法を取得し、極端に小さい値は安全な最小値へ丸めます。
    def get_size(self) -> ScreenSize:
        size = shutil.get_terminal_size((120, 30))
        return ScreenSize(max(20, size.columns), max(8, size.lines))

    # 代替画面へ入り、既存のターミナル内容を保存したままTUIを開始します。
    def enter(self) -> None:
        if self.active:
            return
        enable_windows_virtual_terminal()
        self.active = True
        self.previous_lines = []
        self.previous_size = None
        self._write(ALT_SCREEN_ON + CURSOR_HIDE + CLEAR_SCREEN)

    # 例外経路を含めてカーソルと元の画面バッファを復元します。
    def leave(self) -> None:
        self.stop_live_navigation()
        if not self.active:
            return
        self._write(STYLE_RESET + CURSOR_SHOW + ALT_SCREEN_OFF)
        self.active = False
        self.previous_lines = []
        self.previous_size = None

    # 前回との差分を比較し、変更された行だけをターミナルへ送信します。
    def draw(
        self,
        lines: list[str],
        *,
        cursor: tuple[int, int] | None = None,
        force: bool = False,
    ) -> None:
        size = self.get_size()
        visible_lines = [line.rstrip("\r\n") for line in lines[: size.height]]
        resized = size != self.previous_size
        operations: list[str] = []
        if force or resized:
            operations.append(CLEAR_SCREEN)
            previous: list[str] = []
        else:
            previous = self.previous_lines

        row_count = max(len(previous), len(visible_lines))
        for index in range(row_count):
            old_line = previous[index] if index < len(previous) else ""
            new_line = visible_lines[index] if index < len(visible_lines) else ""
            if old_line == new_line:
                continue
            operations.append(f"\x1b[{index + 1};1H\x1b[2K{new_line}")

        if cursor is None:
            operations.append(CURSOR_HIDE)
        else:
            row = min(max(1, cursor[0]), size.height)
            column = min(max(1, cursor[1]), size.width)
            operations.append(f"\x1b[{row};{column}H{CURSOR_SHOW}")

        if operations:
            self._write("".join(operations))
        self.previous_lines = visible_lines
        self.previous_size = size

    # 入力欄を下端に固定し、回答を保持したまま長い確認内容を閲覧する。
    def read_line(self, base_lines: list[str], prompt: str, *, secret: bool = False) -> str:
        characters: list[str] = []
        offset = 0
        self.start_live_navigation()
        try:
            while True:
                size = self.get_size()
                page = max(1, size.height - 2)
                limit = max(0, len(base_lines) - page)
                offset = min(offset, limit)
                base = list(base_lines[offset:offset + page])
                rendered_value = '*' * len(characters) if secret else ''.join(characters)
                available_width = max(1, size.width - cell_len(prompt))
                while rendered_value and cell_len(rendered_value) > available_width:
                    rendered_value = rendered_value[1:]
                input_line = prompt + rendered_value
                footer = f'ホイール/↑↓・PgUp/PgDn: スクロール [{offset + 1}-{min(len(base_lines), offset + page)}/{len(base_lines)}]'
                base += [''] * (page - len(base))
                self.draw(base + [footer, input_line], cursor=(size.height, min(size.width, cell_len(input_line) + 1)))
                event = read_console_navigation_event()
                if event == 'enter':
                    return ''.join(characters)
                if event == 'backspace':
                    if characters:
                        characters.pop()
                elif event.startswith('text:'):
                    characters.append(event[5:])
                elif event == 'home':
                    offset = 0
                elif event == 'end':
                    offset = limit
                else:
                    delta = {'up': -1, 'down': 1, 'scroll_up': -3, 'scroll_down': 3,
                             'page_up': -page, 'page_down': page}.get(event, 0)
                    offset = max(0, min(limit, offset + delta))
        finally:
            self.stop_live_navigation()
            self.draw(base_lines)

    # 画面を超える結果をホイールまたは移動キーで閲覧し、Enterで終了します。
    def read_scrollable(self, lines: list[str], prompt: str) -> None:
        offset = 0
        input_mode = enable_windows_virtual_terminal_input()
        self._write(MOUSE_TRACKING_ON)
        try:
            while True:
                size = self.get_size()
                page_height = max(1, size.height - 1)
                max_offset = max(0, len(lines) - page_height)
                offset = min(max(0, offset), max_offset)
                end = min(len(lines), offset + page_height)
                position = f" [{offset + 1}-{end}/{len(lines)}]" if max_offset else ""
                footer = f"{prompt}  ホイール/↑↓: スクロール{position}"
                self.draw(lines[offset:end] + [footer])

                event = read_console_navigation_event()
                if event == "enter":
                    return
                if event in ("up", "scroll_up"):
                    offset -= 3 if event == "scroll_up" else 1
                elif event in ("down", "scroll_down"):
                    offset += 3 if event == "scroll_down" else 1
                elif event == "page_up":
                    offset -= page_height
                elif event == "page_down":
                    offset += page_height
                elif event == "home":
                    offset = 0
                elif event == "end":
                    offset = max_offset
        finally:
            self._write(MOUSE_TRACKING_OFF)
            if input_mode is not None:
                try:
                    ctypes.windll.kernel32.SetConsoleMode(ctypes.c_void_p(input_mode[0]), input_mode[1])
                except (AttributeError, OSError):
                    pass

    def _write(self, value: str) -> None:
        self.stream.write(value)
        self.stream.flush()
