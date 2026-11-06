from __future__ import annotations

import json
import sys
import threading
from io import StringIO
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, TextIO

from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown

from terminal_screen import DifferentialScreen
import tui_runtime


LOGO_SEGMENTS = (
    ("bold bright_yellow", (
        "         ", " _ __    ", "| '__|   ",
        "| |      ", "|_| _____", "   |_____|",
    )),
    ("bold bright_cyan", (
        "    _    _  __", r"   / \  | |/ /", r"  / _ \ | ' / ",
        r" / ___ \| . \ ", "/_/   \\_\\_|\\_\\", "             ",
    )),
    ("bold bright_white", (
        "                   _", "  __ _  _ __   __ _| | _   _",
        r" / _` || '_ \ / _` | || | | |",
        "| (_| || | | | (_| | || |_| |",
        r" \__,_||_| |_|\__,_|_| \__, |",
        "                     |___/",
    )),
)
LOGO_TAGLINE = "       STATIC + DYNAMIC  /  LLM ANALYSIS"
LOGO = "\n".join(
    "".join(rows[index] for _, rows in LOGO_SEGMENTS)
    for index in range(6)
) + "\n\n" + LOGO_TAGLINE


# 文字領域ごとに色を付け、メニューと実行画面で同じロゴを使います。
def build_logo() -> Text:
    logo = Text(no_wrap=True, overflow="crop")
    for index in range(6):
        for style, rows in LOGO_SEGMENTS:
            logo.append(rows[index], style=style)
        logo.append("\n")
    logo.append("\n" + LOGO_TAGLINE, style="bright_white")
    return logo


PATH_KEY_SUFFIXES = ("_path", "_dir", "_directory")
SPINNER_FRAMES = ("|", "/", "-", "\\")
SPINNER_FPS = 8


# 既知の失敗文字列を利用者が次に確認できる自然言語へ変換します。
def explain_error(message: str) -> str:
    lowered = message.lower()
    explanations = (
        (
            "codex-package.json",
            "Codex CLIの同梱データが不足しています。r_AKanaly.specを使って3つのEXEを再ビルドしてください。",
        ),
        (
            "sessionstart was not observed",
            "SessionStart Hookが起動されていません。対象PJのtrust、最新Hookの再承認、SDK同梱Codexランタイムを確認してください。",
        ),
        (
            "malware guard self-tests failed",
            "Guard専用EXEと現在のHook設定が一致していません。3つのEXEが同じビルドのものか確認してください。",
        ),
        (
            "required ghidra mcp calls",
            "必要なGhidra MCP操作が完了していません。Ghidra Headlessのパス、タイムアウト、MCP履歴を確認してください。",
        ),
        (
            "vmrun.exe was not found",
            "vmrun.exeを確認できません。vmware.vmrun_pathの指定、または実行時のパス入力を確認してください。",
        ),
        (
            "vmx file was not found",
            "対象VMのVMXファイルが見つかりません。VMware設定の絶対パスを確認してください。",
        ),
        (
            "copy timed out",
            "Guestからのログ転送が制限時間内に完了しませんでした。Guest Tools、出力パス、待機時間を確認してください。",
        ),
        (
            "access is denied",
            "Windowsがファイルまたはコマンドへのアクセスを拒否しました。対象パスとACLを確認してください。",
        ),
    )
    for token, explanation in explanations:
        if token in lowered:
            return explanation
    return "処理を継続できませんでした。表示されたパスと直前の処理段階を確認してください。"


# JSONから利用者が編集できるパス項目だけを再帰的に列挙します。
def collect_path_fields(value: dict[str, Any], prefix: str = "") -> list[tuple[str, str | None]]:
    fields: list[tuple[str, str | None]] = []
    for key, item in value.items():
        dotted = f"{prefix}.{key}" if prefix else key
        if isinstance(item, dict):
            fields.extend(collect_path_fields(item, dotted))
        elif key.endswith(PATH_KEY_SUFFIXES) and (item is None or isinstance(item, str)):
            fields.append((dotted, item))
    return fields


# ドット区切りキーで指定されたJSONのパス値だけを更新します。
def set_nested_value(data: dict[str, Any], dotted_key: str, value: str | None) -> None:
    keys = dotted_key.split(".")
    current = data
    for key in keys[:-1]:
        child = current.get(key)
        if not isinstance(child, dict):
            child = {}
            current[key] = child
        current = child
    current[keys[-1]] = value


# Windows絶対パスだけを設定値として受理します。
def normalize_absolute_path(raw_value: str) -> str | None:
    value = raw_value.strip().strip('"').strip("'").strip()
    if not value:
        return None
    if not PureWindowsPath(value).is_absolute():
        raise ValueError("絶対パスを入力してください。空欄は未設定になります。")
    return value


# Richで幅を計算してANSIカラー付きの行を作り、差分描画へ渡します。
def render_to_lines(renderable: RenderableType, width: int, height: int) -> list[str]:
    output = StringIO()
    console = Console(
        file=output,
        width=width,
        height=height,
        color_system="standard",
        force_terminal=True,
        legacy_windows=False,
        no_color=False,
        soft_wrap=False,
    )
    console.print(renderable, end="")
    # 入力行や次のパネルへ装飾を持ち越さないよう、各行で必ず解除します。
    return [line + "\x1b[0m" for line in output.getvalue().splitlines()]


class _StatusWriter:
    def __init__(self, view: "ExecutionView", original: TextIO) -> None:
        self.view = view
        self.original = original
        self.buffer = ""

    # 既存printの最新行だけを状態欄へ送り、ログによる画面スクロールを防ぎます。
    def write(self, value: str) -> int:
        self.buffer += value
        parts = self.buffer.replace("\r", "").split("\n")
        self.buffer = parts.pop()
        for part in parts:
            if part.strip():
                self.view.set_status(part.strip())
        return len(value)

    def flush(self) -> None:
        if self.buffer.strip():
            self.view.set_status(self.buffer.strip())
            self.buffer = ""

    def isatty(self) -> bool:
        return False

    def fileno(self) -> int:
        return self.original.fileno()


class ExecutionView:
    def __init__(self, screen: DifferentialScreen) -> None:
        self.screen = screen
        self.stage_index = 0
        self.status = "実行準備中"
        self.session_progress = ''
        self.sample_progress = ''
        self.scroll_offset = 0
        self.error_message: str | None = None
        self.confirmation_items: list[tuple[str, str]] = []
        self.output_items: list[tuple[str, str]] = []
        self.started = False
        self.spinner_index = 0
        self.spinner_enabled = True
        self.animation_paused = False
        self.animation_stop = threading.Event()
        self.animation_thread: threading.Thread | None = None
        self.render_lock = threading.RLock()
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr

    # 現在位置は色と先頭マークで示し、矢印の幅を確保して工程名だけを省略する。
    def render_roadmap(self) -> RenderableType:
        table = Table.grid(expand=True)
        for index, _ in enumerate(tui_runtime.STAGES):
            table.add_column(justify="center", ratio=1, min_width=3,
                             no_wrap=True, overflow="ellipsis")
            if index < len(tui_runtime.STAGES) - 1:
                table.add_column(width=3, no_wrap=True)
        labels: list[Text] = []
        for index, stage in enumerate(tui_runtime.STAGES):
            current = index == self.stage_index and tui_runtime.STAGE_RESULTS.get(stage, {}).get('state', 'pending') != 'pending'
            label = Text('▶ ' + stage if current else stage,
                         style='bold bright_cyan' if current else '',
                         no_wrap=True, overflow='ellipsis')
            labels.append(label)
            if index < len(tui_runtime.STAGES) - 1:
                labels.append(Text(' → ', style='white', no_wrap=True))
        table.add_row(*labels)
        return Panel(table, title="解析ロードマップ", border_style="white")

    # ロゴ、ロードマップ、最新状態、必要ならエラー説明を固定画面へまとめます。
    def render(self) -> RenderableType:
        status_title = "現在の処理"
        if self.started and self.spinner_enabled:
            status_title += f" {SPINNER_FRAMES[self.spinner_index]}"
        items: list[RenderableType] = [
            Align.center(build_logo()),
            self.render_roadmap(),
            Panel(Text(self.status + ('\n\n' + self.session_progress if self.session_progress else ''),
                       overflow='fold', no_wrap=False), title=status_title),
        ]
        if self.sample_progress:
            items.insert(2, Panel(Text(self.sample_progress, overflow='fold'), title='検体進捗'))
        if self.error_message:
            detail = Text(self.error_message + "\n\n" + explain_error(self.error_message))
            items.append(Panel(detail, title="エラー", border_style="white"))
        if self.confirmation_items:
            table = Table("項目", "内容", expand=True)
            for label, value in self.confirmation_items:
                table.add_row(label, value)
            items.append(Panel(table, title="実行前の最終確認"))
        if self.output_items:
            table = Table("出力", "保存先", expand=True)
            for label, value in self.output_items:
                table.add_row(label, value)
            items.append(Panel(table, title="今回の出力"))
        if tui_runtime.STAGE_RESULTS:
            results = Table('工程', '結果', expand=True)
            for name, detail in tui_runtime.result_items(include_usage=not self.started):
                results.add_row(name, detail)
            items.append(Panel(results, title='工程別結果（終了＝保存・停止などの後処理）'))
        return Group(*items)

    # 現在のターミナル寸法に合わせて固定画面を行配列へ変換します。
    def render_lines(self) -> list[str]:
        size = self.screen.get_size()
        return render_to_lines(self.render(), size.width, size.height)

    # 初回画面を描画し、既存printをイベント駆動の状態更新へ転送します。
    def start(self) -> None:
        with self.render_lock:
            self.started = True
            self.spinner_enabled = True
            self.animation_paused = False
            self.spinner_index = 0
            self.animation_stop.clear()
            self.screen.start_live_navigation()
            self.refresh()
            sys.stdout = _StatusWriter(self, self.original_stdout)
            sys.stderr = _StatusWriter(self, self.original_stderr)
            tui_runtime.set_active_bridge(self)
        self.animation_thread = threading.Thread(
            target=self.run_animation,
            name="r_AKanaly-tui-spinner",
            daemon=True,
        )
        self.animation_thread.start()

    # 標準ストリームとTUIブリッジを必ず元へ戻します。
    def stop(self) -> None:
        self.animation_stop.set()
        animation_thread = self.animation_thread
        if animation_thread is not None and animation_thread is not threading.current_thread():
            animation_thread.join(timeout=max(1.0, 2.0 / SPINNER_FPS))
        with self.render_lock:
            self.animation_thread = None
            self.screen.stop_live_navigation()
            tui_runtime.set_active_bridge(None)
            sys.stdout = self.original_stdout
            sys.stderr = self.original_stderr
            self.started = False

    # 一定FPSでスピナーを進め、各フレームの描画時に画面サイズを取得し直します。
    def run_animation(self) -> None:
        frame_interval = 1.0 / SPINNER_FPS
        while not self.animation_stop.wait(frame_interval):
            with self.render_lock:
                if not self.animation_paused:
                    try:
                        self.scroll(self.screen.poll_navigation())
                    except KeyboardInterrupt:
                        # 入力は描画スレッドで受けるため、中断を解析側のメインスレッドへ渡す。
                        import _thread
                        _thread.interrupt_main()
            self.advance_spinner()

    # 現在の表示位置だけを移動し、解析やセッションの処理には触れない。
    def scroll(self, event: str) -> None:
        if event not in ('up', 'down', 'scroll_up', 'scroll_down', 'page_up', 'page_down', 'home', 'end'):
            return
        with self.render_lock:
            page = max(1, self.screen.get_size().height - 1)
            limit = max(0, len(self.render_lines()) - page)
            delta = {'up': -1, 'down': 1, 'scroll_up': -3, 'scroll_down': 3,
                     'page_up': -page, 'page_down': page}.get(event, 0)
            self.scroll_offset = (0 if event == 'home' else limit if event == 'end'
                                  else min(limit, max(0, self.scroll_offset + delta)))
            self.refresh()

    # 入力待機中と完了後を除き、次のスピナーフレームへ進めて差分描画します。
    def advance_spinner(self) -> None:
        with self.render_lock:
            if not self.started or not self.spinner_enabled or self.animation_paused:
                return
            self.spinner_index = (self.spinner_index + 1) % len(SPINNER_FRAMES)
            self.refresh()

    # 状態変更時だけ新旧行を比較し、変化した行を更新します。
    def refresh(self) -> None:
        with self.render_lock:
            if self.started:
                lines = self.render_lines()
                size = self.screen.get_size()
                page = max(1, size.height - 1)
                self.scroll_offset = min(self.scroll_offset, max(0, len(lines) - page))
                end = min(len(lines), self.scroll_offset + page)
                footer = f'ホイール/↑↓・PgUp/PgDn: スクロール  Home/End: 先頭/末尾 [{self.scroll_offset + 1}-{end}/{len(lines)}]'
                footer_line = render_to_lines(Text(footer, no_wrap=True, overflow='crop'), size.width, 1)[0]
                self.screen.draw(lines[self.scroll_offset:end] + [footer_line])

    def set_stage(self, stage: str, message: str) -> None:
        with self.render_lock:
            self.session_progress = ''
            if stage in tui_runtime.STAGES:
                self.stage_index = tui_runtime.STAGES.index(stage)
            self.status = message
            self.spinner_enabled = stage != "終了"
            self.refresh()

    def set_status(self, message: str) -> None:
        with self.render_lock:
            if message:
                self.status = message
                self.refresh()

    # 最新進捗は工程説明と分けて保持し、Richの幅に合わせて改行する。
    def set_session_progress(self, phase: str, message: str) -> None:
        with self.render_lock:
            self.session_progress = phase + '\n' + message
            self.refresh()

    # 検体の切り替えだけで更新し、工程変更や通常ログでは上書きしない。
    def set_sample_progress(self, index: int, total: int, filename: str) -> None:
        with self.render_lock:
            self.sample_progress = f'{index}/{total}件目 | {filename}' if total else ''
            self.refresh()

    # 質問を固定入力行へ表示し、回答後は同じ画面上で処理状態へ戻します。
    def read_input(self, prompt: str, secret: bool = False) -> str:
        with self.render_lock:
            self.animation_paused = True
            self.screen.stop_live_navigation()
            input_lines = self.render_lines()
        try:
            value = self.screen.read_line(input_lines, prompt, secret=secret)
        finally:
            with self.render_lock:
                self.screen.start_live_navigation()
                self.animation_paused = False
        with self.render_lock:
            self.status = "入力を受け付けました。次の処理を実行しています"
            self.refresh()
            return value

    def show_error(self, message: str) -> None:
        with self.render_lock:
            self.spinner_enabled = False
            self.error_message = message
            self.refresh()

    # 最終確認中だけ実行対象を固定表示し、回答後の処理画面では非表示にします。
    def set_confirmation(self, items: list[tuple[str, str]]) -> None:
        with self.render_lock:
            self.confirmation_items = list(items)
            self.refresh()

    # 解析完了後も成果物の保存先を結果画面へ残します。
    def set_outputs(self, items: list[tuple[str, str]]) -> None:
        with self.render_lock:
            self.confirmation_items = []
            self.output_items = list(items)
            self.refresh()


class TuiApplication:
    def __init__(
        self,
        run_engine: Callable[[list[str] | None], int],
        settings_path: Path,
        screen: DifferentialScreen | None = None,
    ) -> None:
        self.screen = screen or DifferentialScreen(sys.stdout)
        self.run_engine = run_engine
        self.settings_path = settings_path.resolve()

    # 任意の固定レイアウトを現在の画面寸法に合わせて描画します。
    def draw_renderable(self, renderable: RenderableType, *, force: bool = False) -> list[str]:
        size = self.screen.get_size()
        lines = render_to_lines(renderable, size.width, size.height)
        self.screen.draw(lines, force=force)
        return lines

    # 共通の色付きロゴとキーボード選択式のメインメニューを表示します。
    def show_menu(self) -> str:
        options = ("実行", "設定", "ヘルプ", "更新", "終了")
        selected = 0
        while True:
            menu_items: list[RenderableType] = [
                Align.center(build_logo()),
                Align.center(Text("Malware Analysis Orchestrator\n")),
            ]
            for index, option in enumerate(options):
                marker = ">" if index == selected else " "
                menu_items.append(Align.center(Text(f"{marker} {option}")))
            menu_items.append(Align.center(Text("↑/↓: 選択  Enter: 決定")))
            self.draw_renderable(Group(*menu_items))
            key = self._read_menu_key()
            if key == "up":
                selected = (selected - 1) % len(options)
            elif key == "down":
                selected = (selected + 1) % len(options)
            elif key == "enter":
                return options[selected]

    # Windowsコンソールの拡張キーを読み、メニュー操作へ正規化します。
    def _read_menu_key(self) -> str:
        import msvcrt

        key = msvcrt.getwch()
        if key == "\x03":
            raise KeyboardInterrupt
        if key in ("\x00", "\xe0"):
            extended = msvcrt.getwch()
            return {"H": "up", "P": "down"}.get(extended, "")
        if key == "\r":
            return "enter"
        return ""

    # 既存解析エンジンを差分描画画面の中で実行します。
    def execute(self) -> None:
        tui_runtime.reset_results()
        view = ExecutionView(self.screen)
        view.start()
        try:
            result = self.run_engine(["--settings", str(self.settings_path)])
            # 成否は終了ステージの位置ではなく、解析エンジンの終了コードだけで判断します。
            if result == 0:
                if self.view_is_before_completion(view):
                    view.set_stage("終了", "処理は終了しました。工程別結果を確認してください")
            elif view.error_message is None:
                view.show_error(view.status.removeprefix("Error: "))
        except Exception as error:
            view.show_error(str(error))
        finally:
            view.stop()
        self.screen.draw(view.render_lines())
        self.wait_for_menu_return(view.render_lines())

    # 実行エンジンが完了・取消理由を設定済みなら、その最終表示を上書きしません。
    def view_is_before_completion(self, view: ExecutionView) -> bool:
        return view.stage_index < len(tui_runtime.STAGES) - 1

    # 結果全体をスクロール可能にし、Ctrl+CはEnterと同様にメニューへ戻します。
    def wait_for_menu_return(self, lines: list[str]) -> None:
        try:
            self.screen.read_scrollable(lines, "Enterでメニューへ戻ります")
        except (KeyboardInterrupt, EOFError):
            return

    # 設定編集画面の共通レイアウトを生成します。
    def render_settings(self, data: dict[str, Any] | None, message: str = "") -> RenderableType:
        items: list[RenderableType] = [Panel(str(self.settings_path), title="設定JSON")]
        if data is not None:
            table = Table("No.", "設定項目", "現在値", expand=True)
            for index, (key, value) in enumerate(collect_path_fields(data), start=1):
                empty = ("<未設定: 実行時に入力>" if key in
                         ("malware_transfer.host_path", "malware_transfer.guest_path") else "<未設定>")
                table.add_row(str(index), key, value or empty)
            items.append(table)
            dynamic = data.get('dynamic_analysis', {}).get('llm_control', {})
            instruction = dynamic.get('prompt') if dynamic.get('prompt') is not None else dynamic.get('instruction_file', 'prompts/dynamic_default.md')
            items.append(Text('動的解析LLM: ' + ('ON' if dynamic.get('enabled', False) else 'OFF') +
                              ' / 指示: ' + (instruction or '<ONなら実行開始時に入力>')))
            items.append(Text("番号: パス編集  L: 動的LLM切替  P: 動的指示入力  J: 設定JSON変更  S: 保存  Q: 戻る"))
        if message:
            items.append(Panel(message, title="メッセージ"))
        return Group(*items)

    # JSON内のパス項目だけを選択・編集・保存できる画面を提供します。
    def edit_settings(self) -> None:
        data: dict[str, Any] | None = None
        message = ""
        while True:
            if data is None:
                try:
                    loaded = json.loads(self.settings_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    lines = self.draw_renderable(self.render_settings(None, str(error)))
                    self.screen.read_line(lines, "Enterで戻ります: ")
                    return
                if not isinstance(loaded, dict):
                    lines = self.draw_renderable(
                        self.render_settings(None, "設定JSONのルートはオブジェクトである必要があります。")
                    )
                    self.screen.read_line(lines, "Enterで戻ります: ")
                    return
                data = loaded

            lines = self.draw_renderable(self.render_settings(data, message))
            message = ""
            answer = self.screen.read_line(lines, "選択: ").strip().lower()
            if answer == "q":
                return
            if answer in ('l', 'p'):
                dynamic = data.setdefault('dynamic_analysis', {}).setdefault('llm_control', {})
                if answer == 'l':
                    dynamic['enabled'] = not dynamic.get('enabled', False)
                else:
                    dynamic['prompt'] = self.screen.read_line(lines, '動的解析の指示（空欄なら実行開始時に入力）: ')
                continue
            if answer == "s":
                self.settings_path.write_text(
                    json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                return
            if answer == "j":
                raw_path = self.screen.read_line(lines, "設定JSONの絶対パス: ")
                try:
                    candidate = normalize_absolute_path(raw_path)
                except ValueError as error:
                    message = str(error)
                    continue
                if candidate is None or not Path(candidate).is_file():
                    message = "存在するJSONファイルを指定してください。"
                    continue
                self.settings_path = Path(candidate).resolve()
                data = None
                continue

            fields = collect_path_fields(data)
            if not answer.isdigit() or not (1 <= int(answer) <= len(fields)):
                continue
            key, current = fields[int(answer) - 1]
            raw_value = self.screen.read_line(lines, f"{key} [{current or '未設定'}]: ")
            try:
                set_nested_value(data, key, normalize_absolute_path(raw_value))
            except ValueError as error:
                message = str(error)

    # 起動中は代替画面を維持し、どの終了経路でも元画面を復元します。
    def run(self) -> int:
        self.screen.enter()
        try:
            while True:
                selection = self.show_menu()
                if selection == "実行":
                    self.execute()
                elif selection == "設定":
                    self.edit_settings()
                elif selection == "更新":
                    # 本体の終了を親ランチャーが待ってから更新し、使用中のexeを交換しない。
                    return 42
                elif selection == "ヘルプ":
                    # EXE同梱のMarkdownを読み、長い説明もスクロールして確認できるようにする。
                    help_path = Path(__file__).resolve().parent / 'md/technical/tui_help.md'
                    try:
                        content = Markdown(help_path.read_text(encoding='utf-8'))
                    except OSError as error:
                        content = Text('ヘルプを読み込めません: ' + str(error))
                    lines = render_to_lines(content, self.screen.get_size().width, 1000)
                    self.wait_for_menu_return(lines)
                else:
                    return 0
        except (KeyboardInterrupt, EOFError):
            return 0
        finally:
            self.screen.leave()


# r_AKanalyの通常起動からTUIアプリケーションを開始します。
def launch_tui(
    run_engine: Callable[[list[str] | None], int],
    settings_path: Path,
) -> int:
    return TuiApplication(run_engine, settings_path).run()
