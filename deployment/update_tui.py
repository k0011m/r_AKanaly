"""更新専用の画面表示とキーボード確認を提供する。"""
import sys
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from terminal_screen import enable_windows_virtual_terminal, read_console_navigation_event


class UpdateScreen:
    # 本体の依存を読み込まず、更新画面だけを独立して表示する。
    def __init__(self):
        self.console = Console()
        self.live = None
        self.message = ''

    # 更新処理中だけ代替画面を使い、本体へ戻る際に復元する。
    def __enter__(self):
        enable_windows_virtual_terminal()
        self.live = Live(console=self.console, screen=True, auto_refresh=True)
        self.live.start()
        self.status('更新を確認しています…')
        return self

    # 例外やキャンセルでもカーソルと元の画面を復元する。
    def __exit__(self, *args):
        self.live.stop()

    # 状態と選択肢を同じ枠組みで表示し、エラー文字列をマークアップ扱いしない。
    def draw(self, options=None, selected=0, footer='しばらくお待ちください'):
        items = [Panel(Text('r_AKanaly  /  UPDATE', style='bold cyan'), border_style='cyan'),
                 Panel(Text(self.message), title='更新状況', border_style='cyan')]
        if options:
            choices = Text()
            for index, option in enumerate(options):
                choices.append(('▶ ' if index == selected else '  ') + option + '\n',
                               style='bold cyan' if index == selected else '')
            items.append(Panel(choices, title='選択'))
        items.append(Text(footer, style='dim'))
        self.live.update(Group(*items), refresh=True)

    # 取得・検証・適用の段階を画面に反映する。
    def status(self, message):
        self.message = str(message)
        self.draw()

    # 明示的に更新を選択した場合だけダウンロードへ進める。
    def confirm(self, current, target):
        self.message = f'現在のバージョン：{current}\n更新バージョン：{target}\n更新しますか？'
        selected = 1
        while True:
            self.draw(('更新する', '更新しない'), selected, '↑/↓：選択　Enter：決定　Ctrl+C：取消')
            key = read_console_navigation_event()
            if key in ('up', 'down'):
                selected = 1 - selected
            elif key == 'enter':
                return selected == 0

    # 成功・取消・エラーを確認してから本体へ戻す。
    def finish(self):
        self.draw(('本体へ戻る',), 0, 'Enter：本体へ戻る')
        while read_console_navigation_event() != 'enter':
            pass


# 対話端末だけ画面制御を使い、リダイレクト時は従来の文字出力を維持する。
def interactive():
    return sys.stdin.isatty() and sys.stdout.isatty()
