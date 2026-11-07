"""成功イベントからHook案内・終了制御までを実Tkで確認する。"""
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from tkinter import ttk

from deployment.setup_gui import Setup


class SetupCompletionTests(unittest.TestCase):
    # VMへ接続せず、実際の完了イベントをGUIに渡す。
    def test_success_acknowledgement_in_both_languages(self):
        for language in ('日本語', 'English'):
            with self.subTest(language=language):
                app = Setup()
                app.withdraw()
                try:
                    app.lang.set(language)
                    app.page = 6
                    app.render()
                    app.setup_engine = SimpleNamespace(root=Path('C:/Example Install'))
                    app.events.put(('complete', None))
                    app.poll()
                    self.assertTrue(app.setup_completed)
                    self.assertEqual(app.hook_project_path.get(), str(Path('C:/Example Install/config/analysis_project')))
                    self.assertTrue(app.close_button.instate(['disabled']))
                    self.assertTrue(app.back_button.instate(['disabled']))
                    labels = '\n'.join(str(w.cget('text')) for w in app.body.winfo_children() if isinstance(w, ttk.Label))
                    for name in ('SessionStart', 'PreToolUse', 'PermissionRequest'):
                        self.assertIn(name, labels)
                    with patch('deployment.setup_gui.messagebox.showinfo') as notice:
                        app.close_setup()
                        app.destroy()
                        self.assertEqual(notice.call_count, 2)
                        self.assertTrue(app.winfo_exists())
                    checkbox = next(w for w in app.body.winfo_children() if isinstance(w, ttk.Checkbutton))
                    checkbox.invoke()
                    self.assertFalse(app.close_button.instate(['disabled']))
                    checkbox.invoke()
                    self.assertTrue(app.close_button.instate(['disabled']))
                    checkbox.invoke()
                    app.close_setup()
                finally:
                    # 失敗した検証でもTkを残さず、次の言語の検証へ進む。
                    app.busy = False
                    app.setup_completed = False
                    try:
                        if app.winfo_exists():
                            app.destroy()
                    except Exception:
                        pass


if __name__ == '__main__':
    unittest.main()
