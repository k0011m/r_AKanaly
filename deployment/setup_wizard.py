"""本番セットアップの入力画面・入力検証を管理する。"""
import os
import ctypes
from pathlib import Path, PureWindowsPath
import shutil
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, font

ROOT = Path(__file__).resolve().parents[1]
HOST_TOOLS = {
    "VMware Workstation": ("vmware.exe", r"C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe"),
    "vmrun": ("vmrun.exe", r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"),
    "Procmon (Host conversion)": ("Procmon64.exe", str(ROOT / "tools_runtime/ProcessMonitor/Procmon64.exe")),
}
GUEST_TOOLS = {
    "VMware Tools": r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
    "Python (OS Agent)": r"C:\ProgramData\r_AKanaly\runtime\python\python.exe",
    "Python (Ghidra / PyGhidra)": r"C:\ProgramData\r_AKanaly\runtime\ghidra-python\python.exe",
    "Java JDK": r"C:\ProgramData\r_AKanaly\runtime\jdk\bin\java.exe",
    "Ghidra": r"C:\ProgramData\r_AKanaly\tools\ghidra\ghidraRun.bat",
    "Sysmon": r"C:\ProgramData\r_AKanaly\tools\sysmon\Sysmon64.exe",
    "Procmon": r"C:\ProgramData\r_AKanaly\tools\procmon\Procmon64.exe",
    "Detect It Easy": r"C:\ProgramData\r_AKanaly\tools\die\diec.exe",
    "FLOSS": r"C:\ProgramData\r_AKanaly\tools\floss\floss.exe",
    "capa": r"C:\ProgramData\r_AKanaly\tools\capa\capa.exe",
    "ILSpy CLI": r"C:\ProgramData\r_AKanaly\tools\ilspy\ilspycmd.exe",
    "YARA": r"C:\ProgramData\r_AKanaly\tools\yara\yara64.exe",
}
FIELDS = {
    "vmx_path": ("対象VM (.vmx)", "Target VM (.vmx)"),
    "vm_mode": ("VMの扱い (copy / existing)", "VM mode (copy / existing)"),
    "clone_path": ("複製先 (copyの場合)", "Clone destination (copy mode)"),
    "base_snapshot": ("基点スナップショット（空欄＝現在）", "Base snapshot (blank = current)"),
    "guest_username": ("Guestユーザー名", "Guest username"),
    "guest_password": ("Guestパスワード", "Guest password"),
    "vm_encryption_password": ("VM暗号化パスワード（必要な場合）", "VM encryption password (if required)"),
}

# 既存ツールは起動せず、標準候補とPATHだけを読み取る。
def detect_host():
    result = {}
    for name, (exe, default) in HOST_TOOLS.items():
        candidates = [default, shutil.which(exe)]
        if name in ("VMware Workstation", "vmrun"):
            candidates += [str(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "VMware/VMware Workstation" / exe)]
        found = next((p for p in candidates if p and Path(p).is_file()), None)
        result[name] = (bool(found), found or default)
    return result

class SetupWizard(tk.Tk):
    # 入力値を保持し、本番セットアップ用のウィンドウを作る。
    def __init__(self):
        # Tkウィンドウ生成前に専用IDを登録し、Pythonのタスクバーグループと分離する。
        if sys.platform == "win32":
            set_app_id = ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID
            set_app_id.argtypes = [ctypes.c_wchar_p]
            set_app_id.restype = ctypes.c_long
            result = set_app_id("r_AKanaly.Setup")
            if result < 0:
                raise OSError(f"AppUserModelID registration failed: {result}")
        super().__init__()
        self.title("r_AKanaly Setup")
        self.geometry("1320x900")
        self.minsize(1000, 680)
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont"):
            font.nametofont(name).configure(family="Yu Gothic UI", size=12)
        style = ttk.Style(self)
        style.configure("TButton", padding=(14, 8))
        style.configure("TEntry", padding=7)
        self.app_icon = tk.PhotoImage(file=str(ROOT / "deployment/assets/icon.png"))
        self.iconphoto(True, self.app_icon)
        self.lang = tk.StringVar(value="日本語")
        self.page = 0
        self.install_dir = tk.StringVar(value=str(Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Programs/r_AKanaly"))
        self.output_dir = tk.StringVar(value=str(Path.home() / "Documents/r_AKanaly_results"))
        self.env = {key: tk.StringVar(value="existing" if key == "vm_mode" else "") for key in FIELDS}
        self.host = {k: (tk.BooleanVar(value=v[0]), tk.StringVar(value=v[1])) for k, v in detect_host().items()}
        self.guest = {k: (tk.BooleanVar(value=False), tk.StringVar(value=v)) for k, v in GUEST_TOOLS.items()}
        self.status = {}
        self.render()

    # 選択言語に応じて画面文言を切り替える。
    def tr(self, ja, en):
        return ja if self.lang.get() == "日本語" else en

    # ページ内容を再構築しても入力値は維持する。
    def render(self):
        for widget in self.winfo_children():
            widget.destroy()
        ttk.Label(self, text=self.tr("環境セットアップ：手動方式では作業用クローンを構築します。最終確認後に開始します。", "Environment setup: manual mode provisions a working clone. Setup starts after final confirmation."), foreground="#a04400").pack(pady=12)
        names = [self.tr(a, b) for a, b in [("言語", "Language"), ("保存先", "Locations"), ("Hostツール", "Host tools"), ("個別環境情報", "Environment"), ("Guestツール", "Guest tools"), ("変更内容の確認", "Review"), ("構築状況", "Setup status")]]
        ttk.Label(self, text=f"{self.page + 1}/7   {names[self.page]}", font=("Yu Gothic UI", 21, "bold")).pack(anchor="w", padx=24)
        content = ttk.Frame(self)
        content.pack(fill="both", expand=True)
        canvas = tk.Canvas(content, highlightthickness=0)
        scroll = ttk.Scrollbar(content, orient="vertical", command=canvas.yview)
        scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.configure(yscrollcommand=scroll.set)
        self.body = ttk.Frame(canvas, padding=24)
        body_id = canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", lambda event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(body_id, width=event.width))
        nav = ttk.Frame(self, padding=16)
        nav.pack(fill="x")
        ttk.Button(nav, text=self.tr("戻る", "Back"), state="normal" if self.page else "disabled", command=self.back).pack(side="left")
        ttk.Button(nav, text=self.tr("閉じる", "Close"), command=self.destroy).pack(side="right")
        if self.page < 6:
            ttk.Button(nav, text=self.tr("次へ", "Next"), command=self.next_page).pack(side="right", padx=12)
        if self.page == 0:
            ttk.Label(self.body, text="表示言語 / Display language").pack(anchor="w")
            for lang in ("日本語", "English"):
                ttk.Radiobutton(self.body, text=lang, value=lang, variable=self.lang, command=self.render).pack(anchor="w", pady=10)
        elif self.page == 1:
            self.entry_row(self.tr("本体保存先", "Application location"), self.install_dir, directory=True)
            self.entry_row(self.tr("レポート・ログ保存先", "Reports and logs location"), self.output_dir, directory=True)
        elif self.page == 2:
            self.tool_table(self.host, guest=False)
            ttk.Button(self.body, text=self.tr("再検出", "Detect again"), command=self.redetect).pack(anchor="w", pady=12)
            ttk.Label(self.body, text=self.tr("既存ファイルの存在のみ検査します。版・互換性は未検証。Codexランタイムは製品に同梱します。", "Checks file existence only, not version compatibility. Codex runtime is bundled.")).pack(anchor="w")
        elif self.page == 3:
            ttk.Label(self.body, text=self.tr("環境情報を入力してください。パスは参照ボタンから選択できます。", "Enter environment information. Use Browse to select paths.")).pack(anchor="w", pady=10)
            for key, labels in FIELDS.items():
                self.entry_row(self.tr(*labels), self.env[key], secret="password" in key,
                               directory=key == "clone_path", file=key == "vmx_path")
        elif self.page == 4:
            self.tool_table(self.guest, guest=True)
        else:
            text = tk.Text(self.body, wrap="word", font=("Yu Gothic UI", 13), height=22)
            text.pack(fill="both", expand=True)
            text.insert("1.0", self.review() if self.page == 5 else self.tr("構築処理の開始を待っています。", "Waiting for setup."))
            text.configure(state="disabled")

    # パス欄と秘密欄を共通化し、秘密値を確認画面へ流さない。
    def entry_row(self, label, var, directory=False, secret=False, file=False):
        row = ttk.Frame(self.body)
        row.pack(fill="x", pady=12)
        ttk.Label(row, text=label, width=39).pack(side="left")
        ttk.Entry(row, textvariable=var, show="*" if secret else "").pack(side="left", fill="x", expand=True)
        if directory or file:
            ttk.Button(row, text=self.tr("参照", "Browse"), command=lambda: self.browse(var, directory, vmx=file)).pack(side="right", padx=(8, 0))

    # Hostのみファイル選択を許可し、Guestパスの誤選択を避ける。
    def tool_table(self, tools, guest):
        table = ttk.Frame(self.body)
        table.pack(fill="x")
        table.columnconfigure(1, weight=1)
        self.status = {}
        for i, (name, (checked, path)) in enumerate(tools.items()):
            ttk.Checkbutton(table, text=name, variable=checked, width=29).grid(row=i, column=0, sticky="w", pady=5)
            ttk.Entry(table, textvariable=path).grid(row=i, column=1, sticky="ew", padx=6)
            if not guest:
                ttk.Button(table, text=self.tr("参照", "Browse"), command=lambda p=path: self.browse(p)).grid(row=i, column=2)
            else:
                ttk.Button(table, text=self.tr("Guest参照", "Browse Guest"), command=lambda p=path: self.guest_browse(p)).grid(row=i, column=2)
            status = self.tr("状態未確認", "Unchecked") if guest else self.tr("ファイル検出済み" if Path(path.get()).is_file() else "候補・未確認", "File found" if Path(path.get()).is_file() else "Candidate / unchecked")
            self.status[name] = ttk.Label(table, text=status, width=23)
            self.status[name].grid(row=i, column=3, padx=6)

    # 現在のパスに近い実在フォルダから、用途に応じたWindows選択画面を開く。
    def browse(self, var, directory=False, vmx=False):
        current = Path(var.get()) if var.get().strip() else Path.home()
        initial = current if current.is_dir() else current.parent
        while not initial.is_dir() and initial != initial.parent:
            initial = initial.parent
        options = {"parent": self, "initialdir": str(initial)}
        if directory:
            selected = filedialog.askdirectory(**options, mustexist=False)
        else:
            filters = [("VMware VM", "*.vmx")] if vmx else [("Applications", "*.exe *.bat *.cmd"), ("All files", "*.*")]
            selected = filedialog.askopenfilename(**options, filetypes=filters)
        if selected:
            var.set(str(Path(selected)))

    # 再検出はHostの読取りだけを行う。
    def redetect(self):
        for key, (checked, path) in detect_host().items():
            self.host[key][0].set(checked)
            self.host[key][1].set(path)
        self.render()

    # 各画面の入力検証後に進み、構築の実行は派生クラスへ任せる。
    def next_page(self):
        errors = []
        if self.page == 1:
            for value in (self.install_dir.get(), self.output_dir.get()):
                if not PureWindowsPath(value).is_absolute():
                    errors.append(self.tr("保存先はWindowsの絶対パスで指定してください。", "Use absolute Windows paths for locations."))
        if self.page == 2 and not self.check_tools(self.host):
            return
        if self.page == 3:
            if not self.env["vmx_path"].get().lower().endswith(".vmx") or not PureWindowsPath(self.env["vmx_path"].get()).is_absolute():
                errors.append(self.tr("VMは絶対パスの.vmxを指定してください。", "Use an absolute .vmx path."))
            for key in ("guest_username", "guest_password"):
                if not self.env[key].get().strip():
                    errors.append(self.tr(*FIELDS[key]) + self.tr("：未入力", ": missing"))
            mode = self.env["vm_mode"].get()
            if mode not in ("copy", "existing"):
                errors.append("vm_mode: copy / existing")
            if mode == "copy" and not PureWindowsPath(self.env["clone_path"].get()).is_absolute():
                errors.append(self.tr("複製先に絶対パスが必要です。", "Clone destination must be absolute."))
        if self.page == 4 and not self.check_tools(self.guest, True):
            return
        if errors:
            messagebox.showerror(self.tr("入力を確認", "Check input"), "\n".join(errors), parent=self)
            return
        self.page += 1
        self.render()

    # 前画面へ戻っても既存の入力は失わない。
    def back(self):
        self.page = max(0, self.page - 1)
        self.render()

    # 認証情報は設定の有無だけを示し、平文を確認画面に表示しない。
    def review(self):
        lines = [self.tr("以下の設定を確認してください。次へ進むと最終確認後に構築を開始します。", "Review these settings. Next asks for confirmation before applying them."), "", self.install_dir.get(), self.output_dir.get(), ""]
        for key, var in self.env.items():
            value = self.tr("入力済み", "Provided") if "password" in key and var.get() else var.get()
            lines.append(f"{self.tr(*FIELDS[key])}: {value}")
        for scope, rows in (("Host", self.host), ("Guest", self.guest)):
            lines += ["", scope]
            for name, (checked, path) in rows.items():
                lines.append(f"{name}: " + (self.tr("既存利用候補", "Reuse candidate") if checked.get() else self.tr("新規導入予定", "Planned install")) + f" — {path.get()}")
        return "\n".join(lines)
