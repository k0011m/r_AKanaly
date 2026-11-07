"""本番の入力画面と実構築エンジンをつなぐGUI。"""
import json
from pathlib import Path, PureWindowsPath
import queue
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from .setup_wizard import SetupWizard, ROOT
from .launcher import install_release, install_root
from .setup_engine import SetupEngine
from .storage import atomic_json, installation_lock
from .vm import VMware, quote

class Setup(SetupWizard):
    # GUIスレッドだけでウィジェットを更新し、通信はワーカーへ分離する。
    def __init__(self):
        self.events = queue.Queue()
        self.busy = False
        self.package = None
        self.installed_manifest = None
        self.activity_tick = 0
        self.activity_state = 'idle'
        self.completed_phases = 0
        self.setup_completed = False
        super().__init__()
        self.hook_notice_acknowledged = tk.BooleanVar(master=self, value=False)
        self.registry_profile=tk.StringVar(value='manual_registry')
        # ILSpyはdotnet+DLL構成で配布するため、単独exe指定は受け付けない。
        for name in ('ILSpy CLI', 'YARA'):
            self.guest.pop(name, None)
        if getattr(sys, 'frozen', False):
            candidate = Path(sys.executable).parent / 'tools_runtime/ProcessMonitor/Procmon64.exe'
            self.host['Procmon (Host conversion)'][0].set(candidate.is_file())
            self.host['Procmon (Host conversion)'][1].set(str(candidate))
        self.install_dir.set(str(install_root()) if (install_root()/'current.json').exists() else self.install_dir.get())
        self.title('r_AKanaly Setup')
        self.protocol('WM_DELETE_WINDOW', self.close_setup)
        self.after(100, self.poll)

    # 試作の模擬確認を使わず、既存パスと同梱導入を区別する。
    def check_tools(self, tools, guest=False):
        invalid = [name for name, (checked, path) in tools.items()
                   if checked.get() and not (PureWindowsPath(path.get()).is_absolute() if guest else Path(path.get()).is_file())]
        if invalid:
            messagebox.showerror('Setup', self.tr('既存ツールのパスを修正してください：', 'Correct existing tool paths: ') + ', '.join(invalid), parent=self)
            return False
        if guest and not tools['VMware Tools'][0].get():
            messagebox.showerror('Setup', self.tr('VMware ToolsはGuestへ事前導入してください。', 'Install VMware Tools in the Guest first.'), parent=self)
            return False
        missing = [name for name, (checked, _) in tools.items() if not checked.get()]
        return not missing or messagebox.askyesno('Setup', self.tr('次のツールを配置します。解析ツールは公式配布元から取得・照合し、Pythonなどの実行ライブラリは同梱資材を使います。続行しますか？\n', 'Deploy these tools? Analysis tools are downloaded and verified from official sources; runtime libraries such as Python use bundled assets.\n') + '\n'.join(missing), parent=self)

    # 本番では模擬検出を表示せず、接続後の実在パスだけを扱う。
    def render(self):
        super().render()
        banner = self.winfo_children()[0]
        banner.configure(text=self.tr('環境セットアップ：最終確認後にHostと選択VMを変更します。', 'Environment setup: Host and selected VM are modified after final confirmation.'))
        if self.page == 1:
            ttk.Button(self.body, text=self.tr('署名済み配布フォルダを選択', 'Select signed release folder'), command=self.choose_package).pack(anchor='w', pady=14)
            ttk.Label(self.body, text=str(self.package or self.tr('Setup.exeと同じ場所のreleaseフォルダを既定利用', 'Default: release folder beside Setup.exe')), wraplength=1000).pack(anchor='w')
        if self.page == 2:
            for widget in self.body.winfo_children():
                if isinstance(widget, ttk.Label):
                    widget.configure(text=self.tr('VMwareは事前導入が必要です。解析ツールは各公式配布元から取得・照合します。Procmon・Sysmonは利用規約への同意が必要です。', 'Install VMware first. Analysis tools are downloaded and verified from their official sources. Procmon and Sysmon require license acceptance.'))
        if self.page == 3:
            ttk.Label(self.body,text=self.tr('Guest保護の設定方式（各方式で解析前に実状態を確認します）','Guest protection setup (each verifies effective state before analysis)')).pack(anchor='w',pady=8)
            self.protection_choice=ttk.Combobox(self.body,state='readonly',values=(self.tr('手動レジストリ設定（推奨）','Manual registry setup (recommended)'),self.tr('起動後に公式APIで設定・確認','Apply and verify through official APIs after startup'),self.tr('Windows Pro：手動グループポリシー設定（推奨）','Windows Pro: manual Group Policy (recommended)')),width=65)
            self.protection_choice.current(('manual_registry','official_api','group_policy').index(self.registry_profile.get()))
            self.protection_choice.pack(anchor='w')
            self.protection_choice.bind('<<ComboboxSelected>>',self.change_protection_choice)
            self.manual_baseline_panel=ttk.Frame(self.body)
            self.manual_instruction_label=ttk.Label(self.manual_baseline_panel,wraplength=1000)
            self.manual_instruction_label.pack(anchor='w',pady=10)
            ttk.Label(self.manual_baseline_panel,text=self.tr('設定済み起点スナップショット（必須）','Prepared baseline snapshot (required)')).pack(anchor='w')
            self.baseline_choice=ttk.Combobox(self.manual_baseline_panel,textvariable=self.env['base_snapshot'],width=65)
            self.baseline_choice.pack(anchor='w',pady=6)
            ttk.Button(self.manual_baseline_panel,text=self.tr('スナップショット一覧を更新','Refresh snapshot list'),command=self.refresh_baselines).pack(anchor='w')
            self.automatic_baseline_panel=ttk.Frame(self.body)
            ttk.Label(self.automatic_baseline_panel,text=self.tr('起点スナップショット（空欄＝現在）','Base snapshot (blank = current)')).pack(anchor='w')
            ttk.Entry(self.automatic_baseline_panel,textvariable=self.env['base_snapshot'],width=65).pack(anchor='w')
            self.change_protection_choice()
        if self.page == 4:
            for widget in self.body.winfo_children():
                widget.destroy()
            manual = self.registry_profile.get() in ('manual_registry','group_policy')
            ttk.Label(self.body, text=self.tr('手動方式では元VMを起動して調査しません。既存ツールを再利用する場合だけ指定してください。配置時にSetup用の枝で検証します。' if manual else 'Guestで検出した結果です。Pythonの専用環境は依存関係も検証します。', 'Manual mode does not start the original VM for inspection. Specify existing tools only if you want to reuse them; they are verified in the Setup branch during provisioning.' if manual else 'Actual Guest inventory. Private Python dependencies are verified during setup.'), wraplength=1000).pack(anchor='w')
            self.tool_table(self.guest, guest=True)
            for name, status in self.status.items():
                status.configure(text=self.tr('利用者指定・配置時に検証' if manual else ('Guest検出済み' if self.guest[name][0].get() else '未検出'), 'User specified; verified during provisioning' if manual else ('Detected in Guest' if self.guest[name][0].get() else 'Not found')))
        if self.page == 5:
            text = self.body.winfo_children()[0]
            text.configure(state='normal')
            text.delete('1.0','2.0')
            text.insert('1.0',self.tr('次へ：実際の構築を開始。Guest自動ログイン・自動スリープ/休止の無効化・Host指示によるGuest保護設定・実状態確認・隔離LAN・保存点作成を含みます。\n', 'Next starts real setup, including Guest autologin, disabling automatic sleep/hibernate, Host-requested Guest protection configuration and verification, isolated LAN and snapshots.\n'))
            text.insert('2.0',self.tr('選択したGuest保護方式：','Selected Guest protection mode: ')+self.registry_profile.get()+'\n')
            text.configure(state='disabled')
        if self.page == 6:
            status = ttk.Frame(self.body)
            status.pack(fill='x', before=self.body.winfo_children()[0], pady=8)
            self.activity_label = ttk.Label(status, text=self.tr('開始待ち', 'Waiting to start'))
            self.activity_label.pack(anchor='w')
            self.phase_progress = ttk.Progressbar(status, maximum=6, mode='determinate')
            self.phase_progress.pack(fill='x', pady=4)
            self.activity_progress = ttk.Progressbar(status, mode='indeterminate')
            self.activity_progress.pack(fill='x')
            self.log = next(widget for widget in self.body.winfo_children() if isinstance(widget, tk.Text))
            self.log.configure(state='normal')
            self.log.delete('1.0','end')
            self.log.insert('end',self.tr('セットアップの進捗\n','Setup progress\n'))
            self.log.configure(state='disabled')
            ttk.Button(self.body,text=self.tr('Guestの画面を開く（UAC確認）','Open Guest console (UAC)'),command=self.open_console).pack(anchor='w',pady=8)

    # 基点欄は方式選択の直下へまとめ、重複した自由入力欄を表示しない。
    def entry_row(self,label,var,**kwargs):
        if self.page==3 and any(var is self.env[key] for key in ('base_snapshot', 'vm_mode', 'clone_path')):
            return
        super().entry_row(label,var,**kwargs)

    # 次へを待たず、プルダウン選択イベントで手動設定の説明と基点欄を切り替える。
    def change_protection_choice(self,event=None):
        profile=('manual_registry','official_api','group_policy')[self.protection_choice.current()]
        manual=profile!='official_api'
        self.registry_profile.set(profile)
        self.manual_instruction_label.configure(text=self.manual_protection_instructions()+self.tr('\n\n再起動後の状態を確認し、Guestをシャットダウンして保存点を作成し、下で選択してください。指定保存点へ復元し、同じVM内にSetup専用の新しい枝を作成します。VMは複製しません。既存保存点は削除・上書きしません。保存点に含まれない現在の作業状態は復元時に失われます。必要な作業は先に保存してください。','\n\nVerify the state after reboot, shut down the Guest, create a snapshot and select it below. Setup restores that snapshot and creates a new Setup branch in the same VM. No VM copy is created. Existing snapshots are never deleted or overwritten. Current work not saved in a snapshot is lost on restore; save any needed work first.'))
        self.manual_baseline_panel.pack_forget()
        self.automatic_baseline_panel.pack_forget()
        (self.manual_baseline_panel if manual else self.automatic_baseline_panel).pack(fill='x',pady=10)

    # VMを起動・復元せず、入力されたVMの保存点名だけをワーカーで取得する。
    def refresh_baselines(self):
        if self.busy:return
        plan,secret=self.inputs()
        if not Path(plan['vmx']).is_file():
            messagebox.showerror('Setup',self.tr('先にVMXファイルを選択してください。','Select the VMX file first.'),parent=self)
            return
        vm=VMware(plan['vmrun'],plan['vmx'],plan['username'],secret['guest_password'],secret['vm_password'])
        self.work(lambda:(plan['vmx'],vm.snapshots()),'snapshots')

    # Guest承認が必要な場合だけユーザー操作でVMwareコンソールを表示する。
    def open_console(self):
        vmx=self.env['vmx_path'].get()
        if self.registry_profile.get() in ('manual_registry','group_policy'):
            engine = getattr(self, 'setup_engine', None)
            state = getattr(engine, 'state', {}) if engine else {}
            vmx = state.get('vmx', '')
            if not state.get('owned_setup_branch') or not vmx or Path(vmx).resolve() != Path(self.env['vmx_path'].get()).resolve():
                messagebox.showinfo('Setup', self.tr('Setup用の枝の準備が完了していません。VMは開きません。', 'The Setup branch is not ready. The VM will not be opened.'), parent=self)
                return
        elif self.env['vm_mode'].get()=='copy':
            clone=Path(self.env['clone_path'].get())
            vmx=str(clone if clone.suffix.lower()=='.vmx' else clone/Path(vmx).name)
        # コンソール表示だけでは電源を入れず、構築中の停止・再起動と競合させない。
        subprocess.Popen([self.host['VMware Workstation'][1].get(),vmx])

    # パッケージ選択だけでは実配置しない。
    def choose_package(self):
        path=filedialog.askdirectory(parent=self)
        if path:
            self.package=Path(path)
            self.render()

    # 選択した構築内容だけを取り出し、資格情報は別オブジェクトへ分離する。
    def inputs(self):
        plan={'install_dir':self.install_dir.get(), 'output_dir':self.output_dir.get(), 'vmrun':self.host['vmrun'][1].get(),
              'vmx':self.env['vmx_path'].get(), 'username':self.env['guest_username'].get(), 'mode':'existing',
              'clone_path':'', 'base_snapshot':self.env['base_snapshot'].get(), 'registry_profile':self.registry_profile.get(),
              'guest_tools':{k:{'reuse':v[0].get(),'path':v[1].get()} for k,v in self.guest.items()}}
        plan['accept_sysinternals_license'] = getattr(self, 'accepted_sysinternals', False)
        plan['host_procmon'] = self.host['Procmon (Host conversion)'][1].get() if self.host['Procmon (Host conversion)'][0].get() else None
        secrets={'guest_password':self.env['guest_password'].get(), 'vm_password':self.env['vm_encryption_password'].get()}
        if plan['mode']=='copy' and Path(plan['clone_path']).suffix.lower()!='.vmx':
            plan['clone_path']=str(Path(plan['clone_path'])/Path(plan['vmx']).name)
        return plan,secrets

    # 本番の既存Hostツール未導入は、黙って導入済みとして進ませない。
    def next_page(self):
        if self.busy:
            return
        if self.page == 2:
            for name in ('VMware Workstation','vmrun'):
                if not self.host[name][0].get() or not Path(self.host[name][1].get()).is_file():
                    messagebox.showerror('VMware',self.tr('VMware/VMware Toolsは事前導入が必要です。正しいパスを指定してください。','Install VMware and VMware Tools first; select valid paths.'),parent=self)
                    return
            selected, path = self.host['Procmon (Host conversion)']
            if selected.get() and not Path(path.get()).is_file():
                messagebox.showerror('Setup', self.tr('Host Procmonのパスが存在しません。', 'Host Procmon path does not exist.'), parent=self)
                return
            self.page=3
            self.render()
            return
        if self.page == 3:
            if self.registry_profile.get() in ('manual_registry','group_policy') and not self.env['base_snapshot'].get().strip():
                messagebox.showerror('Setup',self.tr('設定済みの起点スナップショットを選択してください。','Select a prepared baseline snapshot.'),parent=self)
                return
            if not Path(self.env['vmx_path'].get()).is_file():
                messagebox.showerror('Setup', self.tr('指定したVMXファイルが存在しません。', 'Selected VMX file does not exist.'), parent=self)
                return
            super().next_page()
            if self.page != 4:
                return
            if self.registry_profile.get() in ('manual_registry','group_policy'):
                return
            plan,secret=self.inputs()
            paths={k:v[1].get() for k,v in self.guest.items()}
            self.work(lambda: self.inspect(plan,secret,paths),'inventory')
            return
        if self.page == 5:
            if not messagebox.askyesno('Sysinternals license', self.tr('Procmon・SysmonをMicrosoft公式サイトから取得して配置します。以下の利用規約に同意しますか？\nhttps://learn.microsoft.com/en-us/sysinternals/license-terms', 'Download and deploy Procmon and Sysmon from Microsoft. Do you accept these license terms?\nhttps://learn.microsoft.com/en-us/sysinternals/license-terms'), parent=self):
                return
            self.accepted_sysinternals = True
            if not messagebox.askyesno('r_AKanaly Setup',self.tr('表示した内容で実際に構築します。続行しますか？','Apply the displayed setup changes?'),parent=self):
                return
            plan,secret=self.inputs()
            package=self.package or ((Path(sys.executable).parent if getattr(sys,'frozen',False) else ROOT / 'dist/installer') / 'release')
            self.page=6
            self.render()
            self.work(lambda:self.apply_setup(plan,secret,package),'complete')
            return
        super().next_page()

    # 通信中に入力やページを変更して照合対象が食い違うことを防ぐ。
    def back(self):
        if not self.busy and not self.setup_completed:
            super().back()

    # Guestを調査するための起動は行うが、保存点の復元や設定変更はしない。
    def inspect(self,plan,secret,paths):
        if plan.get('registry_profile') in ('manual_registry','group_policy'):
            raise RuntimeError('Manual setup must not inspect the original Guest; tools are verified in the Setup branch')
        vm=VMware(plan['vmrun'],plan['vmx'],plan['username'],secret['guest_password'],secret['vm_password'])
        started=not vm.running()
        vm.boot()
        try:
            return vm.inventory(paths)
        finally:
            if started:
                vm.shutdown()

    # 配布物の信頼設定は配布側で固定し、ダウンロードした鍵を自動信用しない。
    def apply_setup(self,plan,secret,package):
        app_dir=Path(sys.executable).parent if getattr(sys,'frozen',False) else ROOT / 'dist/installer'
        trust=json.loads((app_dir/'release-trust.json').read_text(encoding='utf-8'))
        root=Path(plan['install_dir'])
        with installation_lock(root):
            pending=root/'pending-update.json'
            if pending.exists() and self.package is None:
                from . import releases
                from .storage import version
                pending_data=json.loads(pending.read_text())
                version(pending_data['version'])
                metadata=root/'releases'/pending_data['version']
                manifest=releases.verify_manifest((metadata/'release-manifest.json').read_bytes(),(metadata/'release-manifest.sig').read_bytes(),trust['public_key'])
                releases.verify_files(root/'versions'/manifest['version'],manifest)
            else:
                manifest=install_release(root,package,trust['public_key'])
            for name in ('r_AKanaly.exe','Setup.exe','release-trust.json'):
                source=app_dir/name
                if source.resolve() != (root/name).resolve():
                    shutil.copy2(source,root/name)
            atomic_json(root/'update.json',dict(trust,check_on_start=False))
        self.setup_engine = SetupEngine(plan,secret,manifest,report=lambda msg:self.events.put(('log',msg)),request_action=self.wait_for_manual_setup)
        self.setup_engine.apply()

    # ワーカーを待機させ、Tk操作とユーザーの回答はGUIスレッドへ渡す。
    def wait_for_manual_setup(self, details):
        answer=queue.Queue()
        self.events.put(('manual_action',(details,answer)))
        return answer.get()

    # 初期選択と復旧案内で、手動編集の場所・対象を同じ説明に統一する。
    def manual_registry_instructions(self):
        preparation = self.tr(
            '【先に解析専用Guestの改ざん防止を確認してください】\nGuestのWindows セキュリティ→ウイルスと脅威の防止→設定の管理で、改ざん防止をOFFにしてから、以下の設定を行ってください。Hostでは操作しないでください。Setupは改ざん防止を自動操作しません。OFFにしてもWindowsの構成によっては値が適用されません。DWORD→QWORD→DWORDの切替は不要です。\n\n',
            '[First check Tamper Protection in the analysis Guest]\nIn the Guest, open Windows Security > Virus & threat protection > Manage settings and turn Tamper Protection OFF before the steps below. Do not do this on the Host. Setup does not toggle Tamper Protection automatically. Depending on Windows configuration, the value may still not take effect. Do not cycle DWORD > QWORD > DWORD.\n\n')
        return preparation + self.tr(
            '【変更するのはPolicies側のDisableAntiSpywareだけです】\n対象Guest内でWin+Rを押し、regeditと入力して起動してください。上部のアドレス欄に次のパスを貼り付け、Enterを押してください。\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\n右側の一覧でDisableAntiSpywareを開き、値のデータを1にしてください。存在しない場合は右側の空白部分を右クリック→新規→DWORD（32ビット）値で作成し、名前をDisableAntiSpyware、値を1にしてください。\nPoliciesを含まない同名の場所は変更しないでください。DisableAntiVirusや他の値・キー・アクセス許可は作成・変更・削除しないでください。Host側でも操作しないでください。対象キーが見つからない場合は別の場所を代用せず、パスを確認してください。',
            '[Change only DisableAntiSpyware under Policies]\nInside the selected Guest, press Win+R, enter regedit, and open Registry Editor. Paste this path into its top address bar and press Enter:\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\nOpen DisableAntiSpyware in the right pane and set Value data to 1. If it is absent, right-click an empty area in the right pane, choose New > DWORD (32-bit) Value, name it DisableAntiSpyware, and set it to 1.\nDo not edit the similarly named location without Policies. Do not create, change, or delete DisableAntiVirus, other values or keys, or permissions. Do not perform these steps on the Host. If the target key is missing, check the path instead of substituting another location.')

    # 選択中の手動方式に対応する案内だけを表示し、レジストリ操作を混在させない。
    def manual_protection_instructions(self):
        if self.registry_profile.get()!='group_policy':
            return self.manual_registry_instructions()
        return self.tr(
            '【Windows Pro・手動グループポリシー方式（推奨）】\n解析専用Guestで操作してください。Hostでは操作しないでください。\n1. Windows セキュリティ → ウイルスと脅威の防止 → 設定の管理で「改ざん防止」をOFFにしてください。\n2. Win+Rで gpedit.msc を開いてください。\n3. コンピューターの構成 → 管理用テンプレート → Windows コンポーネント → Microsoft Defender ウイルス対策 → リアルタイム保護を開いてください。\n4. 「リアルタイム保護を無効にする」を「有効」、「動作の監視を有効にする」を「無効」、「ダウンロードしたすべてのファイルと添付ファイルをスキャンする」を「無効」にしてください。\n5. Windowsを再起動してください。Setupはリアルタイム保護・動作監視・IOAV・改ざん防止の4項目を読み取り確認します。ONや取得不能は成功にしません。\nこの方式ではDisableAntiSpywareの編集は不要です。Dev Driveの保護は必須判定に含めません。Setupはポリシーや改ざん防止を自動変更しません。',
            '[Windows Pro: manual Group Policy (recommended)]\nUse only the dedicated analysis Guest, not the Host.\n1. In Windows Security > Virus & threat protection > Manage settings, turn Tamper Protection OFF.\n2. Press Win+R and open gpedit.msc.\n3. Open Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection.\n4. Set Turn off real-time protection to Enabled; Turn on behavior monitoring to Disabled; Scan all downloaded files and attachments to Disabled.\n5. Restart Windows. Setup reads four effective states: real-time protection, behavior monitoring, IOAV and Tamper Protection. ON or unavailable does not pass.\nThis mode does not require editing DisableAntiSpyware. Dev Drive protection is not a required check. Setup does not change these policies or Tamper Protection automatically.')

    # 失敗時の観測値と操作対象を分け、値が1でも実状態の検証失敗であることを伝える。
    def manual_recovery_prompt(self, details):
        diagnostic = details.get('diagnostic') or {}
        security = diagnostic.get('security') or {}
        state = security.get('after') or {}
        lines = [self.tr('直近の失敗時の観測値（現在の画面とは異なる場合があります）：',
                         'Observed at the latest failure (may differ from the current screen):')]
        for entry in security.get('registry_checks') or []:
            lines.append(str(entry.get('path', '?')) + ': ' + str(entry.get('kind')) + ' / ' + str(entry.get('value'))
                         + ' / read_success=' + str(entry.get('read_success')))
        for key in ('AMRunningMode', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'IsTamperProtected'):
            lines.append(key + ': ' + (str(state[key]) if key in state else self.tr('未取得', 'Unavailable')))
        reason = security.get('error') or diagnostic.get('message') or self.tr('旧進捗に詳細記録がありません', 'No diagnostic detail in legacy progress')
        lines.append(self.tr('失敗理由：', 'Failure reason: ') + str(reason))
        return self.tr(
            '保護の実状態がON・取得不能の場合は検証に失敗します。以下の観測値を確認してください。\n\n',
            'Verification fails if effective protection is ON or unavailable. Check the observations below.\n\n') + '\n'.join(lines) + self.tr(
            '\n\n【操作するのはSetup用の枝を選択したVMです】\n元VM・元保存点を移動・削除・上書きする操作は不要です。設定を確認・修正してWindowsを再起動し、状態確認後にGuestをシャットダウンしてください。\n「はい」：SetupがこのVMを起動して読取り検証し、成功したら正常停止して別名の新しい保存点を作り、以降の構築先をその保存点へ切り替えます。元の保存点は保持します。\n「いいえ」：作業中のGuest状態を保持して中断します。\n\nSetup用の枝を選択したVM：',
            '\n\n[Work only in the Setup branch of the selected VM]\nDo not move, delete, or overwrite the original VM or snapshots. Check/correct the settings, restart Windows, verify the state, then shut down the Guest.\nYes: Setup boots this VM for read-only verification; on success it shuts down normally, creates a new snapshot with a different name, and uses it for subsequent provisioning. Existing snapshots are preserved.\nNo: Pause while preserving the current Guest state.\n\nVM containing the Setup branch: ') + details['vmx'] + self.tr(
            '\nSetup用の復元元保存点（保持）：', '\nRestore point within the Setup branch (preserved): ') + details['source_snapshot'] + self.tr(
            '\n選択したVM（同一VM内で構築）：', '\nSelected VM (provisioned in place): ') + details.get('original_vmx', '') + self.tr(
            '\n最初に選択した元保存点（変更しません）：', '\nOriginally selected snapshot (unchanged): ') + details.get('original_snapshot', '')

    # 手動変更中は進捗を止め、再確認するまで同じVMを保持する。
    def show_manual_setup(self, details, answer):
        self.activity_state='waiting'
        self.activity_progress.stop()
        if details.get('kind') == 'manual_vm_clone':
            self.activity_label.configure(text=self.tr('VMwareでの完全クローン作成待ち', 'Waiting for a full clone in VMware'))
            prompt = self.tr(
                '自動クローンに失敗しました。元VMは変更せず、次の手順で作業用VMを作成してください。\n\n1. VMwareで下記の元VMを開いてください。電源はOFFのままにしてください。\n2. 仮想マシン→管理→クローンを開き、「既存のスナップショット」から下記の保存点を選んでください。「現在の状態」は選ばないでください。\n3. 「完全なクローン」を選んでください。リンククローンは使用できません。\n4. 保存先フォルダとVM名を下記どおりに指定し、作成完了まで待ってください。元VMの移動・削除や暗号化解除は不要です。クローンは起動しないでください。\n5. 「はい」で確認します。Setupは指定先・停止状態・ディスクの独立性を検証してから、クローン内だけを構築します。\n「いいえ」は中断します。\n\n元VM：',
                'Automatic cloning failed. Preserve the original VM and create a working VM as follows.\n\n1. Open the original VM below in VMware; keep it powered off.\n2. Open VM > Manage > Clone. Select Existing snapshot and choose the snapshot below. Do not select Current state.\n3. Select Full clone, not Linked clone.\n4. Use exactly the destination folder and VM name below, then wait for cloning to finish. Do not move, delete, or decrypt the original VM. Do not start the clone.\n5. Select Yes. Setup verifies the destination, powered-off state, and independent disk references before provisioning only the clone.\nNo pauses setup.\n\nOriginal VM: ') + details['vmx'] + self.tr(
                    '\n選択する保存点：', '\nSnapshot to select: ') + details['source_snapshot'] + self.tr(
                    '\n新VM名：', '\nNew VM name: ') + Path(details['destination']).stem + self.tr(
                    '\n保存先フォルダ：', '\nDestination folder: ') + str(Path(details['destination']).parent) + self.tr(
                    '\n確認するVMX：', '\nExpected VMX: ') + details['destination'] + self.tr(
                    '\n\nエラー詳細：', '\n\nError detail: ') + details.get('error', '')
            accepted = self.ask_manual_setup(prompt, open_guest=False)
            self.activity_state='running'
            self.activity_progress.start(80)
            answer.put(accepted)
            return
        self.activity_label.configure(text=self.tr('Guestの手動設定・再起動待ち','Waiting for manual Guest setup and restart'))
        prompt=self.tr('対象Guestのレジストリエディターで設定を変更し、Windowsを再起動してください。Hostは変更しないでください。\n\nキー：HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\n値：DisableAntiSpyware / 1\n型：REG_DWORD（32ビット）または既存のREG_QWORD（64ビット）を読み取ります。OSが64ビットでもQWORDを選ぶ必要はありません。新規作成はREG_DWORDを使用してください。既存のQWORDは型だけでは拒否しませんが、Windowsへの反映を保証するものではありません。\n\n再起動とログインが完了したら「はい」で実状態を確認します。設定値だけでは成功にしません。「いいえ」はGuest状態を保持して中断します。\n\n対象VM：', 'Edit the registry in the selected Guest and restart Windows. Do not modify the Host.\n\nKey: HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\nValue: DisableAntiSpyware / 1\nType: REG_DWORD (32-bit) or an existing REG_QWORD (64-bit) can be read. A 64-bit OS does not require QWORD. Please use REG_DWORD for new values. Existing QWORD values are not rejected solely for their type, but their effect on Windows is not guaranteed.\n\nAfter restart and logon, choose Yes to verify effective state. The registry value alone does not establish success. No pauses setup and preserves Guest state.\n\nTarget VM: ')+details['vmx']
        if details.get('kind') == 'manual_registry_recovery':
            prompt=self.manual_recovery_prompt(details)
        if self.registry_profile.get()=='group_policy' and details.get('kind')!='manual_registry_recovery':
            prompt=self.tr('Guestで手動設定・再起動後、「はい」で読み取り確認します。対象VM：','After manual Guest setup and reboot, select Yes for read-only verification. VM: ')+details['vmx']
        prompt=prompt+'\n\n'+self.manual_protection_instructions()
        accepted=self.ask_manual_setup(prompt)
        self.activity_state='running'
        self.activity_progress.start(80)
        answer.put(accepted)

    # 長い診断を画面外へはみ出させず、操作ボタンを常に表示する。
    def ask_manual_setup(self, prompt, open_guest=True):
        dialog = tk.Toplevel(self)
        dialog.title(self.tr('Guestの手動確認', 'Manual Guest verification'))
        width = min(960, max(480, self.winfo_screenwidth() - 80))
        height = min(760, max(400, self.winfo_screenheight() - 100))
        dialog.geometry(f'{width}x{height}')
        dialog.transient(self)
        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill='both', expand=True)
        buttons = ttk.Frame(frame)
        buttons.pack(side='bottom', fill='x', pady=(12, 0))
        body = ttk.Frame(frame)
        body.pack(fill='both', expand=True)
        text = tk.Text(body, wrap='word', font=('Segoe UI', 11))
        scroll = ttk.Scrollbar(body, orient='vertical', command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        text.pack(side='left', fill='both', expand=True)
        text.insert('1.0', prompt)
        text.configure(state='disabled')
        accepted = False

        # 完了の明示操作だけを再確認開始として扱い、閉じる操作は中断する。
        def finish(value):
            nonlocal accepted
            accepted = value
            dialog.destroy()

        ttk.Button(buttons, text=self.tr('はい：操作完了・再確認', 'Yes: finished, verify again'), command=lambda: finish(True)).pack(side='right', padx=8)
        ttk.Button(buttons, text=self.tr('いいえ：状態を保持して中断', 'No: preserve state and pause'), command=lambda: finish(False)).pack(side='right')
        if open_guest:
            ttk.Button(buttons, text=self.tr('作業用Guestを開く', 'Open working Guest'), command=self.open_console).pack(side='left')
        dialog.protocol('WM_DELETE_WINDOW', lambda: finish(False))
        dialog.grab_set()
        self.wait_window(dialog)
        return accepted

    # ワーカー例外はGUIへ返し、完了通知と失敗通知を区別する。
    def work(self,action,kind):
        self.busy=True
        self.activity_state='running'
        if self.page == 6:
            self.activity_progress.start(80)
        def run():
            try:
                self.events.put((kind,action()))
            except Exception as error:
                self.events.put(('error',str(error)))
        threading.Thread(target=run,daemon=True).start()

    # 定期ポーリングでTkをワーカースレッドから触らない。
    def poll(self):
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=='manual_action':
                    self.show_manual_setup(*value)
                elif kind=='log':
                    self.log.configure(state='normal');self.log.insert('end',str(value)+'\n');self.log.see('end');self.log.configure(state='disabled')
                    phases=('prepared','common','dynamic','static','verified','complete')
                    if str(value).endswith(': complete') and str(value).split(':')[0] in phases:
                        self.completed_phases=phases.index(str(value).split(':')[0])+1
                        self.phase_progress.configure(value=self.completed_phases)
                else:
                    self.busy=False
                    self.activity_state='error' if kind=='error' else 'complete'
                    if self.page == 6:
                        self.activity_progress.stop()
                        self.activity_label.configure(text=self.tr('エラーで停止しました' if kind=='error' else '完了しました', 'Stopped with an error' if kind=='error' else 'Completed'))
                    if kind=='snapshots':
                        if self.page==3 and value[0]==self.env['vmx_path'].get():
                            self.baseline_choice.configure(values=value[1])
                    elif kind=='inventory':
                        for name,record in value['tools'].items():
                            self.guest[name][0].set(record['exists'])
                        self.render()
                    elif kind=='error':
                        messagebox.showerror('Setup',value,parent=self)
                        if self.page == 4:
                            self.page = 3
                            self.render()
                        elif self.page == 6:
                            self.page = 5
                            self.render()
                    elif kind=='complete':
                        self.show_hook_completion()
        except queue.Empty:
            pass
        if self.busy and self.page == 6 and self.activity_state=='running':
            self.activity_tick += 1
            dots='.'*((self.activity_tick//5)%4)
            self.activity_label.configure(text=self.tr('セットアップ中','Setting up')+dots+self.tr('  完了工程 ', '  Completed phases ')+str(self.completed_phases)+'/6')
        self.after(100,self.poll)

    # 成功後の初回解析前に必要な承認を、実際の導入先とともに案内する。
    def show_hook_completion(self):
        self.setup_completed = True
        self.hook_notice_acknowledged.set(False)
        project = self.setup_engine.root / 'config' / 'analysis_project'
        for widget in self.body.winfo_children():
            widget.destroy()
        ttk.Label(self.body, text=self.tr('セットアップ完了：初回解析ではCodexのHook承認が必要です',
            'Setup complete: your first analysis requires Codex hook approval'),
            font=('Yu Gothic UI', 16, 'bold'), wraplength=1000).pack(anchor='w', pady=12)
        ttk.Label(self.body, text=self.tr('Codexで開く解析用フォルダ：', 'Analysis project to open in Codex:')).pack(anchor='w')
        path_var = tk.StringVar(master=self, value=str(project))
        ttk.Entry(self.body, textvariable=path_var, state='readonly').pack(fill='x', pady=8)
        self.hook_project_path = path_var
        ttk.Label(self.body, text=self.tr(
            '1. r_AKanalyで初回解析を開始し、解析用フォルダとHookが準備されたら、上のフォルダをCodexで開いて信頼してください。\n\n'
            '2. Hooks画面で、そのフォルダの .codex/hooks/r_AKanaly_guard.exe を使う SessionStart・PreToolUse・PermissionRequest を確認して承認してください。\n\n'
            '3. 承認待ちのエラーで解析が停止した場合は、承認後に同じ設定JSONで解析を最初から実行し直してください。\n\n'
            'このチェックは案内を読んだことの確認です。Codex側の信頼・Hook承認を自動で行うものではありません。',
            '1. Start your first analysis in r_AKanaly. Once the analysis project and hooks are prepared, open the folder above in Codex and trust it.\n\n'
            '2. In Hooks, review and approve SessionStart, PreToolUse and PermissionRequest using .codex/hooks/r_AKanaly_guard.exe in that project.\n\n'
            '3. If analysis stopped while awaiting approval, approve the hooks and restart analysis from the beginning with the same settings JSON.\n\n'
            'This checkbox only confirms that you have read these instructions. It does not grant project trust or hook approval in Codex.'),
            wraplength=1000, justify='left').pack(anchor='w', pady=16)
        ttk.Checkbutton(self.body, text=self.tr('Codexの信頼・Hook承認が必要なことと、上記の手順を確認しました',
            'I have read the instructions and understand that Codex project trust and hook approval are required'),
            variable=self.hook_notice_acknowledged, command=self.update_hook_close_state).pack(anchor='w', pady=12)
        self.back_button.configure(state='disabled')
        self.update_hook_close_state()

    # チェックを外した場合も閉じる操作を再び無効にする。
    def update_hook_close_state(self):
        self.close_button.configure(state='normal' if self.hook_notice_acknowledged.get() else 'disabled')

    # 構築中や成功案内の未確認時には、タイトルバーからも終了させない。
    def close_setup(self):
        if self.busy:
            messagebox.showinfo('Setup',self.tr('処理中です。完了またはエラー表示までお待ちください。','Operation in progress; wait for completion or an error.'),parent=self)
        elif self.setup_completed and not self.hook_notice_acknowledged.get():
            messagebox.showinfo('Setup', self.tr('Hookの案内を読み、確認チェックを入れてください。',
                'Please read the hook instructions and select the acknowledgement checkbox.'), parent=self)
        else:
            self.destroy()

    # 共通の閉じるボタンにも処理中ガードを適用する。
    def destroy(self):
        if getattr(self,'busy',False) or (getattr(self,'setup_completed',False) and not self.hook_notice_acknowledged.get()):
            self.close_setup()
        else:
            super().destroy()

    # Hostの選択画面と混同せず、Guest Operationsで取得した一覧から選ぶ。
    def guest_browse(self,var=None):
        if self.busy or var is None:
            return
        if self.registry_profile.get() in ('manual_registry','group_policy'):
            messagebox.showinfo('Setup', self.tr('元VMを起動しないため、手動方式の構築前はGuest参照を行いません。再利用するツールのパスを入力してください。Setup用の枝への配置時に検証します。', 'To preserve the original VM, Guest browsing is unavailable before manual-mode provisioning. Enter any tool paths to reuse; they will be verified in the Setup branch.'), parent=self)
            return
        from pathlib import PureWindowsPath
        plan,secret=self.inputs()
        dialog=tk.Toplevel(self)
        dialog.title(self.tr('Guest内のファイル参照','Browse Guest files'))
        dialog.geometry('850x600')
        path=tk.StringVar(value=str(PureWindowsPath(var.get()).parent))
        ttk.Entry(dialog,textvariable=path).pack(fill='x',padx=12,pady=12)
        listing=ttk.Treeview(dialog,columns=('type','path'),show='headings')
        listing.heading('type',text=self.tr('種類','Type'));listing.heading('path',text=self.tr('Guestパス','Guest path'))
        listing.column('type',width=80,stretch=False);listing.column('path',width=700)
        listing.pack(fill='both',expand=True,padx=12)
        status=ttk.Label(dialog,text='');status.pack(fill='x',padx=12)
        results=queue.Queue()
        pending=[False]
        # 読取り専用一覧を取得し、調査のために起動したVMだけを元の停止状態へ戻す。
        def retrieve():
            if pending[0]:return
            folder=path.get()
            pending[0]=True;self.busy=True
            status.configure(text=self.tr('Guestを読み取り中…','Reading Guest…'))
            def worker():
                vm=VMware(plan['vmrun'],plan['vmx'],plan['username'],secret['guest_password'],secret['vm_password'])
                started=False
                try:
                    started=not vm.running();vm.boot()
                    data=vm.query('@(Get-ChildItem -LiteralPath '+quote(folder)+' -ErrorAction Stop | Select-Object -First 2000 | ForEach-Object { @{path=$_.FullName;directory=$_.PSIsContainer} })')
                    results.put(('ok',data))
                except Exception as error:results.put(('error',str(error)))
                finally:
                    try:
                        if started:vm.shutdown()
                    except Exception as error:results.put(('error',str(error)))
                    results.put(('done',None))
            threading.Thread(target=worker,daemon=True).start()
        # ダブルクリックはフォルダ移動またはファイル選択として扱う。
        def choose(event=None):
            selected=listing.selection()
            if not selected or pending[0]:return
            values=listing.item(selected[0],'values')
            if values[0]=='directory':path.set(values[1]);retrieve()
            else:var.set(values[1]);dialog.destroy()
        # フォルダの親へ移動する操作もGuest内のパスだけで計算する。
        def parent():
            path.set(str(PureWindowsPath(path.get()).parent));retrieve()
        # GUIスレッドで一覧を更新し、停止完了まで次の操作を受け付けない。
        def poll_files():
            try:
                while True:
                    kind,value=results.get_nowait()
                    if kind=='ok':
                        listing.delete(*listing.get_children())
                        for item in ([value] if isinstance(value,dict) else value or []):
                            listing.insert('','end',values=('directory' if item['directory'] else 'file',item['path']))
                    elif kind=='error':status.configure(text=value)
                    else:pending[0]=False;self.busy=False;status.configure(text=self.tr('読取り完了','Read complete'))
            except queue.Empty:pass
            if dialog.winfo_exists():dialog.after(100,poll_files)
        # 通信中の閉鎖だけを防止する。
        def close():
            if not pending[0]:dialog.destroy()
        controls=ttk.Frame(dialog);controls.pack(fill='x',padx=12,pady=12)
        for text,callback in ((self.tr('読込み','Read'),retrieve),(self.tr('親フォルダ','Parent'),parent),(self.tr('選択','Select'),choose),(self.tr('閉じる','Close'),close)):
            ttk.Button(controls,text=text,command=callback).pack(side='left',padx=5)
        listing.bind('<Double-1>',choose)
        dialog.protocol('WM_DELETE_WINDOW',close)
        poll_files();retrieve()


# 本番GUIは試作の起動コマンドから分離する。
def main():
    app=Setup()
    if '--smoke-test' in sys.argv:
        for language in ('日本語','English'):
            app.lang.set(language)
            for page in range(7):
                app.page=page
                app.render()
                app.update()
        app.destroy()
    else:
        app.mainloop()
