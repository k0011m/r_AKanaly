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
        super().__init__()
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
            ttk.Label(self.body,text=self.tr('Guest保護の設定方式（どちらも解析前に実状態を確認します）','Guest protection setup (both verify effective state before analysis)')).pack(anchor='w',pady=8)
            self.protection_choice=ttk.Combobox(self.body,state='readonly',values=(self.tr('手動レジストリ設定（推奨）','Manual registry setup (recommended)'),self.tr('起動後に公式APIで設定・確認','Apply and verify through official APIs after startup')),width=65)
            self.protection_choice.current(0 if self.registry_profile.get()=='manual_registry' else 1)
            self.protection_choice.pack(anchor='w')
            self.protection_choice.bind('<<ComboboxSelected>>',self.change_protection_choice)
            self.manual_baseline_panel=ttk.Frame(self.body)
            ttk.Label(self.manual_baseline_panel,text=self.manual_registry_instructions()+'\n\n'+self.tr('対象GuestでDisableAntiSpywareを1に設定し、再起動後も値が保持され、Defenderが停止していることを確認してください。その後Guestをシャットダウンしてスナップショットを作成し、下で選択してください。指定保存点から独立したVMの完全クローンを作り、クローン内で構築します。元VMと元保存点は変更しません。既存VMを選んだ場合も完全クローンを使用します。クローン分の空き容量が必要です。','In the selected Guest, set DisableAntiSpyware to 1 and confirm it persists after restart with Defender stopped. Shut down the Guest, create a snapshot, and select it below. Setup creates a full VM clone from that snapshot and provisions only the clone. The original VM and snapshots are preserved, even when using an existing VM. Extra disk space is required for the clone.'),wraplength=1000).pack(anchor='w',pady=10)
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
            ttk.Label(self.body, text=self.tr('Guestで検出した結果です。Pythonの専用環境は依存関係も検証します。', 'Actual Guest inventory. Private Python dependencies are verified during setup.')).pack(anchor='w')
            self.tool_table(self.guest, guest=True)
            for name, status in self.status.items():
                status.configure(text=self.tr('Guest検出済み' if self.guest[name][0].get() else '未検出', 'Detected in Guest' if self.guest[name][0].get() else 'Not found'))
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
        if self.page==3 and var is self.env['base_snapshot']:
            return
        super().entry_row(label,var,**kwargs)

    # 次へを待たず、プルダウン選択イベントで手動設定の説明と基点欄を切り替える。
    def change_protection_choice(self,event=None):
        manual=self.protection_choice.current()==0
        self.registry_profile.set('manual_registry' if manual else 'official_api')
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
        if self.env['vm_mode'].get()=='copy':
            clone=Path(self.env['clone_path'].get())
            vmx=str(clone if clone.suffix.lower()=='.vmx' else clone/Path(vmx).name)
        subprocess.Popen([self.host['VMware Workstation'][1].get(),'-x',vmx])

    # パッケージ選択だけでは実配置しない。
    def choose_package(self):
        path=filedialog.askdirectory(parent=self)
        if path:
            self.package=Path(path)
            self.render()

    # 選択した構築内容だけを取り出し、資格情報は別オブジェクトへ分離する。
    def inputs(self):
        plan={'install_dir':self.install_dir.get(), 'output_dir':self.output_dir.get(), 'vmrun':self.host['vmrun'][1].get(),
              'vmx':self.env['vmx_path'].get(), 'username':self.env['guest_username'].get(), 'mode':self.env['vm_mode'].get(),
              'clone_path':self.env['clone_path'].get(), 'base_snapshot':self.env['base_snapshot'].get(), 'registry_profile':self.registry_profile.get(),
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
            if self.registry_profile.get()=='manual_registry' and not self.env['base_snapshot'].get().strip():
                messagebox.showerror('Setup',self.tr('設定済みの起点スナップショットを選択してください。','Select a prepared baseline snapshot.'),parent=self)
                return
            if not Path(self.env['vmx_path'].get()).is_file():
                messagebox.showerror('Setup', self.tr('指定したVMXファイルが存在しません。', 'Selected VMX file does not exist.'), parent=self)
                return
            super().next_page()
            if self.page != 4:
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
        if not self.busy:
            super().back()

    # Guestを調査するための起動は行うが、保存点の復元や設定変更はしない。
    def inspect(self,plan,secret,paths):
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
        SetupEngine(plan,secret,manifest,report=lambda msg:self.events.put(('log',msg)),request_action=self.wait_for_manual_setup).apply()

    # ワーカーを待機させ、Tk操作とユーザーの回答はGUIスレッドへ渡す。
    def wait_for_manual_setup(self, details):
        answer=queue.Queue()
        self.events.put(('manual_action',(details,answer)))
        return answer.get()

    # 初期選択と復旧案内で、手動編集の場所・対象を同じ説明に統一する。
    def manual_registry_instructions(self):
        return self.tr(
            '【変更するのはPolicies側のDisableAntiSpywareだけです】\n対象Guest内でWin+Rを押し、regeditと入力して起動してください。上部のアドレス欄に次のパスを貼り付け、Enterを押してください。\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\n右側の一覧でDisableAntiSpywareを開き、値のデータを1にしてください。存在しない場合は右側の空白部分を右クリック→新規→DWORD（32ビット）値で作成し、名前をDisableAntiSpyware、値を1にしてください。\nPoliciesを含まない同名の場所は変更しないでください。DisableAntiVirusや他の値・キー・アクセス許可は作成・変更・削除しないでください。Host側でも操作しないでください。対象キーが見つからない場合は別の場所を代用せず、パスを確認してください。',
            '[Change only DisableAntiSpyware under Policies]\nInside the selected Guest, press Win+R, enter regedit, and open Registry Editor. Paste this path into its top address bar and press Enter:\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\nOpen DisableAntiSpyware in the right pane and set Value data to 1. If it is absent, right-click an empty area in the right pane, choose New > DWORD (32-bit) Value, name it DisableAntiSpyware, and set it to 1.\nDo not edit the similarly named location without Policies. Do not create, change, or delete DisableAntiVirus, other values or keys, or permissions. Do not perform these steps on the Host. If the target key is missing, check the path instead of substituting another location.')

    # 手動変更中は進捗を止め、再確認するまで同じVMを保持する。
    def show_manual_setup(self, details, answer):
        self.activity_state='waiting'
        self.activity_progress.stop()
        self.activity_label.configure(text=self.tr('Guestの手動設定・再起動待ち','Waiting for manual Guest setup and restart'))
        prompt=self.tr('対象Guestのレジストリエディターで設定を変更し、Windowsを再起動してください。Hostは変更しないでください。\n\nキー：HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\n値：DisableAntiSpyware / 1\n型：REG_DWORD（32ビット）または既存のREG_QWORD（64ビット）を読み取ります。OSが64ビットでもQWORDを選ぶ必要はありません。新規作成はREG_DWORDを使用してください。既存のQWORDは型だけでは拒否しませんが、Windowsへの反映を保証するものではありません。\n\n再起動とログインが完了したら「はい」で実状態を確認します。設定値だけでは成功にしません。「いいえ」はGuest状態を保持して中断します。\n\n対象VM：', 'Edit the registry in the selected Guest and restart Windows. Do not modify the Host.\n\nKey: HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\nValue: DisableAntiSpyware / 1\nType: REG_DWORD (32-bit) or an existing REG_QWORD (64-bit) can be read. A 64-bit OS does not require QWORD. Please use REG_DWORD for new values. Existing QWORD values are not rejected solely for their type, but their effect on Windows is not guaranteed.\n\nAfter restart and logon, choose Yes to verify effective state. The registry value alone does not establish success. No pauses setup and preserves Guest state.\n\nTarget VM: ')+details['vmx']
        if details.get('kind') == 'manual_registry_recovery':
            prompt=self.tr(
                '対象Guestで手動のレジストリ修正を行ってください。Setupは値を書き換えません。\n\nキー：HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\n値：DisableAntiSpyware / 1\n\nWindowsを再起動し、値と保護の状態を確認した後、Guestをシャットダウンしてください。電源が切れたら「はい」を押してください。Setupが再起動して読取り確認し、正常停止後にクローンVM内で新しい保存点を作ります。既存保存点は削除・上書きしません。\n「いいえ」は現在のGuestを保持して中断します。\n\n元の保存点（保持します）：',
                'Please manually correct the registry in the selected Guest. Setup will not write the value.\n\nKey: HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\nValue: DisableAntiSpyware / 1\n\nRestart Windows, verify the value and protection state, then shut down the Guest. Choose Yes after power-off. Setup will boot for read-only verification, shut down normally, and create a new snapshot in the cloned VM. Existing snapshots are never deleted or overwritten.\nNo pauses setup and preserves the Guest.\n\nSource snapshot (preserved): ')+details['source_snapshot']+'\nVM: '+details['vmx']
        prompt=self.manual_registry_instructions()+'\n\n'+prompt
        accepted=messagebox.askyesno('Guest setup',prompt,parent=self)
        self.activity_state='running'
        self.activity_progress.start(80)
        answer.put(accepted)

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
                    else:
                        messagebox.showinfo('Setup',self.tr('構築と検証が完了しました。','Setup and verification completed.'),parent=self)
        except queue.Empty:
            pass
        if self.busy and self.page == 6 and self.activity_state=='running':
            self.activity_tick += 1
            dots='.'*((self.activity_tick//5)%4)
            self.activity_label.configure(text=self.tr('セットアップ中','Setting up')+dots+self.tr('  完了工程 ', '  Completed phases ')+str(self.completed_phases)+'/6')
        self.after(100,self.poll)

    # 構築中のGUI破棄でGuest処理を孤立させない。
    def close_setup(self):
        if self.busy:
            messagebox.showinfo('Setup',self.tr('処理中です。完了またはエラー表示までお待ちください。','Operation in progress; wait for completion or an error.'),parent=self)
        else:
            self.destroy()

    # 共通の閉じるボタンにも処理中ガードを適用する。
    def destroy(self):
        if getattr(self,'busy',False):
            self.close_setup()
        else:
            super().destroy()

    # Hostの選択画面と混同せず、Guest Operationsで取得した一覧から選ぶ。
    def guest_browse(self,var=None):
        if self.busy or var is None:
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
