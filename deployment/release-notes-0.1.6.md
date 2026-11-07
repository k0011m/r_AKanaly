# r_AKanaly 0.1.6

## 日本語

- 手動設定の案内を、解析専用Guestの改ざん防止を確認してからPolicies側のDWORDを設定する順序に変更しました。DWORD→QWORD→DWORDの手順は廃止しました。Setupが改ざん防止やレジストリを自動変更する機能ではありません。
- 保護検証に失敗した場合、失敗時のレジストリ値・保護状態・理由を表示します。値が1でも実状態がONまたは取得不能なら通過しません。
- 元VM・元保存点と作業用クローンを明確に区別し、保存点の移動が不要なこと、成功時にクローン内へ別名の新しい保存点を作ることを案内します。説明はスクロールできます。
- 手動方式の事前ツール検出で元VMを起動する経路を止め、Guest表示ボタンも作業用クローンだけを開くよう修正しました。
- v0.1.5で導入した完全クローン方式と既存保存点の削除・上書き禁止は維持しています。
- 自動クローンが失敗した場合は、VMwareで指定保存点から完全クローンを作成する手動経路を案内します。元VMを直接構築する方式には戻りません。リンククローンや元VMを参照するディスクは拒否します。

初回導入は`r_AKanaly-0.1.6-installer-windows-x64.zip`を全体展開してください。本体更新だけではSetupを再実行しません。v0.1.3/v0.1.4で失敗した導入先を使わず、新しい導入先を指定してください。

検証：51件の回帰テスト成功。暗号化VMで自動クローンの失敗とVMware GUIによる完全クローン作成・独立性検査を確認しました。今回の手動経路を含むSetup全工程の通し確認は未完了です。改ざん防止OFFでも、Policies値が再起動後に消え、Defenderが起動約107秒でONへ戻る環境を確認しています。手動設定だけで無効化できることを保証する版ではありません。

## English

- Manual instructions now ask you to check Tamper Protection in the dedicated analysis Guest before setting the Policies DWORD. The DWORD > QWORD > DWORD sequence was removed. Setup does not toggle Tamper Protection or rewrite the registry automatically in manual mode.
- Failed verification displays the observed registry values, protection state, and reason. A value of 1 does not pass when effective protection is ON or unavailable.
- The dialog distinguishes the original VM/snapshot from the working clone. No snapshot move is required; successful repair creates a differently named snapshot in the clone. Instructions are scrollable.
- Manual-mode tool inspection no longer starts the original VM, and the Guest console button opens only the working clone.
- Full cloning and preservation of existing snapshots introduced in v0.1.5 remain in place.
- If automatic cloning fails, Setup offers a manual path to create a full clone from the specified snapshot in VMware. It never falls back to provisioning the original VM. Linked clones and disks referencing the original VM are rejected.

For installation, fully extract `r_AKanaly-0.1.6-installer-windows-x64.zip`. Updating the application alone does not rerun Setup. Use a new installation directory instead of reusing a failed v0.1.3/v0.1.4 installation.

Validation: 51 regression tests passed. Automatic cloning failure on an encrypted VM, full cloning through VMware GUI, and clone independence checks were verified. End-to-end Setup verification including the new manual path is not complete. In the tested environment, the Policies value disappeared after reboot despite Tamper Protection being OFF, and Defender became active around 107 seconds after boot. This release does not guarantee that manual registry settings can disable protection.
