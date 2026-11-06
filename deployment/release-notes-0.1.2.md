# r_AKanaly 0.1.2

## 日本語

- Setupの設定方式をプルダウンで選択してください。手動レジストリ方式を選んだ瞬間に、注意書き・起点スナップショット欄・一覧更新ボタンを表示します。「次へ」を押す必要はありません。
- 手動方式では、再起動後もDisableAntiSpyware=1とDefender停止を確認したGuestをシャットダウンし、スナップショットを準備・選択してください。Setupはその起点を復元し、Agent・解析ツールの配置前に設定と実状態を確認します。
- 動的・静的環境は、選んだ起点から構築した共通保存点からそれぞれ派生します。以前の別の解析用保存点へ戻りません。起点確認の失敗時はGuest状態を保持し、同じ入力で再確認できます。
- README日英版に、利用者のVMで2回再現した「QWORD作成・再起動後に削除し、DWORDで作り直す」確認手順を追加しました。全環境での成功を保証するものではありません。

新規導入は`r_AKanaly-0.1.2-installer-windows-x64.zip`を全体展開し、`Setup.exe`を起動してください。既存環境は本体の「更新」を使用してください。0.1.1とGuest資材は同じため、本体更新だけでは既存VM・保存点を再構築しません。新しい起点方式を使う場合はSetupで新規導入先を指定してください。

関連41テストでGUI選択イベント、起点判定、失敗後の再開、共通保存点からの派生順を確認しました。新版での実VM通し再構築は未実施です。更新資材にはEd25519署名を使用します。利用条件・必要環境はREADMEとLICENSEを確認してください。

## English

- Selecting manual registry mode in the Setup dropdown immediately displays the instructions, baseline snapshot field, and refresh button. No Next click is required.
- Prepare a powered-off snapshot after confirming that DisableAntiSpyware=1 persists across restart and Defender is stopped. Setup restores and verifies this baseline before deploying Agents or analysis tools.
- Dynamic and static environments each derive from the common snapshot provisioned from the selected baseline, never from older analysis snapshots. Failed baseline verification preserves Guest state; resume with identical inputs to recheck.
- The Japanese and English README include a QWORD-to-DWORD troubleshooting sequence reproduced twice in a user's VM. Success on every system is not guaranteed.

For a new installation, fully extract `r_AKanaly-0.1.2-installer-windows-x64.zip` and run `Setup.exe`. Existing users can use the application's Update menu. Guest assets are unchanged from 0.1.1, so an application update does not rebuild existing VMs or snapshots. To use the new baseline workflow, select a new installation directory in Setup.

41 related tests cover GUI selection events, baseline checks, failure/resume behavior, and snapshot derivation order. A full real-VM installation with this version has not been rerun. Update assets use Ed25519 signatures. Please see README and LICENSE for requirements and usage terms.
