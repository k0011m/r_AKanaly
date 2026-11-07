# r_AKanaly 0.1.3

## 日本語

- 手動方式で保護設定の検証に失敗した場合、Setupがレジストリ修正・再起動・確認・シャットダウンを案内して待機します。修正のためのレジストリ自動書換えは行いません。
- 操作完了後に電源OFFと起動後の実状態を確認し、修正状態を別名保存した後に対象保存点を同名で更新します。失敗状態と退避保存点は保持します。
- 導入成功時にユーザー環境変数R_AKANALY_HOMEとユーザーPATHへ導入先を登録します。Terminalを開き直してください。

初回・新しいSetupでの導入には `r_AKanaly-0.1.3-installer-windows-x64.zip` を全体展開してください。Setup.exe単体では使用しないでください。解析本体とGuest資材は0.1.2と同じです。既存環境の通常更新だけではSetupの再実行やVM保存点の更新は行いません。

関連43テストとSetup・ランチャーのビルドを確認しました。実VMでの手動修正から保存点置換までの通し試験は未実施です。更新資材はEd25519署名付きです。

## English

- When manual-mode protection verification fails, Setup waits for the user to correct the Guest registry, restart, verify, and shut down. It does not automatically rewrite registry values for this repair.
- After user confirmation, Setup checks power-off and effective state after boot, preserves a separate recovery snapshot, and replaces the target snapshot with the same name. Failed-state and recovery snapshots are retained.
- Successful setup registers the installation directory in the user R_AKANALY_HOME variable and PATH. Please reopen your terminal.

Fully extract `r_AKanaly-0.1.3-installer-windows-x64.zip` to use the new Setup. Do not move Setup.exe alone. The analysis core and Guest assets are unchanged from 0.1.2. An ordinary application update does not rerun Setup or update VM snapshots.

43 related tests passed and Setup/launcher builds succeeded. The manual-repair and snapshot-replacement workflow has not been tested end to end on a real VM. Update assets use Ed25519 signatures.
