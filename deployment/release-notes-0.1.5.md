# r_AKanaly 0.1.5

## 日本語

重要修正：v0.1.3/v0.1.4の保存点を削除・同名再作成する処理を除去しました。これらの版で失敗したSetupは再実行しないでください。

- 手動方式は選択したスナップショットからVMを完全クローンし、クローン側だけを構築します。元VMへの復元・起動・設定変更を行いません。「既存VM」を選んでも手動方式ではクローンします。
- 修正済み状態はクローンVM内の新しい保存点へ保存します。元保存点の削除・上書きはしません。
- 手動待ちの再開では現在状態を保持します。共通検証の再開前に起動確認を追加しました。
- 元VMを対象とする旧Setup進捗は変更せず拒否します。新しいインストール先を指定してください。完全クローン用の空き容量が必要です。

`r_AKanaly-0.1.5-installer-windows-x64.zip`を全体展開して使用してください。本体更新だけではSetupのやり直しになりません。46件のモック・回帰テストが成功しました。実VMでの完全クローンからの新規構築通し試験は未実施です。既に削除された保存点を復元する更新ではありません。

## English

Critical fix: the snapshot deletion and same-name replacement introduced in v0.1.3/v0.1.4 has been removed. Do not rerun a failed Setup from those versions.

- Manual mode creates a full VM clone from the selected snapshot and provisions only the clone. It never reverts, starts, or reconfigures the original VM. This applies even when an existing VM is selected.
- Repaired state is stored in a new snapshot within the clone. Existing snapshots are not deleted or overwritten.
- Resuming manual input preserves current state; common verification now checks startup before resuming.
- Legacy progress targeting the original VM is rejected without changes. Choose a new installation directory and allow disk space for the full clone.

Fully extract `r_AKanaly-0.1.5-installer-windows-x64.zip`. A normal application update does not rerun Setup. 46 mock/regression tests passed. A full real-VM installation through this new clone workflow has not been performed. This release does not restore previously deleted snapshots.
