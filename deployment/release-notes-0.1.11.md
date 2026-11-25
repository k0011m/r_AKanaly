# r_AKanaly 0.1.11

## 日本語
- 結果フォルダのZIP化・削除によって、VM保存点が参照する証拠VMDKが失われる問題を修正しました。
- 新しい証拠ディスクは結果フォルダの外に保持します。dynamic_analysis.evidence_disk.storage_dirで絶対パスを指定でき、未指定時はユーザーホーム配下のrAK/disksを使用します。
- 保存点と証拠ディスクの対応を記録し、旧形式の結果内VMDKや参照先欠落がある場合は破壊的な結果削除を拒否します。既存ディスクの自動移動・削除は行いません。
- 証拠ディスクは結果ZIPに含まれません。保存点を保持する間は元のディスクも保持してください。

検証：関連37テスト成功、本体の配布自己診断ready。今回の版では実VMの通し解析は再実施していません。Guest起動中の証拠保存失敗やログ転送失敗は別問題で、この版で修正したとはしていません。

インストール：r_AKanaly-0.1.11-installer-windows-x64.zipを全て展開し、Setup.exeを実行してください。既存利用者向けの署名済み更新ZIPも添付しています。SetupとGuest資材は0.1.10を維持します。

## English
- Keep evidence VMDKs outside result folders so archiving and deleting results does not break VM snapshot references.
- Configure an absolute directory with dynamic_analysis.evidence_disk.storage_dir. The default is rAK/disks under the user's home directory.
- Record snapshot references and refuse destructive result cleanup when legacy in-folder VMDKs or missing disk references are detected. Existing disks are not automatically moved or deleted.
- Evidence disks are not included in result ZIPs. Retain them while their snapshots are needed.

Validation: 37 related tests passed and the executable deployment self-test reported ready. End-to-end VM analysis was not repeated. Guest-still-powered-on evidence preservation and log-transfer errors are separate issues, not fixed by this release.

Extract the entire installer ZIP and run Setup.exe. A signed update package is also provided. Setup and Guest assets remain at the 0.1.10 versions.
