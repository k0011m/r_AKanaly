# r_AKanaly 0.1.8

## 日本語

- 手動設定方式のSetupを、VM全体の完全クローンから、同じVM内の新しい保存点の枝へ変更しました。指定起点と既存保存点は削除・上書きしません。VMの現在状態と構成は変更しますので、必要な作業を保存してシャットダウンしてから開始してください。
- 保存点の名前衝突、サスペンド中の開始、旧完全クローン方式の進捗流用を拒否します。構築中の中断・再開を記録し、Setup同士が同じVMを同時操作しないよう排他します。
- 共通保存点から動的・静的環境を分岐します。分岐作成自体はGuestを起動しません。その後の構築・再起動後確認は維持しています。
- READMEと画面案内を更新しました。関連回帰テスト68件成功。今回の同一VM分岐方式での実VM通し検証は未実施です。

初回導入は `r_AKanaly-0.1.8-installer-windows-x64.zip` を全体展開して `Setup.exe` を起動してください。中断した旧完全クローン方式からは新しいインストール先で開始してください。更新用ZIP・manifest・署名は自動更新用です。第三者の独立ツールはSetupが公式元から取得します。

## English

- Manual-mode Setup now creates a new snapshot branch in the same VM instead of a full VM clone. The selected baseline and existing snapshots are not deleted or overwritten. The VM's current state and configuration do change; save necessary work and shut down before starting.
- Setup rejects snapshot-name collisions, suspended VMs and progress from the old full-clone workflow. It records branch creation for resumption and serializes Setup operations targeting the same VM.
- Dynamic and static environments derive from a common snapshot. Creating the initial branch does not boot the Guest; subsequent provisioning and post-reboot verification remain in place.
- Updated README and GUI guidance. All 68 related regression tests passed. Real-VM end-to-end validation of this same-VM branch workflow has not been completed.

For first installation, extract the entire `r_AKanaly-0.1.8-installer-windows-x64.zip` and run `Setup.exe`. Use a new installation directory when replacing an interrupted full-clone setup. The update ZIP, manifest and signature are for automatic updates. Setup downloads standalone third-party tools from their official sources.
