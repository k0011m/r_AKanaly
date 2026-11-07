# r_AKanaly 0.1.7

## 日本語

- Windows Pro向けの手動グループポリシー方式を追加しました。選択するとその場で操作案内と起点スナップショット欄を表示します。
- この方式では、リアルタイム保護・動作監視・IOAV・改ざん防止の4項目を読み取り確認します。DisableAntiSpywareの値を必須にせず、設定変更は利用者がGuestで手動で行います。ON・取得不能を成功にしません。
- Setup時、動的解析用スナップショットを保存する前に、Guestのパブリックドキュメント内の`r_AKanaly_ObservationDocuments`へ無害な文書24件（TXT・CSV・RTF・HTML・DOCX・XLSXを各4件）を配置します。追加アプリは不要です。
- 再起動後も文書の一覧とハッシュを確認してから保存点を作成します。解析のたびに生成せず、保存点の復元で戻します。既存の利用者ファイルは上書きしません。
- 元VMと既存保存点を保持する完全クローン方式は維持しています。

初回導入は`r_AKanaly-0.1.7-installer-windows-x64.zip`を全体展開し、`Setup.exe`を起動してください。exe単体では導入できません。アプリ本体の更新だけでは新しいGuest方式や観測文書を配置しないため、必要な場合はSetupでGuestを構築してください。

回帰テストと署名・収録ファイルの照合を実施しています。Windows Pro実VMで新方式を選ぶ新規導入の通し確認は未実施です。

## English

- Added manual Group Policy setup for Windows Pro, with instructions and the baseline snapshot field shown immediately on selection.
- This mode reads four effective states: real-time protection, behavior monitoring, IOAV and Tamper Protection. It does not require a DisableAntiSpyware value or change protection settings automatically. ON or unavailable does not pass.
- During Setup, before saving the dynamic-analysis snapshot, 24 harmless observation documents are placed in `r_AKanaly_ObservationDocuments` under the Guest's Public Documents folder: four each of TXT, CSV, RTF, HTML, DOCX and XLSX. No additional application is required.
- File inventory and hashes are verified after reboot before saving the snapshot. Documents are restored through snapshot restoration, not regenerated for each analysis. Existing user files are not overwritten.
- Full cloning and preservation of the original VM and existing snapshots remain unchanged.

For a new installation, extract the entire `r_AKanaly-0.1.7-installer-windows-x64.zip` and run `Setup.exe`. Do not move the executable alone. Application updates do not provision the new Guest mode or documents; use Setup to construct the Guest when needed.

Regression tests and signature/file-integrity checks are performed. A full new installation using this mode on a real Windows Pro VM has not yet been verified.
