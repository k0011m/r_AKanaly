# r_AKanaly 0.1.0

## 日本語

Windowsの検体を隔離したVMware Guestで調べ、独自AgentとLLMを組み合わせて表層・動的・静的解析からHTMLレポート作成まで進める初版です。

### インストール

1. `r_AKanaly-0.1.0-installer-windows-x64.zip`をダウンロードして全体を展開します。
2. `Setup.exe`を起動します。Setup.exeだけを別フォルダへ移さないでください。
3. 言語、保存先、VMware・vmrun、解析用VMとGuest資格情報を設定します。
4. SetupがGhidra・Java・DiE・FLOSS・capa・ILSpy/ilspycmd・.NETを公式元から取得し、固定ハッシュで検証して配置します。Procmon・Sysmonは利用規約への同意後、Microsoftから取得します。Pythonなどの実行ライブラリは同梱しています。

Windows x64 Host、VMware Workstation、VMware Tools導入済みWindows x64 Guest、Hostのインターネット接続とCodexの利用環境が必要です。Windows・VMwareのライセンス、VM本体、検体、認証情報は配布物に含めません。

### 更新と署名

本体メニューの「更新」から確認・適用します。更新元は`k0011m/r_AKanaly`、更新manifestには正式Ed25519署名を使用します。Windows Authenticode署名は付けていないため、Windowsの発行元表示とは別です。初版公開前はlatest APIに対象Releaseがありません。

### ライセンス

独自部分は非商用の利用・改変・再配布が無料、商用は事前の書面許可が必要です。OSI定義のOSSライセンスではありません。第三者のライセンスは独立して適用されます。同梱する実行ライブラリの`THIRD_PARTY_NOTICES.md`と`third_party_licenses/`を添付しています。独立した第三者ツール本体・対応ソースはこのReleaseでは再配布しません。再配布時もこれらを保持してください。

### 配布資材

- インストール用ZIP：Setup・ランチャー・正式公開鍵・署名済み解析資材・README・ライセンス。
- `r_AKanaly-0.1.0-windows-x64.zip`、`release-manifest.json`、`release-manifest.sig`：自動更新用。インストール用ZIPとは用途が異なります。
- `guest-downloads.json`（署名済み更新ZIP内）：第三者ツールの公式取得先・バージョン・サイズ・SHA-256。
- `SHA256SUMS.txt`：取得した配布資材の照合用。

### 公開前の検証

- 今回の配布方式変更：8ツールの公式元からの実取得・全ハッシュ照合・Guest転送用ZIP構築に成功。
- 新版の関連35テスト、本体exeの自己診断、凍結Setupの日英7画面描画が成功。
- 配布ZIPと凍結Python内部の既知個人パス検出0件・走査エラー0件。独立ツールは配布目録から除外。
- 外部取得方式で、空のHost配置とAgent未導入の検証VM基点からGUI共通バックエンドによる新規構築・再起動・保存点復元を確認しました。インストール済みexeでwhoami全8工程、HTML生成、証拠読取り／検索43回、原本ハッシュ照合、VM停止、結果ZIP化が成功しました。
- 初回のCodexプロジェクト信頼・Hook承認は利用者の操作が必要です。READMEに手順を記載しています。ETWの一部未復号など、取得ログの制限は解析レポートへ明記しています。
- 公開stable latest経由の通し更新は初版公開後に確認します。

## English

Initial release for analyzing Windows samples in an isolated VMware Guest using dedicated agents and an LLM, with surface, dynamic and static analysis and HTML reports.

Download and fully extract `r_AKanaly-0.1.0-installer-windows-x64.zip`, then run `Setup.exe` from the extracted directory. Requires a Windows x64 Host, VMware Workstation, a Windows x64 Guest with VMware Tools, Internet access on the Host and an available Codex environment. Procmon/Sysmon are downloaded directly from Microsoft after license acceptance; they are not redistributed.

Updates use production Ed25519 manifest signatures and `k0011m/r_AKanaly`. Executables do not have Windows Authenticode publisher signatures. Noncommercial use of original r_AKanaly components is free; commercial use requires prior written permission. Bundled runtime libraries retain their own licenses. Independent tools and their source archives are not mirrored in this release; Setup downloads pinned versions from official upstreams and verifies size and SHA-256.

The revised package passed 35 related tests, the frozen core self-test, Japanese/English Setup screen rendering, and real official-source downloads and hash checks for all eight external tools. Known personal-path matches and archive/code scan errors are zero. A fresh Host installation and Guest provisioning from an agent-free test baseline passed through the GUI-shared backend, including reboot and snapshot restoration checks. The installed executable completed all eight whoami stages, HTML generation, 43 evidence reads/searches, raw-log hash checks, VM shutdown and result archiving. Initial Codex project trust and Hook approval require user action; the README includes instructions. The report documents evidence limitations, including partially undecoded ETW payloads. Public stable latest-release updating remains to be checked after publication.
