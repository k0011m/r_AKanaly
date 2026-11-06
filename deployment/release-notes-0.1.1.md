# r_AKanaly 0.1.1

## 日本語

### 変更内容

- READMEとSetupの最初の画面に、解析用Guest OSとしてWindows 11 25H2を推奨する案内を追加しました。

- SetupでGuest保護の設定方法を選択できます。手動レジストリ設定（推奨）では、途中に対象Guestの操作と再起動の案内を表示し、操作後に保護の実状態を確認します。公式APIによる設定・確認も選択できます。
- 手動操作の待機・再開に対応し、セットアップ中のアニメーションと工程の進捗バーを追加しました。
- REG_DWORDと既存REG_QWORDの読取りに対応しました。OSが64ビットでもQWORDが必要という意味ではありません。新規作成にはREG_DWORDを使用してください。型や値だけで保護の無効化を判断せず、手動方式では再起動後・検体投入前の実状態を確認します。
- READMEの日英版に手動設定の案内を追加しました。

### インストール・更新

新規導入では`r_AKanaly-0.1.1-installer-windows-x64.zip`を全体展開し、同じフォルダ内の`Setup.exe`を起動してください。既存環境では本体メニューの「更新」を使用してください。既存の設定方式は更新だけでは自動変更されません。手動方式への変更にはSetupでの環境構築が必要です。

Windows x64 Host、VMware Workstation、VMware Tools導入済みWindows x64 Guest、Hostのインターネット接続とCodexの利用環境が必要です。独立した解析ツールはSetupが公式配布元から取得・検証します。VM本体・検体・認証情報は同梱しません。

更新資材の検証にはEd25519署名を使用します。Windows Authenticode署名とは異なります。独自部分は非商用の利用・改変・再配布が無料、商用は事前の書面許可が必要です。詳細はREADMEとLICENSEを確認してください。

### 確認範囲

手動方式の新規構築・保存点復元と、インストール済み本体によるwhoamiの全8工程、HTML生成、証拠ログの読取り、VM停止、結果ZIP化を確認しました。REG_DWORDの実VM検証に加え、REG_QWORD・不正型・保護ON・状態欠落を含む模擬判定と関連38テストを実施しています。REG_QWORDをWindowsが保護ポリシーとして適用することは保証しません。

## English

### Changes

- README and the initial Setup screen recommend Windows 11 25H2 for the analysis Guest OS.

- Setup now offers manual Guest registry setup (recommended) or configuration and verification through official APIs. Manual setup guides you through Guest-only changes and a restart, then verifies effective protection state.
- Added manual-action pause/resume support, an activity animation, and phase progress.
- Added support for reading REG_DWORD and existing REG_QWORD values. A 64-bit OS does not require QWORD. Please use REG_DWORD for new values. Manual mode verifies effective state after restart and before sample transfer/execution rather than relying on registry values alone.
- Updated the Japanese and English README instructions.

### Install or update

For a new installation, fully extract `r_AKanaly-0.1.1-installer-windows-x64.zip` and run `Setup.exe` from that folder. For existing installations, use the application's Update menu. Updating does not automatically change the existing protection strategy; selecting manual mode requires environment setup through Setup.

Requires a Windows x64 Host, VMware Workstation, a Windows x64 Guest with VMware Tools, Host Internet access, and an available Codex environment. Setup downloads and verifies independent analysis tools from their official upstreams. VMs, samples, and credentials are not bundled.

Update assets use Ed25519 signatures, not Windows Authenticode signatures. Noncommercial use, modification, and redistribution of original components are free; commercial use requires prior written permission. Please read README and LICENSE.

### Verification

Manual-mode provisioning, snapshot restoration, all eight installed whoami analysis stages, HTML generation, evidence access, VM shutdown, and result ZIP creation passed. In addition to real-VM REG_DWORD verification, 38 related tests include simulated REG_QWORD, invalid-type, protection-enabled, and missing-state cases. Windows applying REG_QWORD as a protection policy is not guaranteed.
