# r_AKanaly 0.1.9

## 日本語

- Setupの成功画面に、解析用フォルダのパスとCodexの信頼・Hook承認手順を追加しました。
- 案内の確認チェックを入れるまで「閉じる」と右上の「×」では終了できません。チェックは案内の確認のみで、Codex側の承認は別途必要です。
- 初回解析でHookが準備された後、`SessionStart`・`PreToolUse`・`PermissionRequest`を確認して承認してください。承認待ちで停止した場合は同じ設定JSONで解析を実行し直してください。

### ダウンロード

`r_AKanaly-0.1.9-installer-windows-x64.zip`をすべて展開し、その中の`Setup.exe`を使用してください。通常の本体更新では既存のSetup.exeは置き換わらないため、新しい案内を使用する場合はこのインストーラーを取得してください。

更新用ZIP・`release-manifest.json`・`release-manifest.sig`は自動更新用です。`SHA256SUMS.txt`は配布資材の照合用です。

### 検証範囲

日英両方の成功画面、確認チェックによる終了制御、ビルドしたexeの日英7画面の起動を確認しました。本体・Guest資材は0.1.8と同一です。この版での新規VM構築の通し検証は行っていません。

## English

- The successful Setup screen now shows the analysis project path and instructions for trusting the project and approving hooks in Codex.
- Closing through either Close or the title-bar X requires selecting the acknowledgement checkbox. This only acknowledges the instructions; approval in Codex is still required.
- Once your first analysis prepares the hooks, review and approve `SessionStart`, `PreToolUse` and `PermissionRequest`. If analysis stopped awaiting approval, restart it with the same settings JSON.

### Download

Extract the entire `r_AKanaly-0.1.9-installer-windows-x64.zip` and use its `Setup.exe`. Normal application updates do not replace an existing Setup.exe; download this installer to use the updated instructions.

The update ZIP, `release-manifest.json` and `release-manifest.sig` are for automatic updates. Use `SHA256SUMS.txt` to verify the release assets.

### Validation

Checked the Japanese and English completion screens, acknowledgement-based close controls, and all seven screens of the built executable in both languages. Application and Guest binaries are unchanged from 0.1.8. A fresh end-to-end VM setup was not repeated for this release.
