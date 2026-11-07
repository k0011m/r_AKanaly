# r_AKanaly 0.1.10

## 日本語

- READMEの冒頭に、解析用Guest OSはWindows Pro推奨と大きく表示しました。Host側にはWindows Proを必須としません。
- Setupの「Windows Pro：手動グループポリシー設定」と手順の見出しを「最推奨」にしました。日英両方に反映しています。
- 方式の既定値、設定処理、状態確認の条件は変更していません。0.1.9のHook案内と確認チェックによる終了制御も含みます。

### ダウンロード

`r_AKanaly-0.1.10-installer-windows-x64.zip`をすべて展開し、その中の`Setup.exe`を使用してください。通常の本体更新では既存のSetup.exeは置き換わりません。

更新用ZIP・`release-manifest.json`・`release-manifest.sig`は自動更新用です。`SHA256SUMS.txt`は配布資材の照合用です。

### 検証範囲

ビルドしたSetup.exeの日英7画面の起動を確認しています。本体・Guest資材は0.1.9と同一です。この版でVM構築の通し検証は再実施していません。

## English

- The README now prominently recommends Windows Pro for the analysis Guest. Windows Pro is not required on the Host.
- Setup labels the Windows Pro manual Group Policy option and its instruction heading as “most recommended” in both languages.
- Default selection, configuration behavior and verification conditions are unchanged. The hook instructions and acknowledgement-based close controls from 0.1.9 are included.

### Download

Extract the entire `r_AKanaly-0.1.10-installer-windows-x64.zip` and use its `Setup.exe`. Normal application updates do not replace an existing Setup.exe.

The update ZIP, `release-manifest.json` and `release-manifest.sig` are for automatic updates. Use `SHA256SUMS.txt` to verify the release assets.

### Validation

All seven screens of the built Setup.exe were checked in Japanese and English. Application and Guest binaries are unchanged from 0.1.9. End-to-end VM provisioning was not repeated for this release.
