# r_AKanaly

**日本語** | [English](README.en.md)

> [!IMPORTANT]
> **まずは公式Webサイトをご覧ください。**
> **[▶ r_AKanalyの詳しい紹介はこちら — r-akanaly.com](https://r-akanaly.com/)**
> このREADMEでは、仕組みの概要と導入・操作手順を説明します。

Windows上で検体の解析を進め、HTMLレポートと解析結果を保存するソフトウェアです。

**バージョン：0.1.5**
ダウンロードと、このバージョンの動作確認範囲・制限事項は[GitHub Releases](https://github.com/k0011m/r_AKanaly/releases)を確認してください。

## r_AKanalyとは

**r_AKanalyは、マルウェア解析ツールと独自開発のVM内常駐エージェントをCodexにつなぎ、検体の調査からHTMLレポート作成までを進めるWindows向けソフトウェアです。**

利用者は検体と解析設定を指定します。r_AKanalyがVMの復元、検体の転送、実行時ログの収集、解析ツールの準備を行い、Codexが得られた情報を基に追加調査とレポート作成を行います。単に検体をLLMへ渡して回答させるのではなく、**CodexがVM内のツールへ調査を依頼し、返ってきた結果を読んで次の調査を選べる**構成です。

Hostはr_AKanalyを起動する利用者のPC、GuestはVM内のWindowsです。検体の動的実行とGhidraによる解析はGuest内で行い、Hostでは進行管理と成果物保存、Codexとの接続を行います。

## 必要な環境

- Windows x64のPC。本配布はx86・ARM向けではありません。
- VMware Workstationとvmrun。
- Windows x64の解析専用VM（`.vmx`）と、Guest内にインストール済みのVMware Tools。
- Guestのユーザー名・パスワードと、Guest内で管理者権限の操作を承認できる環境。暗号化VMでは、VMの暗号化パスワードも必要です。
- Codexを利用できるアカウント・認証済み環境と、利用時のインターネット接続。
- 初回セットアップで外部ツールを取得するための、Hostのインターネット接続。
- VM、保存点、解析結果を保存できる空き容量。

Windows・VMware・Codexの利用権やWindows VM本体は含まれません。VMware Workstationと解析専用のWindows VMを先に用意し、GuestへVMware Toolsをインストールしてください。

Guestで.NET Framework 3.5が有効でない場合は、Guestと同じWindowsビルドのインストールISOをVMのCD/DVDドライブへ1つ接続してください。Setupがそのメディアから必要な機能を導入します。Windowsのインストールメディアは配布物に含まれません。

SetupはGuestの自動ログイン、電源設定、解析用の保護設定、隔離ネットワーク、保存点（スナップショット）を設定します。普段使いのVMは指定せず、構築を開始する前に対象VMをシャットダウンしてください。

Guest保護の設定方式は、手動レジストリ設定（推奨）か、起動後の公式APIによる設定・確認を選択してください。手動方式をプルダウンで選ぶと、その場で注意書きと起点スナップショット欄が表示されます。対象Guestで設定し、再起動後も`DisableAntiSpyware=1`が保持され、Defenderが停止していることを確認してください。その後、Guestをシャットダウンして保存点を作成し、「スナップショット一覧を更新」から選択してください。

Setupは選択した起点を復元・起動し、設定値と保護の実状態を確認してからツール・Agentを配置します。動的・静的環境は、その起点から構築した同じ共通保存点からそれぞれ派生します。既存の別の解析用保存点へ戻って構築を続けることはありません。起点の検証に失敗した場合はGuestを保持します。同じ入力内容で再開すると、復元し直さず再確認します。別の保存点を選ぶ場合は、新しいインストール先を指定してください。

### 手動設定で値が消える場合の推奨確認手順

まず、**対象Guest内だけ**で`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`の`DisableAntiSpyware`をREG_DWORDの`1`として設定し、再起動してください。値が消える場合は、次の手順を試してください。

1. 同じ名前の値をREG_QWORDの`1`として作成し、再起動してください。
2. QWORDが残っていることを確認してから、その値を削除してください。
3. 同じ名前でREG_DWORDの`1`を作り直し、再起動してください。
4. DWORDが保持され、Defenderの実状態もOFFであることを確認した後、Guestをシャットダウンして起点スナップショットを作成してください。

これは利用者の解析用VMで2回再現した手順であり、すべての環境での成功やQWORDを挟むことの効果を保証するものではありません。Hostでは実施しないでください。64ビットWindowsでも最終的な値はREG_DWORDです。Setupは既存REG_QWORDも読み取れますが、値が1という理由だけで成功にせず、再起動後・解析前に保護の実状態を確認します。

手動方式の構築中に保護設定の検証が失敗した場合は、Setupの案内に従ってGuestで設定を修正し、再起動・確認後にシャットダウンしてください。Setupはこの修正のためにレジストリ値を自動で書き換えません。完了後に設定を読み取り、クローンVM内で修正済み状態を新しい名前の保存点へ保存します。既存保存点は削除・上書きしません。

導入成功時にユーザー環境変数`R_AKANALY_HOME`とユーザーPATHへ導入先を登録します。Terminalを開き直して使用してください。設定ファイルは引き続き`current.json`で選択され、JSON内の任意の環境変数表記を自動展開するものではありません。

### 手動で編集する場所と対象

**変更するのは、対象GuestのPolicies側にある`DisableAntiSpyware`だけです。**

1. Guest内で`Win+R`を押し、`regedit`と入力してレジストリエディターを開いてください。
2. 上部のアドレス欄に`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender`を貼り付け、Enterを押してください。
3. 右側の一覧にある`DisableAntiSpyware`を開き、値のデータを`1`にしてください。存在しない場合は、右側の空白部分を右クリックし、［新規］→［DWORD（32ビット）値］で作成してください。名前は`DisableAntiSpyware`、値は`1`にしてください。

**Policiesを含まない同名の場所、`DisableAntiVirus`、その他の値・キー・アクセス許可は作成・変更・削除しないでください。Host側では操作しないでください。** 対象キーが見つからない場合は別の場所を代用せず、入力したパスを確認してください。設定後の再起動・確認・シャットダウンはSetupの案内に従ってください。

**v0.1.5以降の手動方式では、選択した保存点から独立したVMの完全クローンを作成し、クローン側だけを構築します。元VM・元保存点は変更しません。** 「既存VM」を選んだ場合も手動方式では完全クローンを作ります。クローン分の空き容量とコピー時間が必要です。v0.1.3/v0.1.4で失敗したSetupは再実行せず、この版を新しいインストール先で使用してください。旧進捗が元VMを指す場合は、変更せず再開を拒否します。

## インストール

[GitHub Releases](https://github.com/k0011m/r_AKanaly/releases)の添付ファイルから、`r_AKanaly-0.1.5-installer-windows-x64.zip`をダウンロードし、全体を1つのフォルダへ展開してください。`Source code`や、ファイル名に`installer`を含まない更新用ZIPは初回インストール用ではありません。`Setup.exe`だけを別のフォルダへ移さず、次の順に進めてください。

1. `Setup.exe`を開き、日本語または英語を選んでください。
2. 本体の保存先と、レポートなどの保存先を指定してください。
3. 検出されたVMware・vmrun・既存ツールのパスを確認してください。異なる場合は参照ボタンで選び直してください。
4. 使用するVMと、Guestのログイン情報などを指定してください。VMを複製するか、指定したVMを使用するかを選んでください。
5. 確認画面で内容を確認し、セットアップを開始してください。GuestのUAC承認が必要な場合は、VMwareでGuestの画面を開き、表示された要求を確認して承認してください。
6. 完了後、インストール先の`r_AKanaly.exe`を開いてください。

SetupがAgentと解析ツールを配置し、解析用保存点と、そのVMを使う設定JSONを作成します。完了後は、インストール先の本体から解析対象を設定してください。

Ghidra・Java（Temurin JDK）・DiE・FLOSS・capa・ILSpy／ilspycmd・.NETは、Setupが公式配布元からHostへ取得し、指定バージョンのサイズ・SHA-256を照合してからGuestへ配置します。Procmon・Sysmonは、表示される利用規約を確認して同意してください。同意後にMicrosoft公式サイトから取得・検証して配置します。これらの取得のためにGuestをインターネットへ接続する必要はありません。

## 起動とメニュー

`r_AKanaly.exe`を開き、↑／↓とEnterで選んでください。

| 項目 | 内容 |
| --- | --- |
| 実行 | 対象と設定を確認して解析を開始します。 |
| 設定 | 使用中のJSONの場所を確認し、パス・動的解析LLMのON/OFF・指示文を変更します。 |
| ヘルプ | 操作説明を表示します。 |
| 更新 | 本体を終了し、更新画面へ切り替えます。 |
| 終了 | 本体を終了します。 |

## 最初の解析を始める

1. インストール先の`r_AKanaly.exe`を開き、「設定」で表示される「設定JSON」のパスを確認してください。
2. 本体を終了し、そのJSONをメモ帳などで開いてください。下の例から単体ZIP・単体EXE・フォルダの連続解析を選び、必要な項目を変更してください。VMのパスや保存点はSetupの値を維持してください。
3. JSONを保存して本体を開き直し、「実行」を選んでください。対象・VM・保存先を確認してから開始してください。
4. 完了後、画面に表示された保存先でHTMLレポートを確認してください。

**初回はCodex側で解析用フォルダの信頼・Hook承認が必要です。** Setupの完了とは別の操作です。解析中に`SessionStart was not observed`で停止した場合は、次の手順で対応してください。

1. 画面の「Codex PJ」（JSONの`llm.codex_project_dir`）に表示されたフォルダをCodexで開き、信頼してください。
2. Hooks画面で、そのフォルダの`.codex/hooks/r_AKanaly_guard.exe`を使う`SessionStart`・`PreToolUse`・`PermissionRequest`を確認して承認してください。
3. 同じJSONで解析を最初から実行し直してください。

承認待ちで停止したときの`analysis_failed.html`は正常レポートではありません。解析用フォルダやHook定義を変更した場合も、再度承認の確認が必要になることがあります。

## JSON設定の使い方

### まず、編集するファイルを確認してください

**Setupが生成した使用中のJSONを編集してください。サンプルJSONで丸ごと置き換えると、構築済みVMのパスや保存点の設定を失います。**

本体の「設定」画面に表示される「設定JSON」が編集対象です。ZIP内部のファイル名・パスワード・連続解析のON/OFFなどを変更する場合は、本体を終了し、そのファイルをメモ帳などのテキストエディターで開いてください。手動で探す場合は、インストール先の`current.json`を開き、`settings`が示すファイルを確認してください。そのパスはインストール先を基準にします。設定ファイル名は導入ごとに異なるため、別の環境のファイル名をそのまま使わないでください。

- `versions/`内の`r_AKanaly_setting.example.json`は参考用です。解析に使う設定は、`current.json`が参照するファイルを編集してください。
- `current.json`は使用版と設定の参照先です。検体パスなどをそこへ追加しないでください。
- 変更前に設定JSONのコピーを保存し、解析開始前に編集を完了してください。実行途中の変更は進行中の解析へ即時反映されません。

「設定」画面で変更できる項目は、パス、動的解析LLMのON/OFF、指示文です。画面内で編集した場合は`S`で保存してください。`Q`は保存せずに戻ります。

### 記述ルール

- UTF-8形式で保存してください。
- `null`は項目ごとに意味が違います。特にZIPパスワードでは`null`と`""`を区別してください。
- 通常のパスは絶対パスを使ってください。相対パスの基準は項目によって異なります。
- `malware_transfer.host_path`という表記は「`malware_transfer`オブジェクト内の`host_path`」です。ドットを含む新しいキーを作る意味ではありません。

**以下のJSONは変更箇所だけを示した例です。使用中JSONの同名項目へ反映し、掲載していない項目は残してください。ブロックを重複追加したり、設定ファイル全体をこの例だけに置き換えたりしないでください。**

### 1個のZIPを解析する

```json
{
  "malware_transfer": {
    "host_path": "C:/Samples/sample.zip",
    "guest_path": "C:\\Users\\Public\\r_AKanaly\\samples\\sample.exe",
    "zip_member": "payload/sample.exe",
    "zip_password": "",
    "zip_max_uncompressed_bytes": 536870912
  },
  "full_auto": {
    "enabled": false,
    "recursive": true
  }
}
```

| 項目 | 意味・変更ルール |
| --- | --- |
| `host_path` | Host上にあるZIPファイルの絶対パス。|
| `guest_path` | Guest内で検体を配置する**ファイルのフルパス**。ZIPの保存先ではありません。通常はSetupの値を維持してください。 |
| `zip_member` | ZIP内の対象ファイルの相対パス。**単体ZIPでは必須で、EXEが1個でも省略できません。** 上の例はZIP内の`payload`フォルダにある`sample.exe`を選択します。直下にあれば`sample.exe`だけです。 |
| `zip_password` | 下の表のとおり。ここで指定するのはZIPのパスワードです。 |
| `zip_max_uncompressed_bytes` | 展開サイズ上限、単位はバイト。上の値は512MiBです。必要な場合だけ変更してください。 |
| `full_auto.enabled` | 単体解析では`false`。`recursive`は単体解析では使いません。 |

`zip_member`は実際のZIP内の名前と一致させてください。Hostのパスや`../`を含むパスは指定しないでください。ZIP内の目録・ファイル名を確認するだけで、Hostへ検体を取り出す必要はありません。**検体の展開はGuestで行います。** ZIP解析には`static_vm.enabled: true`が必要なので、Setupが設定した値を維持してください。

| ZIPの状態 | `zip_password`の値 | 動作 |
| --- | --- | --- |
| パスワードなし | `""` | 入力を求めず、パスワードなしで処理します。 |
| パスワードを都度入力する | `null` | 開始時に非表示入力を求めます。Enterのみならパスワードなしです。 |
| パスワードが分かっている | `"実際のパスワード"` | 指定値を使います。JSONには平文で残ります。 |

ZIPか直接ファイルかは`host_path`の拡張子で判定します。`.ZIP`もZIPとして扱います。形式を別の項目で指定する必要はありません。アーカイブ入力にはZIPを使用してください。`.7z`と`.rar`は対象外です。

### 1個のEXEを直接解析する

```json
{
  "malware_transfer": {
    "host_path": "C:/Samples/sample.exe",
    "guest_path": "C:\\Users\\Public\\r_AKanaly\\samples\\sample.exe",
    "zip_member": null,
    "zip_password": null
  },
  "full_auto": {
    "enabled": false
  }
}
```

EXE入力ではZIP関連項目を使わないため、この`zip_password: null`によるZIPパスワード入力はありません。直接EXEを指定した場合、**表層情報の取得はHostで行い、検体の動的実行とGhidra解析はGuestで行います。** Hostに未展開のZIPだけを置いて解析したい場合は、前のZIP入力を使用してください。

### フォルダ内の検体を連続解析する

```json
{
  "malware_transfer": {
    "host_path": "C:/Samples/batch",
    "zip_member": null,
    "zip_password": ""
  },
  "full_auto": {
    "enabled": true,
    "recursive": true
  }
}
```

- `host_path`に**フォルダ**を指定してください。中にある`.exe`・`.zip`を開始時に列挙し、順番に解析します。
- `recursive: true`はサブフォルダも対象、`false`は指定フォルダ直下だけです。
- 連続解析のZIPは、**各ZIP内にEXEがちょうど1個**ある必要があります。目録から選択するため、このモードでは設定の`zip_member`を使用しません。EXEが0個または複数なら、そのZIPを入力エラーとして記録します。
- ZIP内の全EXEを順番に解析する機能ではありません。複数EXEの入ったZIPは、単体解析で`zip_member`を指定してください。
- ZIPパスワードはバッチ内で共通です。`null`で入力した値も再利用します。異なるパスワードのZIPは実行を分けてください。
- 検体ごとの失敗を記録して次へ進みます。ただしキャンセル、実行承認前の問題、VMの復旧不能などでは全体を停止します。

### 結果の保存先を変更する

**最終レポートの保存先と、中間データの保存先は別設定です。両方を移す場合は、次のように両方を変更してください。**

```json
{
  "llm": {
    "analysis_output_dir": "D:/AnalysisResults"
  },
  "output_directories": {
    "use_common_output_dir": true,
    "common_output_dir": "D:/AnalysisResults"
  }
}
```

- `llm.analysis_output_dir`：最終レポート・metadataなどを保存する親フォルダ。
- `output_directories.common_output_dir`：共通出力モード時の表層・静的・動的解析の中間データの保存先。これだけ変えても、最終レポートの保存先は変わりません。
- `use_common_output_dir: false`にする場合は、同じブロックの`surface_analysis_output_dir`・`static_analysis_output_dir`・`dynamic_analysis_output_dir`をすべて指定してください。`llm.analysis_output_dir`も別途維持してください。
- 検体ごとに結果が分かれます。入力する検体フォルダと結果の保存先は別にしてください。

### 動的解析でCodexを使うか・何を調べるか

```json
{
  "dynamic_analysis": {
    "execution_timeout_seconds": 300,
    "post_exit_seconds": 10,
    "llm_control": {
      "enabled": true,
      "prompt": "プログラムの表示と生成ファイルを調べ、実際に観測したことと未確認のことを区別してください。",
      "instruction_file": null,
      "max_duration_seconds": 900
    }
  }
}
```

| 項目 | 変更したときの動作 |
| --- | --- |
| `dynamic_analysis.llm_control.enabled` | `true`でCodexが動的調査を操作。`false`では通常の検体実行・ログ収集を行います。**`false`でも、その後の静的解析・レポート生成ではCodexを使用します。** |
| `prompt` | 動的調査への指示文。改行はJSON内で`\n`と書いてください。 |
| `instruction_file` | `prompt: null`のときに読むUTF-8の指示ファイル。相対パスは**使用中の設定JSONがあるフォルダ**を基準にします。 |
| `max_duration_seconds` | LLMによる動的操作の時間枠、単位は秒。 |
| `execution_timeout_seconds` | 通常の検体実行の待機上限、単位は秒。解析全体のタイムアウトではありません。 |
| `post_exit_seconds` | 検体終了後の追加観測時間、単位は秒。 |

独自の調査を依頼する場合は、実行前に`prompt`へ指示を書いてください。ファイルから指示を読む場合は、`prompt`を`null`にして`instruction_file`を指定してください。

`prompt: ""`では標準指示を使い、`instruction_file`は読みません。指示が空、指示ファイルが見つからない、またはLLMによる指示確認に通らなかった場合も標準指示を使います。独自指示が適用されなかった場合は、記録された理由を確認してください。

動的調査の時間枠を変えるときは、`finalize_timeout_seconds`・`transfer_timeout_seconds`・`conversion_timeout_seconds`と混同しないでください。これらはそれぞれ収集終了・転送・Host変換の待機上限です。上記の秒数は正の整数で指定してください。

### 定期スクリーンショットを結果に残す

```json
{
  "dynamic_analysis": {
    "llm_control": {
      "screenshot_recording_enabled": true,
      "screenshot_interval_seconds": 10,
      "screenshot_output_dir": "{analysis_dir}/dynamic_screenshots"
    }
  }
}
```

10秒ごとに動的解析の画面を保存する例です。`{analysis_dir}`はその検体の結果フォルダに置き換わります。この記録はユーザーの後確認用で、自動的にCodexへ渡す画像とは別です。`llm_control.enabled: false`でも定期記録は利用できます。

### 通常はSetupの値を維持する項目

| 項目 | 役割 |
| --- | --- |
| `vmware.vmrun_path` / `vmware.vmx_path` | Hostのvmrunと操作対象VM。 |
| `vmware.snapshot_name` | 動的解析前に復元する保存点。 |
| `static_vm.snapshot_name` | 表層・静的解析で使う保存点。動的解析用とは別です。 |
| `static_vm.guest_root` / `static_vm.guest_python` | Guest側AgentとPythonの配置先。 |
| `static_vm.security_strategy` / `dynamic_analysis.require_defender_disabled` | Setupで構築したGuest準備・確認方式との対応。 |
| `dynamic_analysis.guest_root` / `dynamic_analysis.task_name` / `dynamic_analysis.sample_task_name` | Guest側ロガーと登録済みタスク。 |
| `dynamic_analysis.host_procmon_path` | Hostのログ変換用Procmon。Setupが取得・検証したパスを使用します。 |
| `guest.username` / `credentials.env_file_path` | Guest接続設定。インストール版では資格情報をDPAPIで保存し、通常`env_file_path`は`null`です。VMのパスワードをZIPパスワード欄に入れないでください。 |
| `llm.codex_project_dir` | Codexの解析用作業場所。レポート保存先ではありません。変更するとHook承認の確認が必要になる場合があります。 |
| `codex_malware_guard` | Host側の操作制限。検体を替えるために変更する項目ではありません。 |

追加で、`llm.language`はレポート言語、`llm.model`・`llm.reasoning_effort`は利用するモデルと推論設定、`static_analysis.yara_rule_path`は任意のYARAルールを指定する項目です。モデルの利用可否は使用中のCodex環境に依存します。0.1.5の通常運用では`llm.report_format`は`"html"`を維持してください。

### 保存して、実行前に確認してください

1. 使用中のJSONへ変更を保存してください。
2. インストール先でPowerShellを開き、設定確認を行ってください。

```powershell
.\r_AKanaly.exe --dry-run
```

別名でコピーした設定を試す場合は、ファイルを実際に保存してから次のように指定できます。この指定はその起動だけに適用され、通常起動の`current.json`を書き換えません。

```powershell
.\r_AKanaly.exe --settings ".\config\my-analysis.json" --dry-run
```

3. 「実行」時の最終確認で、単体か連続か・検体・ZIP内部パス・VM・保存先を確認してください。動的解析ではGuest内で検体を実行します。

`--dry-run`は設定の事前確認であり、実際のGuest接続、ZIPの復号・展開、ツール実行や解析完了を保証するものではありません。未知キーの扱いはブロックごとに異なり、誤字が必ずエラーになるわけではないため、キー名を正確に記述してください。

## 結果の確認

終了画面に表示された保存先を開いてください。結果がZIPの場合は展開し、中のHTMLレポートをブラウザーで開いてください。レポート生成の成否と各工程の結果は別々に表示されます。HTMLレポートの生成成功だけで、検体のすべての挙動が確認できたことを意味するものではありません。

正常なHTMLレポートが結果フォルダ内に保存されたことを確認すると、結果をパスワードなしのZIPへまとめ、内容のハッシュを照合してから元の結果フォルダを削除します。連続解析でも1件ごとに行います。この自動ZIP化はJSON設定では無効にできません。レポート未生成やZIP化・照合の失敗時は、通常の完了ZIPができたと判断せず、画面と残存ログを確認してください。

## 更新

本体メニューの「更新」を選ぶと、本体が終了して更新画面が開き、現在のバージョンと取得可能なバージョンを表示します。「更新する」を選んだ場合だけ取得・検証・適用します。結果画面からEnterで本体へ戻れます。

更新元は公開リポジトリ`k0011m/r_AKanaly`です。正式Ed25519署名を検証して更新します。通信できない、公開Releaseがない、または更新ファイルを検証できない場合は更新しません。

## 困ったとき

- 起動や解析に失敗した場合は、画面の工程名・エラー・結果の保存先を確認してください。
- VMのパス、ログイン情報、VMware Toolsの動作を確認してください。
- 更新できない場合は、更新画面のエラーを記録してください。
- 問い合わせ時は使用バージョンと再現手順を添えてください。パスワード、認証情報、検体そのものは添付しないでください。

## 独自エージェントは何をするのか

ここでいう「エージェント」は、VM内で待機してコマンドを受け取るプログラムです。エージェント自身がLLMとして考えるのではなく、調査の判断をするCodexと、実際に動く解析ツールの間をつなぎます。

- **Guest OS Agent**：プロセスやウィンドウの情報取得、アプリの起動、ZIP展開、画面取得、UI操作などを担当します。動的解析でCodexによる操作を有効にすると、Codexは公開された操作を使ってVM内の調査を進められます。
- **Ghidra解析Agent**：VM内のGhidraを常駐させ、解析済みプログラムに対する問い合わせを受け付けます。関数一覧、デコンパイル結果、呼び出し関係などを返すため、Codexは調べたい箇所を指定して繰り返し確認できます。
- **Host側のブリッジ**：Codexからの依頼をVMへ届け、Agentが返した結果をCodexへ渡します。MCP（LLMが外部ツールを呼び出すための接続方式）を操作窓口とし、VMwareのGuest OperationsでVM内外の指示・結果を受け渡します。

たとえばCodexが「この関数がファイルを書き換える条件を確認したい」と判断した場合、対象関数のデコンパイルを要求します。ブリッジがVMへ依頼を送り、Ghidra解析Agentが結果を返します。Codexはその内容を読み、呼び出し元を追加で調べたり、実行時ログに記録された書込みと照合したりします。

```text
利用者：検体と解析条件を指定
  ↓
r_AKanaly：VM復元・準備・検体転送・ログ収集を進行
  ↓
Codex：調査する内容を選ぶ
  ⇅ MCP / Host側ブリッジ / VMware Guest Operations
VM内の独自エージェント：依頼された操作を実行し、結果を返す
  ⇅
Ghidraなどの解析ツール・Guest OS
  ↓
Codex：調査結果と観測ログを照合し、レポートを作成
```

## 解析はどの順番で進むのか

1. **ファイルの基本情報を調べる**：EXEまたはZIPを指定します。ZIPはGuest側で展開して調べます。EXEを直接指定した場合の基本情報取得はHost側で行います。
2. **動的解析用VMを準備する**：保存点へ復元し、Agent・ロガーなどの準備を確認してから検体を配置します。
3. **検体を実行して挙動を記録する**：Sysmon、Process Monitor、ETWなどで、プロセス起動、ファイル操作、レジストリ変更などを記録します。Codexによる動的操作は設定でON/OFFできます。
4. **原本ログを回収する**：Hostへ転送し、ハッシュを照合してから読み取り用データへ変換します。
5. **静的解析と追加調査を行う**：静的解析用の保存点へ切り替え、Codexが独自エージェントを通じてGhidraなどを操作します。コードの処理と動的解析で観測した挙動を照合します。
6. **HTMLレポートと成果物を保存する**：何が確認できたか、その根拠は何か、未確認の点は何かをまとめます。工程ごとの失敗も別に記録します。

コードから読み取れる処理と、実行して観測した挙動は同じとは限りません。r_AKanalyは両方を調査材料として扱いますが、すべての挙動を必ず観測できるわけではありません。実行条件や観測時間による制限も含めてレポートを確認してください。

## ライセンスと外部ソフトウェア

**非商用なら、利用・改変・再配布は無料です。商用利用は、原版・改変版ともに事前の書面による許可が必要です。** 有償サービスへの組込みや企業の営利事業を支える社内業務も商用利用に含みます。改変ソースの公開義務はありません。再配布時は著作権表示・ライセンスを保持し、改変を明示してください。

条件全文：[r_AKanaly 非商用利用ライセンス 1.0](LICENSE.md)。商用利用の申請先：[rk01mwork@gmail.com](mailto:rk01mwork@gmail.com)。商用の許可範囲・料金は個別に合意します。

同梱または連携する外部ソフトウェアには、それぞれのライセンスが適用されます。[第三者ソフトウェアの表示](THIRD_PARTY_NOTICES.md)を確認してください。

Ghidra・Java・DiE・FLOSS・capa・ILSpy／ilspycmd・.NET・Procmon・Sysmonは配布物に同梱せず、Setupが各公式配布元から取得します。Pythonなど、本体とAgentに必要な実行ライブラリは同梱します。初回セットアップにはHostのインターネット接続が必要です。取得した配布物が登録済みのサイズ・ハッシュと一致しない場合、Setupは配置を停止します。表示されたエラーを確認し、更新されたSetup／配布資材を使用してください。

