# r_AKanaly 0.1.4

## 日本語

説明のみの更新です。Setupの手動方式選択時・修正待ちダイアログとREADMEに、Guestでregeditを開き、アドレス欄からPolicies側のキーへ移動する手順を追加しました。変更対象はDisableAntiSpywareだけであり、非Policies側・DisableAntiVirus・その他の値やアクセス許可を変更しないことを明記しました。

Setupの判定・保存点更新・解析処理は0.1.3から変更していません。初回導入には `r_AKanaly-0.1.4-installer-windows-x64.zip` 全体を展開してください。通常の本体更新では既存VMを再構築しません。実VMの手動修正・保存点置換の通し試験は未実施です。

## English

Instructions-only update. Setup's manual-mode selection, repair dialog, and README now explain how to open regedit in the Guest and navigate to the Policies key using the address bar. Only DisableAntiSpyware is to be changed; the non-Policies location, DisableAntiVirus, other values, and permissions must not be modified.

Verification, snapshot replacement, and analysis behavior are unchanged from 0.1.3. Fully extract `r_AKanaly-0.1.4-installer-windows-x64.zip` for installation. A normal application update does not rebuild existing VMs. End-to-end manual repair and snapshot replacement on a real VM remain untested.
