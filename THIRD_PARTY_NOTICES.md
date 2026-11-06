# Third-party software / 第三者ソフトウェア

r_AKanalyの非商用ライセンスは独自部分だけに適用します。以下の第三者部分の利用・改変・再配布の権利を制限しません。各資材内の著作権表示・LICENSE・NOTICEを保持してください。

The r_AKanaly license applies only to original r_AKanaly components. Third-party components retain their own licenses and rights. Preserve their copyright, LICENSE and NOTICE files.

| Component | License / distribution handling |
| --- | --- |
| Process Monitor 4.13 / Sysmon 15.22 | Microsoft Sysinternals terms. **Not redistributed.** Setup asks for consent, downloads from Microsoft, and checks pinned hashes and Microsoft Authenticode signatures. |
| Ghidra 12.1.3 / PyGhidra | Ghidra is downloaded from the official NSA GitHub release by Setup; not mirrored in this release. PyGhidra Python bindings remain runtime dependencies. |
| Eclipse Temurin JDK 21.0.12.1+1 | Downloaded from Adoptium by Setup; not redistributed. Original notices are retained when installed. |
| Detect It Easy 3.21 / Qt | Downloaded from the official DIE-engine release by Setup; neither the tool nor its Qt DLLs are mirrored here. |
| FLOSS 3.1.1 / capa 9.4.0 | Downloaded from the official Mandiant releases by Setup; not redistributed. |
| ILSpy / ilspycmd 11.0 | Downloaded from official ICSharpCode GitHub / NuGet by Setup; not redistributed. |
| .NET runtime 10.0.12 | Downloaded from Microsoft by Setup; not redistributed. |
| Python and Python packages | PSF, MIT, Apache, BSD and individual package licenses. Guest runtime licenses are retained. Additional Host/build-environment license texts are supplied under `third_party_licenses/python-packages` (a superset, not a claim that all those packages are used). |
| PyInstaller | GPL with an exception permitting distribution of applications under their own license; license and exception are included with the collected package notices. |
| Codex CLI / SDK | Upstream license texts are retained with collected package notices. Account/service terms are separate; this package does not supply an account or credentials. |

## External tools / 外部取得するツール

独立した解析ツールとJava/.NETはGitHubのr_AKanaly配布物に同梱しません。Setupが署名済み`guest-downloads.json`の公式URL・固定版・サイズ・SHA-256で取得・照合し、利用者のHost内でGuest転送資材を構築します。Guestのインターネット接続は不要です。Pythonなど本体とAgentの実行ライブラリは同梱します。

Setup downloads independent tools directly from their official upstream sources. Version, size and SHA-256 are pinned in the signed release. Tool source archives are no longer mirrored as release assets. Original upstream licenses and notices remain in the downloaded archives. Bundled application runtime dependencies retain their license notices.

## Official references

- Sysinternals: https://learn.microsoft.com/en-us/sysinternals/license-faq
- Terms: https://learn.microsoft.com/en-us/sysinternals/license-terms
- Ghidra: https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.1.3_build
- Temurin: https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1
- Qt: https://download.qt.io/archive/qt/5.15/5.15.2/single/
- DIE: https://github.com/horsicq/DIE-engine/tree/3.21
- FLOSS: https://github.com/mandiant/flare-floss/tree/v3.1.1
- capa: https://github.com/mandiant/capa/tree/v9.4.0
- ILSpy: https://github.com/icsharpcode/ILSpy/tree/v11.0

2026-11-06: Checked official redistribution terms, removed Sysinternals binaries from release ZIPs and frozen executables, supplemented missing license/NOTICE texts, and prepared source assets. This records the technical distribution review, not a third-party legal certification.

2026-11-06: Independent tools moved to official-source downloads; personal build caches and legacy user-specific setup paths removed.
