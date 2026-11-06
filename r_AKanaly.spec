# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_all
from pathlib import Path
import sys

project_root = Path(SPECPATH)
# 他PJのSDKを更新せず導入した製品専用ランタイムを、配布exeにも同じ版で収集する。
product_runtime = project_root / 'tools_runtime/codex_product_runtime'
if product_runtime.is_dir():
    sys.path.insert(0, str(product_runtime))


# 関数内で動的importされるCodex SDK本体と同梱CLIを明示的に収集します。
sdk_datas, sdk_binaries, sdk_hiddenimports = collect_all('openai_codex')
cli_datas, cli_binaries, cli_hiddenimports = collect_all('codex_cli_bin')
# 製品一覧を共通化し、検証ツールを混入させずHook資材も同梱する。
sys.path.insert(0, str(project_root))
from deployment.payload import product_datas
guest_datas = product_datas(project_root)
guest_datas += [(str(project_root / 'VMWARE_GUEST_CONTROL_PACKAGE/runtime/guest-transfer.zip'), 'VMWARE_GUEST_CONTROL_PACKAGE/runtime'),
                (str(project_root / 'prompts'), 'prompts')]

# Sysinternalsは再配布せず、Setupが利用者環境で公式配布元から取得する。
guest_datas += [(str(project_root / 'md/technical/tui_help.md'), 'md/technical')]

main_a = Analysis(
    ['r_akanaly.py'],
    pathex=[str(product_runtime), str(project_root / 'VMWARE_GUEST_CONTROL_PACKAGE/host'), str(project_root / 'VMWARE_GUEST_CONTROL_PACKAGE/tools')],
    binaries=sdk_binaries + cli_binaries,
    datas=sdk_datas + cli_datas + guest_datas,
    hiddenimports=sdk_hiddenimports + cli_hiddenimports + ['analysis_mcp_server', 'bridge_service', 'bridge_client', 'vm_guest_control', 'vm_analysis', 'dynamic_analysis', 'dynamic_evidence', 'dynamic_vm', 'dynamic_llm', 'vm_screen_recorder', 'console_input', 'console_lifecycle', 'visual_controller', 'Evtx.Evtx'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
main_pyz = PYZ(main_a.pure)

main_exe = EXE(
    main_pyz,
    main_a.scripts,
    main_a.binaries,
    main_a.datas,
    [],
    name='r_AKanaly',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)


# Codex Hookから独立して起動できるmalware guard専用EXEを生成します。
guard_a = Analysis(
    ['hookrules/hooks/malware_guard.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
guard_pyz = PYZ(guard_a.pure)

guard_exe = EXE(
    guard_pyz,
    guard_a.scripts,
    guard_a.binaries,
    guard_a.datas,
    [],
    name='r_AKanaly_guard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)


# Ghidra Javaスクリプトを内包したMCPサーバー専用EXEを生成します。
mcp_script_datas = [
    ('ghidra-mcp-ghidra-headless/ghidra_scripts', 'ghidra_scripts'),
]
mcp_a = Analysis(
    ['ghidra-mcp-ghidra-headless/ghidra_mcp_server.py'],
    pathex=[],
    binaries=[],
    datas=mcp_script_datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
mcp_pyz = PYZ(mcp_a.pure)

mcp_exe = EXE(
    mcp_pyz,
    mcp_a.scripts,
    mcp_a.binaries,
    mcp_a.datas,
    [],
    name='r_AKanaly_ghidra_mcp',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
