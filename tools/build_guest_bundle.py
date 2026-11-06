"""配布者向け：Agentと実行ライブラリだけのGuest構築パッケージを作る。"""
import argparse
import json
import re
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deployment.storage import atomic_json, digest
from deployment.payload import GUEST_FILES, require_files
ROOT = Path(__file__).resolve().parents[1]

# Windows PowerShell 5.1が日本語をANSI扱いしないよう、PS1はBOM付きUTF-8で配布する。
def copy_guest_source(source, destination):
    source, destination = Path(source), Path(destination)
    if destination.is_dir():
        destination = destination / source.name
    if source.suffix.lower() == '.ps1':
        destination.write_text(source.read_text(encoding='utf-8-sig'), encoding='utf-8-sig')
    else:
        shutil.copy2(source, destination)

# 個人用パスや旧ファイル削除を含まない配布専用の動的セットアップを生成する。
def portable_dynamic(source):
    text = source.read_text(encoding="utf-8-sig")
    # 共有配置先Public以外の個人プロファイルへの依存を公開資材へ持ち込まない。
    if re.search(r'[A-Za-z]:[\\/]+Users[\\/]+(?!Public(?:[\\/]|\b))[^\\/\s\x27\x22]+', text, re.IGNORECASE) or '$SysmonPath' not in text:
        raise ValueError("Portable setup conversion failed")
    return text

# 配布元の資材を変更せず、要求した実行環境とAgentソースだけを梱包する。
def build(assets, output):
    assets, output = Path(assets), Path(output)
    required = ['runtime/python.exe','runtime/pythonw.exe','ghidra-runtime/python.exe']
    missing = [name for name in required if not (assets / name).is_file()]
    if missing:
        raise ValueError('Missing offline assets: ' + ', '.join(missing))
    output.mkdir(parents=True, exist_ok=True)
    # ビルド先と同じ領域で作業し、失敗したZIPを完成品の名前で残さない。
    with tempfile.TemporaryDirectory(prefix='guest-build-', dir=output) as temp:
        staging = Path(temp)
        # 独立ツールはSetupが公式元から取得する。ビルド元パスを含む再生成可能なキャッシュは配布しない。
        for name in ('runtime','ghidra-runtime'):
            if (assets / name).exists():
                shutil.copytree(assets / name, staging / name, ignore=shutil.ignore_patterns('__pycache__'))
        source = ROOT / 'VMWARE_GUEST_CONTROL_PACKAGE/guest'
        require_files(source, GUEST_FILES)
        for folder, patterns in (('agent', ('*.py','uia_worker.ps1')), ('dynamic', ('*.ps1','*.xml','*.wprp'))):
            (staging / folder).mkdir()
            for pattern in patterns:
                for path in (source / name for name in GUEST_FILES if Path(name).match(pattern)):
                    copy_guest_source(path, staging / folder / path.name)
        copy_guest_source(ROOT / 'deployment/guest/provision.ps1', staging)
        copy_guest_source(ROOT / 'deployment/guest/configure_registry.ps1', staging)
        shutil.copy2(ROOT / 'deployment/guest/agent_healthcheck.py', staging)
        shutil.copy2(ROOT / 'tools/guest_install_static_tools.py', staging)
        (staging / 'setup_dynamic_portable.ps1').write_text(portable_dynamic(source / 'setup_dynamic.ps1'), encoding='utf-8-sig')
        pending = staging / 'guest.zip.pending'
        with zipfile.ZipFile(pending, 'w', zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
            for path in staging.rglob('*'):
                if path.is_file() and path != pending:
                    archive.write(path, path.relative_to(staging).as_posix())
        pending.replace(output / 'guest.zip')
    atomic_json(output / 'guest-manifest.json', {'schema':1,'sha256':digest(output / 'guest.zip'),'required_free_bytes':10*1024**3})

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--assets',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    build(args.assets,args.output)
