"""本体ビルドとGuest配布を、利用者データを含まないRelease作業領域へまとめる。"""
import argparse
from pathlib import Path
import shutil
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from deployment.payload import AGENT_FILES, HOOK_FILES, require_files

# 新規ディレクトリだけを作り、個人設定・検体・過去の成果物をコピーしない。
def assemble(core,guest,output):
    core,guest,output=Path(core),Path(guest),Path(output)
    inputs=[(core/'r_AKanaly.exe','r_AKanaly_core.exe'),(core/'r_AKanaly_guard.exe','r_AKanaly_guard.exe'),
            (core/'r_AKanaly_ghidra_mcp.exe','r_AKanaly_ghidra_mcp.exe'),
            (guest/'guest.zip','guest.zip'),(guest/'guest-manifest.json','guest-manifest.json'),
            (ROOT/'r_AKanaly_setting.example.json','r_AKanaly_setting.example.json'),
            (ROOT/'LICENSE.md','LICENSE.md'),(ROOT/'LICENSE.en.md','LICENSE.en.md'),
            (ROOT/'README.md','README.md'),(ROOT/'README.en.md','README.en.md'),
            (ROOT/'THIRD_PARTY_NOTICES.md','THIRD_PARTY_NOTICES.md'),
            (ROOT/'deployment/sysinternals-downloads.json','sysinternals-downloads.json'),
            (ROOT/'deployment/guest-downloads.json','guest-downloads.json')]
    for source,_ in inputs:
        if not source.is_file():raise ValueError('Missing release input: '+str(source))
    if output.exists():raise FileExistsError('Use a new payload directory')
    require_files(ROOT, AGENT_FILES + HOOK_FILES)
    output.mkdir(parents=True)
    for source,target in inputs:
        destination=output/target
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,destination)
    shutil.copytree(ROOT/'prompts',output/'prompts')
    shutil.copytree(ROOT/'deployment/third_party_licenses', output/'third_party_licenses')
    for name in AGENT_FILES + HOOK_FILES:
        destination=output/name
        destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(ROOT/name,destination)
    runtime=output/'VMWARE_GUEST_CONTROL_PACKAGE/runtime'
    runtime.mkdir(parents=True)
    shutil.copy2(ROOT/'VMWARE_GUEST_CONTROL_PACKAGE/runtime/guest-transfer.zip',runtime)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('core','guest','output'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();assemble(args.core,args.guest,args.output)
