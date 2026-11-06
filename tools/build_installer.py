"""配布用ランチャーとGUIを独立exeにビルドする。"""
import argparse
from pathlib import Path
import struct
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]

# PNGを変更せずWindowsアイコンコンテナーへ収める。
def make_icon(source,target):
    data=Path(source).read_bytes()
    width,height=struct.unpack('>II',data[16:24])
    if not (0<width<=256 and 0<height<=256):
        raise ValueError('Icon PNG must be <=256 pixels')
    Path(target).parent.mkdir(parents=True,exist_ok=True)
    Path(target).write_bytes(struct.pack('<HHH',0,1,1)+struct.pack('<BBBBHHII',width%256,height%256,0,0,1,32,len(data),22)+data)

# ビルド成果物をdist/installerへ分け、PJ直下の解析exeを置換しない。
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--clean',action='store_true');args=parser.parse_args()
    output=ROOT/'dist/installer'
    icon=ROOT/'build/installer/icon.ico'
    make_icon(ROOT/'deployment/assets/icon.png',icon)
    for name,entry,gui in (('r_AKanaly','launcher_main.py',False),('Setup','setup_main.py',True)):
        command=[sys.executable,'-m','PyInstaller','--noconfirm','--onefile','--name',name,'--distpath',str(output),'--workpath',str(ROOT/'build/installer'/name),'--specpath',str(ROOT/'build/installer'),'--icon',str(icon),'--paths',str(ROOT)]
        if args.clean: command+=['--clean']
        if gui:
            command+=['--windowed','--add-data',str(ROOT/'deployment/assets')+';deployment/assets']
        command+=[str(ROOT/entry)]
        subprocess.run(command,cwd=ROOT,check=True)

if __name__=='__main__':
    main()
