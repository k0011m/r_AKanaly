"""配布用Pythonの再生成可能なキャッシュだけを除去する。"""
import argparse
from pathlib import Path
import zipfile
import shutil


# 元ソースのないバイトコードを消して実行を壊さないよう、除去前に対応ソースを検査する。
def sanitize(source, target):
    if Path(source).resolve() == Path(target).resolve():
        raise ValueError('Use a separate runtime archive destination')
    with zipfile.ZipFile(source) as src, zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=1) as dst:
        names = set(src.namelist())
        for info in src.infolist():
            if '/__pycache__/' in info.filename and info.filename.endswith('.pyc'):
                folder, name = info.filename.rsplit('/__pycache__/',1)
                if folder+'/'+name.split('.')[0]+'.py' not in names:
                    raise ValueError('Cannot remove sourceless bytecode: '+info.filename)
                continue
            with src.open(info) as input_stream, dst.open(info,'w',force_zip64=True) as output_stream:
                shutil.copyfileobj(input_stream,output_stream,1024*1024)


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('source');parser.add_argument('target')
    args=parser.parse_args()
    sanitize(args.source,args.target)
