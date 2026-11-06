"""構築エンジンの非対話入口。GUIと同じ処理を利用する。"""
import argparse
import getpass
import json
from pathlib import Path
from .launcher import install_release
from .setup_engine import SetupEngine
from .storage import installation_lock

# 認証値は対話入力し、構築計画ファイルへ含めない。
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan',required=True)
    parser.add_argument('--release',required=True)
    parser.add_argument('--trust',required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    plan=json.loads(Path(args.plan).read_text(encoding='utf-8'))
    if any('password' in key.lower() for key in plan):
        raise ValueError('Do not put passwords in the plan')
    if not args.apply:
        print(json.dumps({'operation':'setup','plan':plan,'applied':False},ensure_ascii=False,indent=2))
        return
    trust=json.loads(Path(args.trust).read_text(encoding='utf-8'))
    secret={'guest_password':getpass.getpass('Guest password: '),'vm_password':getpass.getpass('VM encryption password (empty if none): ')}
    with installation_lock(plan['install_dir']):
        manifest=install_release(plan['install_dir'],args.release,trust['public_key'])
    SetupEngine(plan,secret,manifest).apply()

if __name__=='__main__': main()
