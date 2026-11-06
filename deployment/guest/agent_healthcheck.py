"""OS/Ghidra常駐Agentを無害なWindowsバイナリで照会する導入検証。"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

# 一意な要求をキューに投入し、同じIDの応答だけを採用する。
def request(root, role, action, child=None, **values):
    identity=uuid.uuid4().hex
    queue=root/role/'queue'
    queue.mkdir(parents=True,exist_ok=True)
    payload=dict(action=action,request_id=identity,analysis_id=root.name,**values)
    temporary=queue/(identity+'.tmp')
    temporary.write_text(json.dumps(payload),encoding='utf-8')
    temporary.replace(queue/(identity+'.json'))
    response=root/role/'responses'/(identity+'.json')
    deadline=time.monotonic()+420
    while time.monotonic()<deadline:
        if child is not None and child.poll() is not None:
            log=root/(role+'.log')
            detail=log.read_text(encoding='utf-8',errors='replace')[-4096:] if log.exists() else ''
            raise RuntimeError('Agent exited before response: '+role+' (exit '+str(child.returncode)+'): '+detail)
        if response.is_file():
            result=json.loads(response.read_text(encoding='utf-8'))
            if result['request_id']!=identity or not result.get('ok'):
                raise RuntimeError('Agent request failed: '+action)
            return result['result']
        time.sleep(.1)
    raise TimeoutError('Agent response timed out: '+action)

# 本番キューとは別のディレクトリで検証し、自分が起動したプロセスだけを終了する。
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--python',required=True)
    parser.add_argument('--code',required=True)
    parser.add_argument('--static',action='store_true')
    args=parser.parse_args()
    root=Path(r'C:\Users\Public\r_AKanaly\installer\probes')/uuid.uuid4().hex
    root.mkdir(parents=True)
    children=[]
    logs=[]
    results={}
    try:
        for role in (('os','ghidra') if args.static else ('os',)):
            # 子の異常終了を待ち時間切れと混同しないよう、起動出力を役割別に残す。
            log=(root/(role+'.log')).open('wb')
            logs.append(log)
            children.append(subprocess.Popen([args.python,str(Path(args.code)/'analysis_agent.py'),'--role',role,'--root',str(root)],stdout=log,stderr=subprocess.STDOUT,creationflags=subprocess.CREATE_NO_WINDOW))
            results[role]=request(root,role,'health',child=children[-1])
        if args.static:
            sample=str(Path(os.environ['WINDIR'])/'System32/whoami.exe')
            results['open']=request(root,'ghidra','open',child=children[-1],sample_path=sample,project='setup_probe')
            results['functions']=request(root,'ghidra','functions',child=children[-1],limit=3)
            results['save']=request(root,'ghidra','save_close',child=children[-1])
        (root/'verified.json').write_text(json.dumps(results),encoding='utf-8')
        print(json.dumps({'complete':True,'results':results}))
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=30)
        for log in logs:
            log.close()

if __name__=='__main__':main()
