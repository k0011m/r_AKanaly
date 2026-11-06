"""ログオン時に固定配置から今回の対話Agentだけを起動する。"""
import argparse
import json
import subprocess
import time
from pathlib import Path
from analysis_runtime import SingleInstance


# 起動時に前回のrunを実行しないよう、有効期限と終了マーカーを検査する。
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    args = parser.parse_args()
    root = Path(args.root)
    lock = SingleInstance('LifecycleLauncher')
    child = None
    current = None
    try:
        while True:
            try:
                active = json.loads((root / 'recovery-active.json').read_text(encoding='utf-8-sig'))
                run = root / 'runs' / active['analysis_id']
                enabled = (active.get('enabled') is True and active.get('interactive') is True
                           and time.time() < active['expires_utc'])
                if enabled and not (run / 'recovery-closed.json').exists() and (child is None or child.poll() is not None):
                    target = Path(active['agent_root'])
                    # 実行ファイルは固定配置からだけ選び、検体・任意コマンドを起動しない。
                    if target.resolve().parent != (root / 'agents').resolve():
                        raise ValueError('Unexpected agent root')
                    child = subprocess.Popen([str(root / 'agent/runtime/python.exe'),
                        str(root / 'agent/code/analysis_agent.py'), '--role', 'os', '--root', str(target), '--keep-awake'],
                        creationflags=subprocess.CREATE_NO_WINDOW)
                    current = active['analysis_id']
                elif child and child.poll() is None and (not enabled or current != active['analysis_id']):
                    child.terminate()
                    child.wait(timeout=10)
                    child = None
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(2)
    finally:
        lock.close()


if __name__ == '__main__':
    main()
