"""速度・応答性の実験入口。既存OSエージェントを置換せず別配置で動く。"""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from contextlib import contextmanager

from analysis_runtime import QueueAgent
from ghidra_operations import GhidraOperations
import production_operations as operations


# 解析CLI・登録済みアプリ・UIAを常駐受付から呼び分ける。
def os_operation(request, root=None):
    action = request['action']
    root = Path(root) if root is not None else Path(__file__).resolve().parent.parent
    if action in ('launch_sample', 'launch_analysis_app', 'process_status', 'stop_process'):
        import dynamic_operations
        return dynamic_operations.operate(request, root)
    if action in ('ui_observe', 'ui_action'):
        import uia_operations
        return uia_operations.operate(request)
    if action == 'extract_zip':
        import analysis_archive
        return analysis_archive.extract(request, root)
    if action in ('observe', 'click', 'type_text', 'press_key'):
        # 既存OS操作実装を同じ常駐受付へ接続し、汎用コマンド実行は追加しない。
        import guest_agent
        return guest_agent.handle_request(request)
    if action == 'tools':
        return json.loads(operations.TOOLS.read_text(encoding='utf-8-sig'))
    if action == 'run_tool':
        return operations.run_tool(request, root)
    if action == 'read_result':
        return operations.read_result(request, root)
    if action == 'launch_registered_app':
        return operations.launch_application(request)
    if action == 'export_artifacts':
        return operations.export_artifacts(request, root)
    if action == 'preflight':
        # 設定変更はせず、既定経路・Defender状態と導入済み環境を読み取る。
        command = "$r=@(Get-NetRoute -ErrorAction Stop | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')}); $d=Get-MpComputerStatus -ErrorAction Stop; @{routes=$r.Count; realtime=$d.RealTimeProtectionEnabled} | ConvertTo-Json -Compress"
        result = subprocess.run([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            '-NoProfile', '-NonInteractive', '-Command', command], capture_output=True, text=True, timeout=30, check=True)
        status = json.loads(result.stdout)
        if status['routes'] or status['realtime']:
            raise RuntimeError('Guest isolation/Defender readiness does not match the analysis snapshot')
        if not Path(r'C:\Users\Public\r_AKanaly\environment.json').is_file():
            raise RuntimeError('Ghidra environment.json missing')
        status['tools'] = operations.check_tools(root)
        return status
    if action == 'delay':
        time.sleep(min(10, max(0, float(request.get('seconds', 1)))))
        return {'completed': True}
    if action == 'fingerprint':
        path = Path(request['path'])
        with path.open('rb') as source:
            digest = hashlib.file_digest(source, 'sha256').hexdigest()
        return {'sha256': digest, 'size': path.stat().st_size}
    raise PermissionError('Operation is not available in benchmark mode')


# Agentが稼働する間だけ自動スリープを抑え、終了時に要求を解除する。電源プランは変更しない。
@contextmanager
def keep_system_awake(enabled):
    if not enabled:
        yield
        return
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    setter = kernel.SetThreadExecutionState
    setter.argtypes = [wintypes.DWORD]
    setter.restype = wintypes.DWORD
    if not setter(0x80000001):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield
    finally:
        setter(0x80000000)


# OS用・Ghidra用のキューとプロセスを分け、同じ共通受付を使う。
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=['os', 'ghidra'], required=True)
    parser.add_argument('--root', required=True)
    parser.add_argument('--environment', default=r'C:\Users\Public\r_AKanaly\environment.json')
    parser.add_argument('--keep-awake', action='store_true')
    args = parser.parse_args()
    # 固定配置のコードと解析ごとの状態ディレクトリを分離する。
    def handle_os(request):
        return os_operation(request, args.root)
    handler = handle_os
    if args.role == 'ghidra':
        environment = json.loads(Path(args.environment).read_text(encoding='utf-8-sig'))
        handler = GhidraOperations(environment, Path(args.root) / 'projects')
    # 静的解析・レポート生成中も保存前に自動サスペンドされないよう稼働中だけ抑止する。
    with keep_system_awake(args.keep_awake or args.role == 'ghidra'):
        QueueAgent(args.root, args.role, handler).run()


if __name__ == '__main__':
    main()
