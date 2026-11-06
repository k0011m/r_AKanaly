"""静的解析実験用の共通受付。既存GUI操作の受付とは分離する。"""
import ctypes
import hashlib
import json
import os
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


# 書込み途中のJSONを応答側に見せない。
def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    temporary.replace(path)


# 同じ配置先・役割のプロセスだけを一つに制限する。
class SingleInstance:
    # HANDLEを64bitのまま保持して誤判定を防ぐ。
    def __init__(self, name):
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.kernel.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        self.kernel.CreateMutexW.restype = ctypes.c_void_p
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        # ログオンタスク(Session 1)とGuest Operations(Session 0)で同じキューを奪い合わない。
        ctypes.set_last_error(0)
        self.handle = self.kernel.CreateMutexW(None, False, 'Global\\r_AKanaly_' + name)
        error = ctypes.get_last_error()
        if not self.handle or error == 183:
            if self.handle:
                self.kernel.CloseHandle(self.handle)
            raise RuntimeError('Agent already running or mutex unavailable')

    # 正常終了時にもMutexの参照を解放する。
    def close(self):
        self.kernel.CloseHandle(self.handle)


# 長時間処理を単一ワーカーへ分離し、healthの受付を止めない。
class QueueAgent:
    # 再起動時の実行中要求は再実行せず、結果不明として記録する。
    def __init__(self, root, role, handler):
        self.root = Path(root) / role
        self.role, self.handler = role, handler
        self.generation = uuid.uuid4().hex
        self.pending = {}
        self.executor = ThreadPoolExecutor(max_workers=1)
        for name in ('queue', 'accepted', 'responses', 'secrets'):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    # Mutex取得後だけ中断記録を回復し、二重起動側が稼働中要求を書き換えない。
    def recover(self):
        # 固定配置の動的Agentは起動区間を保存し、未受付キューも再起動後には再実行しない。
        lifecycle = self.root.parent.parent.parent / 'lifecycle-status.json'
        if lifecycle.is_file():
            current_boot = json.loads(lifecycle.read_text(encoding='utf-8-sig')).get('boot_id')
            boot_file = self.root / 'boot.json'
            previous_boot = json.loads(boot_file.read_text(encoding='utf-8')).get('boot_id') if boot_file.exists() else None
            if previous_boot and previous_boot != current_boot:
                for path in (self.root / 'queue').glob('*.json'):
                    request = json.loads(path.read_text(encoding='utf-8'))
                    identity = {'request_id': request['request_id'], 'analysis_id': request['analysis_id'],
                                'digest': hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()}
                    write_json(self.root / 'accepted' / path.name, identity)
                    write_json(self.root / 'responses' / path.name, dict(identity, ok=False, error='InterruptedOutcomeUnknown'))
                    path.unlink()
                for path in (self.root.parent / 'jobs').glob('*/status.json'):
                    status = json.loads(path.read_text(encoding='utf-8'))
                    if status.get('state') in ('running', 'launch_pending'):
                        status.update(state='interrupted', outcome='unknown_after_reboot', previous_boot=previous_boot)
                        write_json(path, status)
            write_json(boot_file, {'boot_id': current_boot})
        # 再起動前の一時秘密は再実行用に残さず、UUID名の配送ファイルだけを片付ける。
        for path in (self.root / 'secrets').glob('*.json'):
            try:
                uuid.UUID(path.stem)
            except ValueError:
                continue
            path.unlink()
        for path in (self.root / 'accepted').glob('*.json'):
            record = json.loads(path.read_text(encoding='utf-8'))
            response = self.root / 'responses' / path.name
            if not response.exists():
                write_json(response, dict(record, ok=False, error='InterruptedOutcomeUnknown'))

    # 小さな確認要求は重い解析ワーカーを待たず返す。
    def health(self):
        return {'role': self.role, 'pid': os.getpid(), 'generation': self.generation,
                'pending': len(self.pending), 'ready': True}

    # 例外も要求IDに対応する応答として保存する。
    def execute(self, request, identity):
        started = time.perf_counter()
        try:
            result = self.health() if request['action'] in ('health', 'ping') else self.handler(request)
            response = dict(identity, ok=True, result=result)
        except Exception as error:
            response = dict(identity, ok=False, error=type(error).__name__, message=str(error),
                            traceback=traceback.format_exc(limit=12))
        response.update(generation=self.generation, pid=os.getpid(),
                        guest_seconds=time.perf_counter() - started)
        write_json(self.root / 'responses' / (identity['request_id'] + '.json'), response)

    # 確定名の要求だけ受け取り、同一IDの再配送で再実行しない。
    def tick(self):
        self.pending = {key: future for key, future in self.pending.items() if not future.done()}
        for path in sorted((self.root / 'queue').glob('*.json')):
            try:
                request = json.loads(path.read_text(encoding='utf-8'))
                if not isinstance(request, dict) or not isinstance(request.get('action'), str) or not isinstance(request.get('analysis_id'), str):
                    raise ValueError('Object with action and analysis_id is required')
                if not isinstance(request.get('request_id'), str):
                    raise ValueError('String request_id is required')
                request_id = uuid.UUID(request['request_id']).hex
                if path.stem != request_id:
                    raise ValueError('Request filename mismatch')
                digest = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
                identity = {'request_id': request_id, 'analysis_id': request['analysis_id'], 'digest': digest}
                accepted = self.root / 'accepted' / path.name
                if accepted.exists():
                    previous = json.loads(accepted.read_text(encoding='utf-8'))
                    if previous['digest'] != digest:
                        raise ValueError('Request ID reused with different content')
                    path.unlink()
                    continue
                if len(self.pending) >= 32 and request['action'] not in ('health', 'ping'):
                    continue
                write_json(accepted, identity)
                path.unlink()
                if request.get('generation') not in (None, self.generation):
                    write_json(self.root / 'responses' / (request_id + '.json'),
                               dict(identity, ok=False, error='GenerationMismatch'))
                elif request['action'] in ('health', 'ping'):
                    self.execute(request, identity)
                else:
                    self.pending[request_id] = self.executor.submit(self.execute, request, identity)
            except (ValueError, KeyError) as error:
                # 不正要求を繰り返し読まないよう、別拡張子へ隔離する。
                path.rename(path.with_suffix('.invalid'))
                write_json(path.with_suffix('.error'), {'error': str(error)})

    # VM内のファイルキューを監視し、待機間隔も計測条件として固定する。
    def run(self):
        lock = SingleInstance(hashlib.sha256(os.path.normcase(str(self.root.resolve())).encode()).hexdigest())
        monitor = None
        try:
            self.recover()
            if self.role == "os":
                from desktop_monitor import DesktopMonitor
                monitor = DesktopMonitor(self.root / "desktop-state.json", self.generation)
                monitor.start()
            while True:
                self.tick()
                time.sleep(0.05)
        finally:
            if monitor:
                monitor.stop()
            self.executor.shutdown(wait=True)
            lock.close()
