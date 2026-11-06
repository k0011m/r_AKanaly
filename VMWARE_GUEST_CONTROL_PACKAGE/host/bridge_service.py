"""実験用Hostブリッジ。JSONの名前付きパイプと永続要求記録を提供する。"""
# 単独起動と同梱exeの両方で、製品共通のエラー形式を参照する。
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from vmrun_errors import error_details, ErrorContext
import argparse
from contextlib import closing
import hashlib
import importlib.util
import json
import sqlite3
import shutil
import threading
import tempfile
import time
import uuid
from multiprocessing.connection import Listener
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vm_control', PACKAGE / 'tools/vm_guest_control.py')
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


class Bridge:
    # SQLiteは短い更新にのみ使い、Guestの待機中はトランザクションを保持しない。
    def __init__(self, config, root, guest_root):
        self.config, self.root, self.guest_root = config, Path(root), guest_root
        self.root.mkdir(parents=True, exist_ok=True)
        self.db = self.root / 'requests.sqlite3'
        self.lock = threading.Lock()
        # vmrun配送待ちとVMコンソール撮影を分離し、Guest無応答時の画面確認を妨げない。
        self.visual_lock = threading.Lock()
        self.intake_condition = threading.Condition()
        self.active_connections = 0
        self.accepting = True
        self.visual = None
        self.desktop = None
        self.control_handler = None
        self.request_gate = None
        self.archive_secrets = {}
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, digest TEXT, request TEXT, state TEXT, response TEXT)')

    # 受付停止と実行中クライアントの排出を同じロックで行い、保存開始との競合を防ぐ。
    def close_intake(self, timeout=660):
        self.stop_desktop_monitor()
        with self.intake_condition:
            self.accepting = False
            if not self.intake_condition.wait_for(lambda: self.active_connections == 0, timeout=timeout):
                raise TimeoutError('MCP connections did not finish before finalization')

    # Guest世代確定後に監視を起動し、MCP再接続後も記録を利用する。
    def start_desktop_monitor(self, analysis_id, generation):
        from desktop_state import DesktopState
        self.desktop = DesktopState(self, analysis_id, generation)
        self.desktop.start()

    # VM停止・復元・例外終了前に監視を排出する。
    def stop_desktop_monitor(self):
        if self.desktop is not None:
            self.desktop.stop()

    # 状態照会はGuestキューを待たずHost内で処理する。
    def desktop_call(self, request):
        monitor = self.desktop
        if monitor is None:
            return {'ok': True, 'result': {'monitor_available': False}}
        if request['analysis_id'] != monitor.analysis_id:
            raise ValueError('Desktop session mismatch')
        action = request['action']
        if action == 'desktop_status':
            result = monitor.status()
        elif action == 'desktop_events':
            result = monitor.history(request.get('after_sequence', 0), request.get('limit', 50))
        elif action == '_desktop_picture':
            result = monitor.take_picture()
        else:
            result = monitor.review_stall(request['review_of_request_id'], request.get('unknown', False))
        return {'ok': True, 'result': result}

    # 認証値は既存ラッパー内だけで扱い、コマンド文字列をログに保存しない。
    def vmrun(self, operation, *args, check=True):
        cfg = self.config
        prefix = ['-gu', cfg['guest_user'], '-gp', cfg['guest_password'], operation, cfg['vmx_path']]
        # 共通の実行層で短い一時パスへ変換し、ここでは二重コピーしない。
        return control.run_vmrun(cfg, [*prefix, *args], check=check)

    # ZIP秘密値はHost常駐プロセス内だけに保持し、MCPへは不透明な参照を渡す。
    def register_archive_secret(self, analysis_id, password):
        if not isinstance(password, str):
            raise ValueError('Archive secret must be a string')
        reference = uuid.uuid4().hex
        self.archive_secrets[reference] = (analysis_id, password)
        return reference

    # 通常の要求・SQLiteへ秘密値を混ぜず、Guestが読取後削除する一時ファイルへ配送する。
    def deliver_archive_secret(self, request):
        reference = request.get('password_ref')
        if not reference:
            return None
        secret = self.archive_secrets.get(reference)
        if not secret or secret[0] != request['analysis_id']:
            raise ValueError('Unknown archive password reference')
        target = self.guest_root + '\\os\\secrets\\' + request['request_id'] + '.json'
        with tempfile.TemporaryDirectory(prefix='r_AKanaly_zip_secret_') as temporary:
            path = Path(temporary) / 'secret.json'
            path.write_text(json.dumps({'analysis_id': secret[0], 'password_ref': reference,
                                       'password': secret[1]}), encoding='utf-8')
            try:
                self.vmrun('copyFileFromHostToGuest', str(path), target)
            except Exception:
                self.vmrun('deleteFileInGuest', target, check=False)
                raise
        return target

    # 同じ要求IDは再送せず、保存済み応答またはGuestの応答を照会する。
    def call(self, message):
        role = message['role']
        if role not in ('os', 'ghidra'):
            raise ValueError('Invalid role')
        request = dict(message['request'])
        if self.request_gate is not None:
            self.request_gate(role, request)
        request['request_id'] = uuid.UUID(request['request_id']).hex
        if not isinstance(request.get('analysis_id'), str):
            raise ValueError('analysis_id is required')
        if any(key in request for key in ('password', 'guest_password', 'vm_password')):
            raise ValueError('Secrets are not accepted by the benchmark bridge')
        content = json.dumps(request, sort_keys=True)
        digest = hashlib.sha256((role + content).encode()).hexdigest()
        request_id = request['request_id']
        if role == 'os' and request.get('action') in ('screen_observe', 'screen_click', 'screen_key', 'finish_investigation', 'recovery_status', 'request_followup'):
            return self.call_visual(request, content, digest)
        if role == 'os' and request.get('action') in ('desktop_status', 'desktop_events', '_desktop_picture', '_review_stall'):
            return self.desktop_call(request)
        started = time.perf_counter()
        guest = self.guest_root + '\\' + role
        target = guest + '\\queue\\' + request_id + '.json'
        with self.lock:
            with closing(sqlite3.connect(self.db)) as db, db:
                previous = db.execute('SELECT digest,state,response FROM requests WHERE id=?', (request_id,)).fetchone()
                if previous and previous[0] != digest:
                    raise ValueError('Request ID content mismatch')
                if previous and previous[2]:
                    return json.loads(previous[2])
                if not previous:
                    if role == 'os' and request.get('action') == 'extract_zip' and request.get('password_ref'):
                        secret = self.archive_secrets.get(request['password_ref'])
                        if not secret or secret[0] != request['analysis_id']:
                            raise ValueError('Archive password reference is unavailable in this session')
                    # 転送中断後に自動再実行しないため、配送前に記録する。
                    db.execute('INSERT INTO requests VALUES (?,?,?,?,NULL)', (request_id, digest, content, 'dispatching'))
            if not previous:
                source = self.root / (request_id + '.json')
                source.write_text(content, encoding='utf-8')
                secret_target = None
                try:
                    if role == 'os' and request.get('action') == 'extract_zip':
                        secret_target = self.deliver_archive_secret(request)
                    self.vmrun('copyFileFromHostToGuest', str(source), target + '.tmp')
                    control.run_vmrun(self.config, control.guest_program_args(
                        self.config, r'C:\Windows\System32\cmd.exe',
                        ['/c move /Y "' + target + '.tmp" "' + target + '"']), check=True)
                except Exception:
                    if secret_target:
                        self.vmrun('deleteFileInGuest', secret_target, check=False)
                    raise
                with closing(sqlite3.connect(self.db)) as db, db:
                    db.execute('UPDATE requests SET state=? WHERE id=?', ('sent', request_id))
        timeout = min(600, max(0.1, float(message.get('timeout', 30))))
        deadline = time.monotonic() + timeout
        response_file = self.root / (request_id + '-' + uuid.uuid4().hex + '.response.json')
        last_transfer_error = None
        while time.monotonic() < deadline:
            result = self.vmrun('copyFileFromGuestToHost', guest + '\\responses\\' + request_id + '.json', str(response_file), check=False)
            if result['exit_code'] == 0:
                response = json.loads(response_file.read_text(encoding='utf-8'))
                expected = hashlib.sha256(content.encode()).hexdigest()
                if response.get('request_id') != request_id or response.get('analysis_id') != request['analysis_id'] or response.get('digest') != expected:
                    raise RuntimeError('Response identity mismatch')
                response['host_roundtrip_seconds'] = time.perf_counter() - started
                if role == 'os' and request.get('action') == 'ui_action':
                    return self.complete_ui_response(request, response)
                with closing(sqlite3.connect(self.db)) as db, db:
                    db.execute('UPDATE requests SET state=?, response=? WHERE id=?', ('complete', json.dumps(response), request_id))
                return response
            last_transfer_error = result.get('error_details') or {'type': 'VmrunError', 'vmrun_errors': [{'operation': 'copyFileFromGuestToHost', 'returncode': result['exit_code']}]}
            time.sleep(0.1)
        diagnostic = {'action': request.get('action'), 'request_id': request_id, 'error_details': last_transfer_error}
        (self.root / (request_id + '.transfer-error.json')).write_text(json.dumps(diagnostic, ensure_ascii=False, indent=2), encoding='utf-8')
        return {'ok': False, 'pending': True, 'error_details': last_transfer_error, 'request_id': request_id,
                'message': 'Query the same request ID; do not create another job'}

    # Guestが再解決したUIA座標をHost仮想入力へ渡し、並行照会や中断で二重クリックしない。
    def complete_ui_response(self, request, response):
        identity = request['request_id']
        with self.lock:
            with closing(sqlite3.connect(self.db)) as db, db:
                previous = db.execute('SELECT state,response FROM requests WHERE id=?', (identity,)).fetchone()
                if previous and previous[1]:
                    return json.loads(previous[1])
                if previous and previous[0] == 'ui_postprocessing':
                    return {'ok': False, 'error': 'InterruptedOutcomeUnknown', 'request_id': identity,
                            'recovery': 'observe_again_or_continue_other_analysis', 'analysis_halt_required': False}
                db.execute('UPDATE requests SET state=? WHERE id=?', ('ui_postprocessing', identity))
            payload = response.get('result')
            if isinstance(payload, dict) and request.get("operation") != "point":
                if self.visual is None:
                    if request.get('operation') == 'click':
                        payload.update(status='image_fallback', message='VM console is unavailable', input_sent=False)
                else:
                    screen = self.visual.call({'action': 'screen_observe', 'analysis_id': request['analysis_id']})
                    if request.get('operation') == 'click' and payload.get('status') == 'resolved' and screen.get('ok'):
                        x, y = payload['point']
                        screen = self.visual.call({'action': 'screen_click', 'analysis_id': request['analysis_id'],
                            'frame_id': screen['result']['frame_id'], 'x': x, 'y': y})
                        payload.update(status='performed' if screen.get('ok') else 'image_fallback',
                                       input_method='vmware_console_from_uia', application_result_verified=False)
                        # Guestの座標解決時点のfalseを残さず、実際のHost入力結果へ更新する。
                        payload['input_sent'] = True if screen.get('ok') else (
                            False if screen.get('input_outcome') == 'not_sent' else None)
                        payload['input_outcome'] = 'sent' if screen.get('ok') else screen.get('input_outcome', 'unknown')
                    if screen.get('ok'):
                        snapshot = dict(screen['result'])
                        payload['image'] = snapshot.pop('image')
                        payload['screen'] = snapshot
                    else:
                        payload['screen_error'] = screen
                payload['analysis_halt_required'] = False
            with closing(sqlite3.connect(self.db)) as db, db:
                db.execute('UPDATE requests SET state=?,response=? WHERE id=?',
                           ('complete', json.dumps(response), identity))
            return response

    # 入力前に要求を永続化し、ブリッジ中断後も同じクリックを自動再実行しない。
    def call_visual(self, request, content, digest):
        request_id = request['request_id']
        with self.visual_lock:
            with closing(sqlite3.connect(self.db)) as db, db:
                previous = db.execute('SELECT digest,state,response FROM requests WHERE id=?', (request_id,)).fetchone()
                if previous and previous[0] != digest:
                    raise ValueError('Request ID content mismatch')
                if previous and previous[2]:
                    return json.loads(previous[2])
                if previous:
                    return {'ok': False, 'request_id': request_id, 'error': 'InterruptedOutcomeUnknown',
                            'recovery': 'observe_again_or_continue_other_analysis', 'analysis_halt_required': False}
                db.execute('INSERT INTO requests VALUES (?,?,?,?,NULL)',
                           (request_id, digest, content, 'visual_dispatching'))
            if request.get('action') in ('finish_investigation', 'recovery_status', 'request_followup') and self.control_handler is not None:
                result = self.control_handler(request)
            elif request.get('action') == 'finish_investigation':
                raise ValueError('Dynamic completion is unavailable in this session')
            elif self.visual is None:
                result = {'ok': False, 'error': 'VisualControlUnavailable',
                          'recovery': 'continue_other_analysis', 'analysis_halt_required': False}
            else:
                result = self.visual.call(request)
            result.update(request_id=request_id, analysis_id=request['analysis_id'],
                          digest=hashlib.sha256(content.encode()).hexdigest())
            with closing(sqlite3.connect(self.db)) as db, db:
                db.execute('UPDATE requests SET state=?,response=? WHERE id=?',
                           ('complete', json.dumps(result), request_id))
            return result


# pickleによる入力復元を使わず、認証済み接続上のJSONだけを処理する。
def serve_connection(connection, bridge):
    active = False
    try:
        try:
            with bridge.intake_condition:
                if not bridge.accepting:
                    raise RuntimeError('Analysis is finalizing; new requests are closed')
                bridge.active_connections += 1
                active = True
            if not connection.poll(15):
                raise TimeoutError('MCP client did not send a request')
            result = bridge.call(json.loads(connection.recv_bytes(1024 * 1024)))
        except Exception as error:
            result = {'ok': False, 'error': type(error).__name__, 'message': str(error), 'error_details': error_details(error)}
        connection.send_bytes(json.dumps(result).encode('utf-8'))
    finally:
        connection.close()
        if active:
            with bridge.intake_condition:
                bridge.active_connections -= 1
                bridge.intake_condition.notify_all()


# Hostだけの名前付きパイプで常駐し、MCPの再接続を受け付ける。
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=str(control.DEFAULT_CONFIG))
    parser.add_argument('--root', required=True)
    parser.add_argument('--guest-root', default=r'C:\Users\Public\CodexGuestAgent\analysis_bench')
    parser.add_argument('--pipe', default=r'\\.\pipe\r_AKanaly_analysis_bench')
    args = parser.parse_args()
    config = control.load_config(args.config)
    control.assert_vmx_network(config)
    bridge = Bridge(config, args.root, args.guest_root)
    token = bridge.root / 'pipe.key'
    if not token.exists():
        with token.open('xb') as output:
            output.write(uuid.uuid4().bytes + uuid.uuid4().bytes)
    with Listener(args.pipe, family='AF_PIPE', authkey=token.read_bytes()) as listener:
        while True:
            connection = listener.accept()
            threading.Thread(target=serve_connection, args=(connection, bridge), daemon=True).start()


if __name__ == '__main__':
    main()
