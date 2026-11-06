"""対話Agent起動前に、Guestコンソールのログイン準備を期限付きで監視する。"""
# 単独起動と同梱exeの両方で、製品共通のエラー形式を参照する。
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from vmrun_errors import error_details, ErrorContext
import json
import time
import uuid
from pathlib import Path

POWERSHELL = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'


# OS Agentに依存せずGuest Operationsで状態を確認し、文言解析で分岐しない。
def wait_for_login(session):
    session.state.mkdir(parents=True, exist_ok=True)
    guest_script = session.settings.guest_root + '\\code\\login_status.ps1'
    # exeではモジュールの仮想配置でなく、実際の同梱データ展開先を使う。
    if getattr(sys, 'frozen', False):
        source = Path(sys._MEIPASS) / 'VMWARE_GUEST_CONTROL_PACKAGE/guest/login_status.ps1'
    else:
        source = Path(__file__).resolve().parents[1] / 'guest/login_status.ps1'
    if not source.is_file():
        raise RuntimeError('Bundled Guest login probe is missing: ' + str(source))
    session.guest('copyFileFromHostToGuest', str(source), guest_script)
    identity = uuid.uuid4().hex
    guest_result = session.settings.guest_root + '\\code\\login-' + identity + '.json'
    local_result = session.state / 'login-probe.json'
    status_path = session.state / 'login-readiness.json'
    deadline = time.monotonic() + session.settings.ready_timeout_seconds
    last = {'state': 'waiting_for_login', 'ready': False}
    previous_state = None
    original_timeout = session.config['vmrun_timeout_seconds']
    try:
        while time.monotonic() < deadline:
            nonce = uuid.uuid4().hex
            session.config['vmrun_timeout_seconds'] = max(0.1, min(15, deadline - time.monotonic()))
            try:
                session.program(POWERSHELL, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                    '-File', guest_script, '-OutputPath', guest_result, '-RequestId', nonce])
                session.config['vmrun_timeout_seconds'] = max(0.1, min(15, deadline - time.monotonic()))
                session.guest('copyFileFromGuestToHost', guest_result, str(local_result))
                last = json.loads(local_result.read_text(encoding='utf-8-sig'))
                if last.get('request_id') != nonce:
                    raise ValueError('Login probe request ID mismatch')
                if last.get('state') == 'probe_error':
                    raise ValueError('Guest login probe failed: ' + last.get('error', 'unknown'))
                if last.get('ready') is True and last.get('state') == 'session_active':
                    # WTSのActiveだけでなく、VMwareが対話プロセスを起動できることも確認する。
                    session.config['vmrun_timeout_seconds'] = max(0.1, min(15, deadline - time.monotonic()))
                    session.program(r'C:\Windows\System32\cmd.exe', ['/c exit 0'], interactive=True)
                    last.update(state='interactive_ready', ready=True)
            except (RuntimeError, TimeoutError) as error:
                # エラー文は診断用だけに残し、再試行判定に日本語・英語を用いない。
                last = {'state': 'waiting_for_interactive_access', 'ready': False, 'error': str(error), 'error_details': error_details(error)}
            status_path.write_text(json.dumps(last, ensure_ascii=False, indent=2), encoding='utf-8')
            if last['state'] != previous_state:
                print('Guest login: ' + last['state'], flush=True)
                previous_state = last['state']
            if last.get('ready') is True and last['state'] == 'interactive_ready':
                return last
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        raise ErrorContext('Guest login readiness timed out: ' + json.dumps(last, ensure_ascii=False), details=last.get('error_details'))
    except (ValueError, OSError) as error:
        # 不正JSON・世代違い・API障害は未ログインと混同せず、診断を残す。
        status_path.write_text(json.dumps({'state': 'probe_failed', 'ready': False,
            'error': str(error), 'error_details': error_details(error)}, ensure_ascii=False), encoding='utf-8')
        raise RuntimeError('Guest login readiness probe failed: ' + str(error)) from error
    finally:
        session.config['vmrun_timeout_seconds'] = original_timeout
