"""Guest入力先状態と未通知のデスクトップ画像をHostで永続保持する。"""
# 単独起動と同梱exeの両方で、製品共通のエラー形式を参照する。
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from vmrun_errors import error_details, ErrorContext
from contextlib import closing
import json
import sqlite3
import threading
import time


class DesktopState:
    # 要求キューとは別DB・ロックを使い、CLI待機中も監視を進める。
    def __init__(self, bridge, analysis_id, generation):
        self.bridge, self.analysis_id, self.generation = bridge, analysis_id, generation
        self.db = bridge.root / 'desktop.sqlite3'
        self.stop_event = threading.Event()
        self.delivery_lock = threading.Lock()
        self.thread = None
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, value TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS events (generation TEXT, sequence INTEGER, value TEXT, picture TEXT, delivered INTEGER DEFAULT 0, PRIMARY KEY(generation,sequence))')
            db.execute('CREATE TABLE IF NOT EXISTS stalls (id TEXT PRIMARY KEY, first_seen REAL, last_capture REAL)')

    # Guestヘルス確認で得た世代に固定して監視を開始する。
    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    # VM停止・復元前に新規撮影を止め、進行中の転送・撮影を排出する。
    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join()

    # 撮影はGuestキューと独立したVMwareコンソールから行う。
    def capture(self):
        if self.bridge.visual is None:
            return {'screen_error': 'VisualControlUnavailable'}
        with self.bridge.visual_lock:
            result = self.bridge.visual.call({'action': 'screen_observe', 'analysis_id': self.analysis_id})
        return result.get('result', {}) if result.get('ok') else {'screen_error': result}

    # 既読シーケンスの画像は再生成せず、世代違いの状態は受理しない。
    def ingest(self, state):
        if state.get('generation') != self.generation:
            raise ValueError('Desktop monitor generation mismatch')
        with closing(sqlite3.connect(self.db)) as db, db:
            last = db.execute('SELECT MAX(sequence) FROM events WHERE generation=?', (self.generation,)).fetchone()[0] or 0
            events = state.get('events', [])
            gap = bool(events and events[0]['sequence'] > last + 1)
            status = {k: v for k, v in state.items() if k != 'events'}
            status.update(received_at=time.time(), history_gap=gap)
            db.execute('INSERT OR REPLACE INTO state VALUES (1,?)', (json.dumps(status),))
        for event in events:
            if event['sequence'] <= last or self.stop_event.is_set():
                continue
            picture = None
            if event['kind'] == 'desktop_switch':
                capture_requested_at = time.time()
                try:
                    picture = self.capture()
                except Exception as error:
                    picture = {'screen_error': str(error), 'error_details': error_details(error)}
                picture['desktop_event'] = dict(event, generation=self.generation,
                    capture_requested_at=capture_requested_at, timing='captured_after_host_received_event')
            with closing(sqlite3.connect(self.db)) as db, db:
                db.execute('INSERT OR IGNORE INTO events(generation,sequence,value,picture) VALUES (?,?,?,?)',
                    (self.generation, event['sequence'], json.dumps(event), json.dumps(picture) if picture else None))

    # vmrunの専用短時間転送を使い、Guest操作受付のロックを奪わない。
    def run(self):
        from bridge_service import control
        config = dict(self.bridge.config, vmrun_timeout_seconds=5)
        target = self.bridge.root / 'desktop-state.json'
        while not self.stop_event.is_set():
            try:
                control.run_vmrun(config, ['-gu', config['guest_user'], '-gp', config['guest_password'],
                    'copyFileFromGuestToHost', config['vmx_path'],
                    self.bridge.guest_root + '\\os\\desktop-state.json', str(target)], check=True)
                if not self.stop_event.is_set():
                    self.ingest(json.loads(target.read_text(encoding='utf-8')))
            except Exception as error:
                with closing(sqlite3.connect(self.db)) as db, db:
                    previous = db.execute('SELECT value FROM state WHERE id=1').fetchone()
                    status = json.loads(previous[0]) if previous else {}
                    status.update(transport_error=str(error), error_details=error_details(error), error_at=time.time())
                    db.execute('INSERT OR REPLACE INTO state VALUES(1,?)', (json.dumps(status),))
            self.stop_event.wait(1)

    # 最新状態は常時通知せず、Codexが必要な時だけ確認できるようにする。
    def status(self):
        with closing(sqlite3.connect(self.db)) as db:
            row = db.execute('SELECT value FROM state WHERE id=1').fetchone()
        status = json.loads(row[0]) if row else {'available': False}
        status['stale'] = time.time() - min(status.get('received_at', 0), status.get('heartbeat_at', 0)) > 10
        return status

    # 履歴はシーケンスでページングし、画像を混ぜずに返す。
    def history(self, after=0, limit=50):
        with closing(sqlite3.connect(self.db)) as db:
            rows = db.execute('SELECT value FROM events WHERE generation=? AND sequence>? ORDER BY sequence LIMIT ?',
                (self.generation, int(after), min(200, max(1, int(limit))))).fetchall()
        return {'generation': self.generation, 'events': [json.loads(row[0]) for row in rows]}

    # 一応答一画像で転送上限を守り、MCP再起動後も未通知画像を回収できるようにする。
    def take_picture(self):
        with self.delivery_lock, closing(sqlite3.connect(self.db)) as db, db:
            row = db.execute('SELECT sequence,picture FROM events WHERE generation=? AND picture IS NOT NULL AND delivered=0 ORDER BY sequence LIMIT 1', (self.generation,)).fetchone()
            if not row:
                return {}
            db.execute('UPDATE events SET delivered=1 WHERE generation=? AND sequence=?', (self.generation, row[0]))
            result = json.loads(row[1])
            result['delivery_note'] = 'handed_to_mcp_transport; not_model_acknowledgement'
            return result

    # 通常pendingでは撮影せず、30秒継続または応答不明時のみ60秒間隔で撮影する。
    def review_stall(self, request_id, unknown=False):
        now = time.time()
        with self.delivery_lock, closing(sqlite3.connect(self.db)) as db, db:
            row = db.execute('SELECT first_seen,last_capture FROM stalls WHERE id=?', (request_id,)).fetchone()
            first, previous = row if row else (now, 0)
            due = (unknown or now - first >= 30) and now - previous >= 60
            db.execute('INSERT OR REPLACE INTO stalls VALUES (?,?,?)', (request_id, first, now if due else previous))
        return self.capture() if due else {}
