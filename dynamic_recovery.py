"""動的解析の予定外停止を監視し、同じディスク状態で観測を復帰する。"""
import json
import threading
import time
from pathlib import Path

DEFAULTS = {
    'enabled': False, 'poll_seconds': 5, 'boot_timeout_seconds': 180,
    'max_restarts': 3, 'total_seconds': 1800, 'process_snapshot_seconds': 10,
    'ai_review_enabled': True, 'max_reviews': 3, 'max_experiments': 2,
}


# 無効な制限を受理すると無限復帰になるため、型・範囲を開始前に固定する。
def parse_settings(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError('Invalid dynamic_analysis.recovery settings')
    result = dict(DEFAULTS, **value)
    for key, default in DEFAULTS.items():
        item = result[key]
        if type(default) is bool:
            if type(item) is not bool:
                raise ValueError('recovery.' + key + ' must be boolean')
        elif type(item) is not int or not 1 <= item <= 86400:
            raise ValueError('recovery.' + key + ' must be an integer in 1..86400')
    if result['poll_seconds'] >= result['boot_timeout_seconds']:
        raise ValueError('recovery.poll_seconds must be less than boot_timeout_seconds')
    return result


# Guest由来の情報とHost自身の電源観測を分離し、通知だけでは起動しない。
class RecoveryMonitor:
    # callbacksは製品のVM制御層だけが実装し、AIへ任意コマンドを渡さない。
    def __init__(self, settings, output, power, start, probe, restore, clock=time.monotonic):
        self.settings = parse_settings(settings)
        self.output = Path(output)
        self.power, self.start_vm, self.probe, self.restore = power, start, probe, restore
        self.clock = clock
        self.state = 'ready'
        self.boot_id = None
        self.restarts = 0
        self.sequence = 0
        self.events = []
        self.deadline = None
        self.wait_since = None
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.worker = None
        self.last_notice = None

    # 全履歴をHostへ追記し、Guest停止で調査経緯を失わない。
    def record(self, kind, **details):
        with self.lock:
            self.sequence += 1
            event = dict(sequence=self.sequence, utc=time.time(), kind=kind,
                         state=self.state, restarts=self.restarts, **details)
            self.events.append(event)
            self.output.mkdir(parents=True, exist_ok=True)
            with (self.output / 'recovery_events.jsonl').open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + '\n')
            return event

    # 電源一覧の失敗は停止ではなく不明とし、起動要求を発行しない。
    def tick(self):
        if self.stop_event.is_set() or self.state == 'diagnosis':
            return
        now = self.clock()
        if self.deadline is not None and now >= self.deadline:
            self.state = 'diagnosis'
            self.record('total_limit')
            return
        try:
            running = self.power()
        except Exception as error:
            self.record('power_unknown', error=type(error).__name__)
            return
        if not running:
            if self.state == 'starting':
                if now - self.wait_since >= self.settings['boot_timeout_seconds']:
                    self.state = 'diagnosis'
                    self.record('power_on_timeout')
                return
            if self.restarts >= self.settings['max_restarts']:
                self.state = 'diagnosis'
                self.record('restart_limit')
                return
            self.state = 'starting'
            self.wait_since = now
            self.restarts += 1
            self.record('unexpected_power_off')
            try:
                self.start_vm()
                self.record('power_on_requested')
            except Exception as error:
                self.state = 'diagnosis'
                self.record('power_on_failed', error=type(error).__name__)
            return
        try:
            status = self.probe()
        except Exception:
            status = None
        if not status:
            if self.state not in ('waiting_guest', 'starting', 'shutting_down'):
                self.state, self.wait_since = 'waiting_guest', now
                self.record('guest_unavailable')
            if self.wait_since is not None and now - self.wait_since >= self.settings['boot_timeout_seconds']:
                self.state = 'diagnosis'
                self.record('guest_timeout')
            return
        boot = status.get('boot_id')
        if not isinstance(boot, str) or not boot:
            raise ValueError('Guest lifecycle status has no boot identity')
        notice = status.get('shutdown_notice')
        if notice and notice != self.last_notice:
            self.last_notice = notice
            self.state, self.wait_since = 'shutting_down', now
            self.record('shutdown_notice', notice=notice)
            return
        if self.boot_id is None:
            self.boot_id = boot
        changed = boot != self.boot_id
        if changed or self.state in ('starting', 'waiting_guest'):
            old = self.boot_id
            if self.wait_since is None:
                self.wait_since = now
            self.state = 'restoring'
            self.record('guest_returned', previous_boot=old, boot_id=boot,
                        previous_shutdown_notice=status.get('previous_shutdown_notice'))
            try:
                self.restore(status, changed)
            except Exception as error:
                self.state = 'waiting_guest'
                self.record('restore_pending', error=type(error).__name__)
                if self.wait_since is not None and now - self.wait_since >= self.settings['boot_timeout_seconds']:
                    self.state = 'diagnosis'
                    self.record('restore_timeout')
                return
            self.boot_id, self.state, self.wait_since = boot, 'ready', None
            self.record('observation_restored', boot_id=boot)
        elif self.state == 'shutting_down' and now - self.wait_since >= self.settings['boot_timeout_seconds']:
            # 通知の取消しと終了ハングはここでは断定せず、画面診断へ渡す。
            self.state = 'diagnosis'
            self.record('shutdown_not_completed')

    # 監視障害を黙殺せず記録し、Hostの解析処理とは独立して監視する。
    def run(self):
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception as error:
                self.record('monitor_error', error=type(error).__name__)
            self.stop_event.wait(self.settings['poll_seconds'])

    # 観測開始時からだけ制限時間を計測する。
    def start(self):
        self.deadline = self.clock() + self.settings['total_seconds']
        self.tick()
        self.worker = threading.Thread(target=self.run, daemon=True, name='dynamic-recovery')
        self.worker.start()

    # 製品の終了処理より先に監視を止め、予定された停止を復帰対象にしない。
    def stop(self):
        self.stop_event.set()
        if self.worker:
            self.worker.join(timeout=self.settings['boot_timeout_seconds'] + 30)
            if self.worker.is_alive():
                raise TimeoutError('Recovery worker has not stopped; do not power off or restore VM')

    # AIが観測継続を選んだ場合だけ再照会し、総時間と電源投入回数の上限は維持する。
    def resume_observation(self):
        with self.lock:
            if self.stop_event.is_set() or (self.deadline is not None and self.clock() >= self.deadline):
                return False
            if self.state == 'diagnosis':
                self.state, self.wait_since = 'waiting_guest', self.clock()
                self.record('ai_review_resume')
            return True

    # MCPと追加調査ターンへ同じ根拠を渡す。
    def status(self, after=0):
        with self.lock:
            return {'state': self.state, 'boot_id': self.boot_id, 'restarts': self.restarts,
                    'sequence': self.sequence, 'events': [e for e in self.events if e['sequence'] > after]}
