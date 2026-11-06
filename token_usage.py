"""解析一回分のSDK報告使用量を、スレッド累積値から集計する。"""
from threading import Lock


class UsageTracker:
    # 遅れて終了した前回のワーカーとは別の集計器を使用する。
    def __init__(self):
        self.lock = Lock()
        self.totals = {}
        self.pending = set()
        self.started = False

    # 使用量通知がないターンをゼロとして扱わないため、開始を記録する。
    def begin(self, key):
        with self.lock:
            self.started = True
            self.pending.add(key)

    # SDKのtotalは累積値なので、通知ごとの加算ではなく置換する。
    def update(self, key, thread_id, usage):
        if hasattr(usage, 'model_dump'):
            usage = usage.model_dump(by_alias=True)
        total = usage.get('total', {}) if isinstance(usage, dict) else {}
        names = ('inputTokens', 'outputTokens', 'cachedInputTokens', 'totalTokens')
        values = {name: total.get(name) for name in names}
        if not thread_id or any(type(v) is not int or v < 0 for v in values.values()):
            return
        with self.lock:
            self.totals[thread_id] = values
            self.pending.discard(key)

    # キャッシュ入力は入力の内数であり、合計へ再加算しない。
    def items(self):
        with self.lock:
            available = self.started and not self.pending and bool(self.totals)
            return [('合計トークン', f'{sum(t["totalTokens"] for t in self.totals.values()):,}'
                     if available else '取得できず')]


current = UsageTracker()


# 解析開始時に集計を交換し、連続解析の使用量が混ざらないようにする。
def reset():
    global current
    current = UsageTracker()
