"""同じSDKターンの公開イベントを表示し、解析結果の収集はSDKへ委譲する。"""
from datetime import datetime
import json
from pathlib import Path
import re
import time

import tui_runtime


# ターミナル制御文字と典型的な資格情報を除き、証拠中の文字を命令として描画しない。
def clean_text(value):
    text = str(value)
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = ''.join(c for c in text if c in '\n\t' or (ord(c) >= 32 and not 127 <= ord(c) <= 159))
    text = re.sub(r'(?i)((?:password|passwd|api[_-]?key|auth-key|token)\s*["\x27]?\s*[:=]\s*["\x27]?)[^\s,"\x27]+', r'\1[伏字]', text)
    text = re.sub(r'(?i)(-gp|-vp)\s+("[^"]*"|\S+)', r'\1 [伏字]', text)
    return text.strip()


# SDKのPydanticモデル・RootModelを表示用の辞書へ変換する。
def event_dict(value):
    if hasattr(value, 'model_dump'):
        return value.model_dump(mode='json', by_alias=True)
    return value if isinstance(value, dict) else {}


class SessionProgress:
    # 表示は最新3件とし、全文イベントや画像をメモリに蓄積しない。
    def __init__(self, phase, path=None):
        self.phase = phase
        self.path = Path(path) if path else None
        self.rows = []
        self.texts = {}
        self.last_draw = 0.0
        self.log_failed = False

    # 差分は同じ行を更新し、確定した公開項目だけをJSONLへ記録する。
    def publish(self, key, text, complete=False):
        text = clean_text(text)[:4000]
        if not text:
            return
        stamp = datetime.now().astimezone().isoformat(timespec='seconds')
        self.rows = [row for row in self.rows if row[0] != key]
        self.rows.append((key, stamp[11:19] + ' ' + text[:600]))
        self.rows = self.rows[-3:]
        if complete and self.path and not self.log_failed:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps({'time': stamp, 'phase': self.phase, 'text': text}, ensure_ascii=False) + '\n')
            except OSError:
                # 進捗ログの書込障害で本来の解析結果を失わない。
                self.log_failed = True
        if complete or time.monotonic() - self.last_draw >= 0.25:
            detail = '\n'.join(row[1] for row in self.rows)
            if self.log_failed:
                detail += '\n進捗ログを保存できません。画面表示のみ継続します。'
            tui_runtime.set_session_progress(self.phase, detail)
            self.last_draw = time.monotonic()

    # reasoning・画像・引数・ツール出力本文は公開せず、進捗と実行状態だけを採用する。
    def accept(self, event):
        method = event.method
        payload = event_dict(event.payload)
        if method == 'item/agentMessage/delta':
            key = payload.get('itemId', '')
            self.texts[key] = (self.texts.get(key, '') + payload.get('delta', ''))[-4000:]
            self.publish(key, 'Codex: ' + self.texts[key])
        elif method in ('item/started', 'item/completed'):
            item = payload.get('item', {})
            kind, key = item.get('type'), item.get('id', '')
            done = method == 'item/completed'
            if kind == 'agentMessage' and done:
                self.texts.pop(key, None)
                self.publish(key, 'Codex: ' + item.get('text', ''), True)
            elif kind in ('mcpToolCall', 'dynamicToolCall', 'commandExecution', 'fileChange', 'webSearch'):
                label = {'commandExecution': 'コマンド', 'fileChange': 'ファイル更新', 'webSearch': '検索'}.get(kind, 'ツール')
                tool = item.get('tool', '')
                if re.fullmatch(r'[A-Za-z0-9_.:/-]{1,100}', str(tool)):
                    label += ': ' + tool
                arguments = item.get('arguments')
                if isinstance(arguments, dict) and isinstance(arguments.get('request'), dict):
                    action = arguments['request'].get('action', '')
                    if re.fullmatch(r'[a-z_]{1,60}', str(action)):
                        label += ' / ' + action
                result = str(item.get('status', 'completed' if done else 'inProgress'))
                code = item.get('exitCode')
                if code is not None:
                    result += ' / 終了コード ' + str(code)
                self.publish(key, label + ' — ' + ('終了: ' + result if done else '実行中'), True)
        elif method == 'turn/completed':
            self.publish('turn', 'セッション応答終了: ' + str(payload.get('turn', {}).get('status', 'unknown')), True)


# SDK標準の結果収集を維持し、ツール履歴・最終応答・失敗伝搬を変えずに表示を挟む。
def consume_turn(turn, phase, path=None):
    import token_usage
    tracker = token_usage.current
    usage_key = object()
    tracker.begin(usage_key)
    from openai_codex._run import _collect_turn_result
    progress = SessionProgress(phase, path)
    progress.publish('start', 'Codexの応答を待っています', True)
    stream = turn.stream()

    # 表示不能な未知イベントでも、結果収集への配送を止めない。
    def observed():
        for event in stream:
            if event.method == 'thread/tokenUsage/updated':
                payload = event_dict(event.payload)
                if payload.get('turnId') == turn.id:
                    tracker.update(usage_key, payload.get('threadId'), payload.get('tokenUsage'))
            try:
                progress.accept(event)
            except (TypeError, ValueError, AttributeError):
                pass
            yield event

    try:
        return _collect_turn_result(observed(), turn_id=turn.id)
    finally:
        stream.close()


# ターンの作成は一度だけ行い、表示用の別Codexセッションを起動しない。
def run_turn(thread, prompt, phase, path=None, **options):
    return consume_turn(thread.turn(prompt, **options), phase, path)
