"""画像と入力を同じ観測世代に結び付け、結果不明でも解析全体を止めない。"""
import base64
import hashlib
import json
import math
from pathlib import Path
import threading
import time
import uuid


class VisualController:
    # MCPプロセスではなくHostブリッジに所有させ、MCP再起動時にも観測を保持する。
    def __init__(self, backend, root, analysis_id, max_age=60):
        self.backend, self.root, self.analysis_id = backend, Path(root), analysis_id
        self.max_age = max_age
        self.generation = uuid.uuid4().hex
        self.frames = {}
        self.lock = threading.Lock()
        self.root.mkdir(parents=True, exist_ok=True)

    # 原寸画像と保存記録を同時に作り、LLMが画像パスだけを受け取る状態を避ける。
    def observe(self):
        width, height, image = self.backend.observe()
        if len(image) > 8 * 1024 * 1024:
            raise ValueError('Frame exceeds image transport limit')
        identity = uuid.uuid4().hex
        frame = {'frame_id': identity, 'generation': self.generation,
                 'analysis_id': self.analysis_id, 'width': width, 'height': height,
                 'coordinate_space': 'original_image_pixels', 'captured_at': time.time(),
                 'image_sha256': hashlib.sha256(image).hexdigest()}
        (self.root / (identity + '.png')).write_bytes(image)
        (self.root / (identity + '.json')).write_text(json.dumps(frame), encoding='utf-8')
        # 古い観測を残してもメモリが無制限に増えないよう最新32件だけを保持する。
        self.frames[identity] = dict(frame, deadline=time.monotonic() + self.max_age)
        while len(self.frames) > 32:
            self.frames.pop(next(iter(self.frames)))
        return dict(frame, image={'mimeType': 'image/png', 'data': base64.b64encode(image).decode('ascii')})

    # 推定点や矩形中心の計算をツール内に固定し、画像とGuestの原寸座標を一致させる。
    def point(self, request, frame):
        if 'rectangle' in request:
            rectangle = request['rectangle']
            if not isinstance(rectangle, list) or len(rectangle) != 4:
                raise ValueError('rectangle must be [left, top, right, bottom]')
            left, top, right, bottom = rectangle
            values = rectangle
        else:
            left = right = request.get('x')
            top = bottom = request.get('y')
            values = [left, top]
        if any(type(v) not in (int, float) or not math.isfinite(v) for v in values):
            raise ValueError('Finite pixel coordinates are required')
        if not (0 <= left <= right < frame['width'] and 0 <= top <= bottom < frame['height']):
            raise ValueError('Target is outside the observed image')
        return math.floor((left + right) / 2 + 0.5), math.floor((top + bottom) / 2 + 0.5)

    # 無効な操作は再観測可能な結果を返し、送信後の不明状態では同じ操作を繰り返さない。
    def call(self, request):
        with self.lock:
            sent = False
            try:
                if request.get('analysis_id') != self.analysis_id:
                    raise ValueError('Visual analysis binding mismatch')
                action = request['action']
                if action == 'screen_observe':
                    return {'ok': True, 'result': self.observe()}
                if action not in ('screen_click', 'screen_key'):
                    raise ValueError('Unknown visual action')
                frame = self.frames.get(request.get('frame_id'))
                if not frame or time.monotonic() > frame['deadline']:
                    raise ValueError('Frame is stale or unknown; observe again')
                point = self.point(request, frame) if action == 'screen_click' else None
                # 入力開始前に観測を失効させ、別IDでの同一画面操作も再観測を必要とする。
                self.frames.clear()
                sent = True
                if point is not None:
                    self.backend.click(frame['width'], frame['height'], *point)
                else:
                    self.backend.key(frame['width'], frame['height'], request.get('keysym'))
                time.sleep(0.2)
                return {'ok': True, 'result': dict(self.observe(), input_sent=True,
                        application_result_verified=False)}
            except Exception as error:
                return {'ok': False, 'error': type(error).__name__, 'message': str(error),
                        'input_outcome': 'unknown' if sent else 'not_sent',
                        'recovery': 'observe_again_or_continue_other_analysis',
                        'analysis_halt_required': False}
