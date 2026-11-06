"""Host内のブリッジへJSONで問い合わせる。"""
import json
import time
from multiprocessing.connection import Client
from pathlib import Path


# 受付再起動後も同じ要求IDで結果を取得できる。
def call_bridge(message, key_path, pipe=r'\\.\pipe\r_AKanaly_analysis_bench'):
    deadline = time.monotonic() + 10
    while True:
        try:
            connection = Client(pipe, family='AF_PIPE', authkey=Path(key_path).read_bytes())
            break
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    with connection:
        connection.send_bytes(json.dumps(message).encode('utf-8'))
        # OS操作は短い受信期限で制御を戻し、Guest転送が止まっていても別接続で撮影できるようにする。
        response_timeout = float(message.get('response_timeout', float(message.get('timeout', 30)) + 120))
        if not connection.poll(response_timeout):
            raise TimeoutError('Bridge response timeout; retain the request ID')
        return json.loads(connection.recv_bytes(16 * 1024 * 1024))
