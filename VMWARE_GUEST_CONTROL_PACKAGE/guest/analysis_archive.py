"""解析用ZIP公開。秘密値と一般のキュー記録を分け、展開はGuest内に限定する。"""
import json
from pathlib import Path
import sys
import uuid
from archive_ops import extract_zip


# 解析ルート外やリンク先を読ませず、公開済みの展開制限をそのまま適用する。
def extract(request, root):
    root = Path(root).resolve()
    # 本体が準備時に配置した依存を使い、常駐Pythonへ別途ネットインストールしない。
    dependencies = root / 'transfer/runtime/Lib/site-packages'
    if dependencies.is_dir() and str(dependencies) not in sys.path:
        sys.path.append(str(dependencies))
    request_id = uuid.UUID(request['request_id']).hex
    secret_path = root / 'os' / 'secrets' / (request_id + '.json')
    password = None
    if request.get('password_ref'):
        try:
            record = json.loads(secret_path.read_text(encoding='utf-8'))
        finally:
            secret_path.unlink(missing_ok=True)
        if record.get('analysis_id') != request['analysis_id'] or record.get('password_ref') != request['password_ref']:
            raise ValueError('Archive secret binding mismatch')
        password = record['password']
    source = Path(request['archive_path']).resolve()
    destination = Path(request['destination']).resolve()
    allowed = tuple(root / name for name in ('samples', 'transfer', 'extracted'))
    if not any(source.is_relative_to(path) for path in allowed):
        raise ValueError('Archive must be inside the Guest analysis area')
    if not destination.is_relative_to(root / 'extracted') or destination == root / 'extracted':
        raise ValueError('Destination must be a new child of Guest extracted directory')
    (root / 'extracted').mkdir(exist_ok=True)
    try:
        return extract_zip(str(source), str(destination), password=password,
            max_total_bytes=request.get('max_total_bytes', 536870912),
            max_members=request.get('max_members', 10000), max_seconds=request.get('max_seconds', 120))
    except Exception as error:
        message = str(error).replace(password, '[REDACTED]') if password else str(error)
        raise RuntimeError('ZIP extraction failed: ' + message) from None
