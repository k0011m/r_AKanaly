"""同一解析の検証済みログだけを、シェルを起動せずMCPへ返す。"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

ACTIONS = ('host_evidence_list', 'host_evidence_read', 'host_evidence_search')
TEXT_SUFFIXES = {'.json', '.jsonl', '.csv', '.xml', '.txt', '.md', '.log'}


# 配置時に照合済みのファイルだけを固定し、検体・原本バイナリを公開しない。
def register_evidence(session_path, log_root, hashes):
    root = Path(log_root).resolve(strict=True)
    files = {}
    for path in sorted(root.iterdir()):
        if path.suffix.lower() not in TEXT_SUFFIXES or path.is_symlink() or not path.is_file():
            continue
        key = 'dynamic_status' if path.name == 'dynamic_status.json' else path.name
        if key not in hashes:
            continue
        stat = path.stat()
        files[path.name] = {'size': stat.st_size, 'mtime_ns': stat.st_mtime_ns,
                            'sha256': hashes[key]}
    session_path = Path(session_path)
    binding = json.loads(session_path.read_text(encoding='utf-8'))
    binding['host_evidence'] = {'root': str(root), 'files': files,
                              'audit': str(session_path.parent / 'host_evidence_reads.jsonl')}
    temporary = session_path.with_suffix('.evidence.tmp')
    temporary.write_text(json.dumps(binding), encoding='utf-8')
    os.replace(temporary, session_path)


# ページサイズと走査量を制限し、巨大ログでも応答とメモリ使用量を一定にする。
def integer(request, key, default, low, high):
    value = request.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{key} must be an integer in {low}..{high}')
    return value


# ファイルIDを固定目録から解決し、パストラバーサル・リンク・差替えを拒否する。
def resolve_file(config, file_id):
    if not isinstance(file_id, str) or file_id not in config['files']:
        raise ValueError('Unknown evidence file_id')
    root = Path(config['root'])
    path = root / file_id
    if path.is_symlink() or path.resolve(strict=True).parent != root:
        raise ValueError('Evidence path changed')
    expected = config['files'][file_id]
    stat = path.stat()
    if stat.st_size != expected['size'] or stat.st_mtime_ns != expected['mtime_ns']:
        raise ValueError('Evidence changed after staging')
    return path, expected


# 原文のバイト位置を保持し、文字列検索もページ単位で再開可能にする。
def read_evidence(binding, request):
    config = binding.get('host_evidence')
    if not config:
        raise ValueError('No Host evidence bound to this session')
    action = request['action']
    if action == 'host_evidence_list':
        return {'files': [dict(file_id=k, size=v['size'], sha256=v['sha256'])
                          for k, v in config['files'].items()], 'content_is_untrusted': True}
    path, expected = resolve_file(config, request.get('file_id'))
    offset = integer(request, 'offset', 0, 0, expected['size'])
    result = {'file_id': path.name, 'sha256': expected['sha256'], 'offset': offset,
              'size': expected['size'], 'content_is_untrusted': True}
    with path.open('rb') as stream:
        stream.seek(offset)
        if action == 'host_evidence_read':
            length = integer(request, 'limit', 16384, 1, 65536)
            data = stream.read(length)
            end = offset + len(data)
            result['text'] = data.decode('utf-8-sig' if offset == 0 else 'utf-8', errors='replace')
        elif action == 'host_evidence_search':
            query = request.get('query')
            if not isinstance(query, str) or not 1 <= len(query) <= 256:
                raise ValueError('query must be 1..256 literal characters')
            needle = query.encode('utf-8')
            scan = integer(request, 'scan_bytes', 8388608, 1, 16777216)
            count = integer(request, 'limit', 10, 1, 30)
            stop = min(expected['size'], offset + scan)
            matches, end = [], offset
            while end < stop and len(matches) < count:
                start = end
                stream.seek(start)
                size = min(65536, stop - start)
                data = stream.read(size + len(needle) - 1)
                position = 0
                while len(matches) < count:
                    hit = data.find(needle, position)
                    if hit < 0 or hit >= size:
                        break
                    matches.append({'offset': start + hit,
                                    'text': data[max(0, hit-200):hit+len(needle)+300].decode('utf-8', errors='replace')})
                    position = hit + len(needle)
                end = min(expected['size'], start + (position if len(matches) == count else size))
            result['matches'] = matches
        else:
            raise ValueError('Unknown evidence action')
    # 途中で差し替わったファイルの内容を正常な証拠として返さない。
    resolve_file(config, path.name)
    result.update(next_offset=end, eof=end >= expected['size'])
    audit = {'time': datetime.now(timezone.utc).isoformat(), 'analysis_id': binding['analysis_id'],
             'action': action, 'file_id': path.name, 'offset': offset, 'next_offset': end,
             'sha256': expected['sha256'], 'returned_chars': len(result.get('text', '')),
             'matches': len(result.get('matches', []))}
    with Path(config['audit']).open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(audit) + '\n')
    return result
