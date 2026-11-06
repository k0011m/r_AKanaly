"""独立した第三者ツールを公式元から取得し、利用者環境内でGuest転送資材を作る。"""
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import urlsplit
import zipfile
from .releases import fetch
from .storage import digest, safe_member

ORIGINS = {
    'ghidra': ('github.com', '/NationalSecurityAgency/ghidra/releases/download/'),
    'jdk': ('github.com', '/adoptium/temurin21-binaries/releases/download/'),
    'die': ('github.com', '/horsicq/DIE-engine/releases/download/'),
    'floss': ('github.com', '/mandiant/flare-floss/releases/download/'),
    'capa': ('github.com', '/mandiant/capa/releases/download/'),
    'ilspy_gui': ('github.com', '/icsharpcode/ILSpy/releases/download/'),
    'ilspycmd': ('api.nuget.org', '/v3-flatcontainer/ilspycmd/'),
    'dotnet': ('builds.dotnet.microsoft.com', '/dotnet/'),
}


# 署名済みの取得指定でも、未知ツールや公式元以外のURLは受理しない。
def load(release):
    data = json.loads((Path(release)/'guest-downloads.json').read_text(encoding='utf-8'))
    if data.get('schema') != 1 or not isinstance(data.get('packages'), list):
        raise ValueError('Invalid Guest download manifest')
    records = data['packages']
    if len(records) != len(ORIGINS) or {r.get('tool') for r in records} != set(ORIGINS):
        raise ValueError('Guest download inventory mismatch')
    for record in records:
        url = urlsplit(record['url'])
        host, prefix = ORIGINS[record['tool']]
        if url.scheme != 'https' or url.hostname != host or not url.path.startswith(prefix) or url.username or url.password or url.port:
            raise ValueError('Official Guest download URL required: '+record['tool'])
        if not re.fullmatch('[0-9a-f]{64}', record.get('sha256', '')):
            raise ValueError('Invalid Guest download hash')
        if type(record.get('bytes')) is not int or not 0 < record['bytes'] <= 2*1024**3:
            raise ValueError('Invalid Guest download size')
        if len(safe_member(record['file'])) != 1:
            raise ValueError('Guest package filename must be a basename')
    return records


# ダウンロード完了と照合後にだけキャッシュへ確定し、不完全ファイルを再利用しない。
def download(record, cache, report):
    folder = cache/record['sha256']
    folder.mkdir(parents=True, exist_ok=True)
    target = folder/record['file']
    if target.is_file() and target.stat().st_size == record['bytes'] and digest(target) == record['sha256']:
        return target
    report('Downloading official Guest tool: '+record['tool'])
    with tempfile.TemporaryDirectory(dir=folder) as temporary:
        pending = Path(temporary)/'download'
        fetch(record['url'], pending, record['bytes'])
        if pending.stat().st_size != record['bytes'] or digest(pending) != record['sha256']:
            raise ValueError('Guest download size/hash mismatch: '+record['tool'])
        os.replace(pending, target)
    return target


# 元ZIPの先頭ディレクトリだけを除き、Guestの固定配置へ安全に写す。
def append_tree(bundle, source, destination):
    with zipfile.ZipFile(source) as archive:
        names = archive.infolist()
        roots = {safe_member(i.filename)[0] for i in names}
        if len(roots) != 1:
            raise ValueError('Expected single tool archive root')
        seen, total = set(), 0
        for info in names:
            parts = safe_member(info.filename)
            key = info.filename.rstrip('/').casefold()
            total += info.file_size
            if key in seen or ((info.external_attr >> 16) & 0o170000) == 0o120000 or total > 8*1024**3:
                raise ValueError('Unsafe tool archive')
            seen.add(key)
            if info.is_dir() or len(parts) == 1:
                continue
            with archive.open(info) as src, bundle.open(destination+'/'+ '/'.join(parts[1:]), 'w', force_zip64=True) as dst:
                shutil.copyfileobj(src, dst, 1024*1024)


# 通信はHostだけで行い、隔離したGuestへは検証済みの資材を渡す。
def prepare(release, root, report=print):
    records = load(release)
    cache = Path(root)/'external-tools'/'guest'
    paths = [(r, download(r, cache, report)) for r in records]
    cache.mkdir(parents=True, exist_ok=True)
    target = cache/'guest-tools.zip'
    with tempfile.TemporaryDirectory(dir=cache) as temporary:
        pending = Path(temporary)/'guest-tools.zip'
        with zipfile.ZipFile(pending, 'w', zipfile.ZIP_STORED) as bundle:
            packages = []
            for record, path in paths:
                if record['tool'] in ('jdk', 'ghidra'):
                    append_tree(bundle, path, record['tool'])
                else:
                    bundle.write(path, 'static-tool-packages/'+record['file'])
                    packages.append(record)
            bundle.writestr('static-tool-packages/manifest.json', json.dumps({'packages': packages}))
        os.replace(pending, target)
    return target
