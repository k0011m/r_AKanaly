"""版・設定・進捗の永続化と、配布アーカイブの境界検証。"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import tempfile
import zipfile


# 同一ディレクトリで置換し、途中のJSONを次の起動に見せない。
def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


# 大きい配布物でもメモリへ丸ごと読み込まない。
def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


# 版名をディレクトリに使用するため、数値三要素の正式版だけを許す。
def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value):
        raise ValueError("Version must be MAJOR.MINOR.PATCH")
    return tuple(map(int, value.split(".")))


# Windowsの別名・ADS・リンク・大文字小文字衝突を展開前に拒否する。
def safe_member(name):
    if not isinstance(name, str) or not name or "\\" in name or ":" in name or "\0" in name:
        raise ValueError("Unsafe archive path")
    path = PureWindowsPath(name)
    parts = name.rstrip("/").split("/")
    if path.root or path.drive or any(p in ("", ".", "..") or p.endswith((".", " ")) or re.search(r'[<>"|?*\x00-\x1f]', p) or re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', p) for p in parts):
        raise ValueError("Unsafe archive path: " + name)
    return parts


# 新規の空ディレクトリにだけ展開し、失敗時に稼働版へ影響させない。
def extract_zip(archive, destination, limit=16 * 1024**3):
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError(destination)
    with zipfile.ZipFile(archive) as bundle:
        seen, size = set(), 0
        for item in bundle.infolist():
            safe_member(item.filename)
            key = item.filename.rstrip("/").casefold()
            if key in seen or ((item.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError("Duplicate path or archive link")
            seen.add(key)
            size += item.file_size
            if size > limit or len(seen) > 200000:
                raise ValueError("Archive exceeds extraction limit")
        destination.mkdir(parents=True)
        for item in bundle.infolist():
            target = destination.joinpath(*safe_member(item.filename))
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(item) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)


# 解析・構築・更新を同じOSロックに載せ、異常終了時もロックが解放されるようにする。
@contextmanager
def installation_lock(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".operation.lock").open("a+b") as stream:
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("Analysis, setup or update is already running") from None
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)
