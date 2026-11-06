"""Guest内だけでZIPを検証・展開する。展開物の実行は行わない。"""
import hashlib
import os
import re
import shutil
import stat
import tempfile
import time
from pathlib import Path


# 要求中の秘密値を応答やログへ複製しない。
def public_request(request):
    return {key: value for key, value in request.items() if key != "password"}


# Windowsで別パスとして解釈される名前や特殊ファイルを展開前に拒否する。
def member_parts(info):
    name = info.orig_filename.replace("\\", "/")
    if info.is_dir():
        name = name[:-1]
    parts = name.split("/")
    for part in parts:
        if (not part or part in (".", "..") or part.endswith((".", " "))
                or re.search(r'[<>:"|?*\x00-\x1f]', part)
                or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])", part.split(".")[0])):
            raise ValueError("Unsafe ZIP member path")
    kind = stat.S_IFMT(info.external_attr >> 16)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or info.external_attr & 0x400:
        raise ValueError("ZIP links and special files are not supported")
    return parts


# シンボリックリンクやjunctionを含む保存先を拒否し、既存領域の上書きを防ぐ。
def validate_destination(destination):
    path = Path(destination)
    if not path.is_absolute() or path.drive.startswith("\\\\"):
        raise ValueError("Destination must be an absolute local path")
    if any(part == ".." for part in path.parts):
        raise ValueError("Destination traversal is not allowed")
    if not path.name or re.search(r'[<>:"|?*\x00-\x1f]', path.name) or path.name.endswith((".", " ")):
        raise ValueError("Invalid destination name")
    for parent in (path, *path.parents):
        if os.path.lexists(parent):
            attrs = getattr(parent.lstat(), "st_file_attributes", 0)
            if parent.is_symlink() or attrs & 0x400:
                raise ValueError("Destination must not contain reparse points")
    if os.path.lexists(path):
        raise FileExistsError("Destination already exists; choose a new directory")
    if not path.parent.is_dir():
        raise ValueError("Destination parent must already exist")
    return path


# 全件を検証して一時領域へ展開し、整合性確認が完了した場合だけ保存先を公開する。
def extract_zip(archive_path, destination, password=None, max_total_bytes=4 * 1024**3,
                max_members=10000, max_seconds=300):
    import pyzipper

    if not isinstance(password, (str, type(None))):
        raise ValueError("Password must be a UTF-8 string")
    for value, ceiling in ((max_total_bytes, 4 * 1024**3), (max_members, 10000), (max_seconds, 300)):
        if type(value) is not int or not 0 < value <= ceiling:
            raise ValueError("Extraction limit is out of range")
    archive = Path(archive_path)
    if not archive.is_absolute() or archive.drive.startswith("\\\\") or not archive.is_file():
        raise ValueError("Archive must be an existing absolute local file")
    if archive.stat().st_size > 1024**3:
        raise ValueError("Archive exceeds 1 GiB input limit")
    target = validate_destination(destination)
    deadline = time.monotonic() + max_seconds
    staging = None
    try:
        with pyzipper.AESZipFile(str(archive)) as zf:
            infos = zf.infolist()
            if len(infos) > max_members or sum(i.file_size for i in infos) > max_total_bytes:
                raise ValueError("ZIP exceeds extraction limits")
            members, seen, files = [], set(), set()
            for info in infos:
                parts = member_parts(info)
                key = "/".join(parts).casefold()
                if key in seen:
                    raise ValueError("Duplicate ZIP member path")
                seen.add(key)
                if not info.is_dir():
                    files.add(key)
                members.append((info, parts))
            for _, parts in members:
                if any("/".join(parts[:i]).casefold() in files for i in range(1, len(parts))):
                    raise ValueError("ZIP file/directory path conflict")
            if any(i.flag_bits & 1 for i in infos) and not password:
                raise ValueError("Password is required for encrypted ZIP")
            zf.setpassword(password.encode("utf-8") if password else None)
            staging = Path(tempfile.mkdtemp(prefix=".zip-extract-", dir=target.parent))
            manifest, total = [], 0
            for info, parts in members:
                if time.monotonic() > deadline:
                    raise TimeoutError("ZIP extraction time limit exceeded")
                out = staging.joinpath(*parts)
                if info.is_dir():
                    out.mkdir(parents=True, exist_ok=True)
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                digest, size = hashlib.sha256(), 0
                # EOFまで読むことでCRCまたはAES認証エラーも確定前に検出する。
                with zf.open(info) as source, out.open("xb") as sink:
                    while chunk := source.read(1024 * 1024):
                        size += len(chunk)
                        total += len(chunk)
                        if total > max_total_bytes or size > info.file_size:
                            raise ValueError("Expanded data exceeds extraction limits")
                        if time.monotonic() > deadline:
                            raise TimeoutError("ZIP extraction time limit exceeded")
                        sink.write(chunk)
                        digest.update(chunk)
                if size != info.file_size:
                    raise ValueError("ZIP member size mismatch")
                manifest.append({"path": str(target.joinpath(*parts)), "size": size, "sha256": digest.hexdigest()})
        validate_destination(target)
        staging.rename(target)
        staging = None
        return {"destination": str(target), "files": manifest, "file_count": len(manifest), "total_bytes": total}
    finally:
        if staging is not None:
            # 自分が作った同一親配下の一時領域だけを削除する。
            if staging.resolve().parent == target.parent.resolve() and staging.name.startswith(".zip-extract-"):
                shutil.rmtree(staging)
