"""完了した解析結果を検証付きの通常ZIPへ保存する。"""
import hashlib
from pathlib import Path
import shutil
import uuid
import zipfile


# 大きなログもメモリへ一括展開せず、元ファイルとZIP内の内容を照合する。
def digest(stream):
    value = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        value.update(chunk)
    return value.hexdigest()


# リンク先やジャンクションを辿って解析フォルダ外を回収・削除しない。
def inventory(root):
    paths = sorted(root.rglob('*'))
    for path in [root, *paths]:
        if path.is_symlink() or path.is_junction():
            raise RuntimeError(f'解析結果にリンクが含まれています: {path}')
    return paths


# レポートと全成果物を照合し、完成ZIPを確定した後だけ元フォルダを削除する。
def archive_results(directory, report):
    root = Path(directory).absolute()
    report = Path(report).absolute()
    if not root.is_dir() or not report.is_file() or report.stat().st_size == 0:
        raise RuntimeError('ZIP化には保存済みの空でないレポートが必要です')
    if root not in report.parents or root == root.parent:
        raise RuntimeError('レポートが解析結果フォルダ内にありません')
    target = root.with_name(root.name + '.zip')
    if target.exists():
        raise RuntimeError(f'既存ZIPを上書きしません: {target}')
    temporary = root.with_name(root.name + '.' + uuid.uuid4().hex + '.zip.tmp')
    try:
        paths = inventory(root)
        hashes = {}
        with zipfile.ZipFile(temporary, 'x', compression=zipfile.ZIP_DEFLATED,
                             compresslevel=1, allowZip64=True) as archive:
            for path in paths:
                name = path.relative_to(root).as_posix()
                if path.is_dir():
                    archive.writestr(name + '/', b'')
                else:
                    with path.open('rb') as source:
                        hashes[name] = digest(source)
                    archive.write(path, name)
        # CRCだけでなく、ZIP内の全ファイルを元データのSHA-256と比較する。
        with zipfile.ZipFile(temporary) as archive:
            for name, expected in hashes.items():
                with archive.open(name) as source:
                    if digest(source) != expected:
                        raise RuntimeError(f'ZIP内容の照合に失敗しました: {name}')
        if paths != inventory(root):
            raise RuntimeError('ZIP作成中に成果物一覧が変化しました')
        for name, expected in hashes.items():
            with (root / name).open('rb') as source:
                if digest(source) != expected:
                    raise RuntimeError(f'ZIP作成中に成果物が更新されました: {name}')
        temporary.rename(target)
        shutil.rmtree(root)
        return target
    except Exception as error:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f'解析結果のZIP保存・元フォルダ削除に失敗: {error}') from error
