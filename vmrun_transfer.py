"""vmrunのファイル転送だけを短いHost一時パスへ統一する。"""
import os
import errno
from pathlib import Path
import shutil
import tempfile
import uuid


# 認証オプションの値を操作名と誤認せず、vmrunの操作位置を特定する。
def operation_index(command):
    index = 1
    while index < len(command):
        if command[index] in ('-T', '-vp', '-gu', '-gp', '-h', '-P', '-u', '-p'):
            index += 2
        else:
            return index
    return None


# 受信成功時だけ正式保存先を原子的に更新し、転送失敗では既存成果物を保持する。
def run_staged(command, execute, **kwargs):
    args = list(command)
    index = operation_index(args)
    if index is None or args[index] not in ('copyFileFromHostToGuest', 'copyFileFromGuestToHost'):
        return execute(args, **kwargs)
    if len(args) != index + 4:
        raise ValueError('Unexpected vmrun file transfer arguments')
    upload = args[index] == 'copyFileFromHostToGuest'
    host_index = index + (2 if upload else 3)
    host = Path(args[host_index]).absolute()
    # 長いTEMP設定の場合はユーザーのローカルTempを候補にする。上限超過をvmrunへ渡さない。
    bases = [Path(tempfile.gettempdir())]
    if os.environ.get('LOCALAPPDATA'):
        bases.append(Path(os.environ['LOCALAPPDATA']) / 'Temp')
    base = next((p for p in bases if len(str(p.absolute())) + 32 < 240 and p.is_dir()), None)
    if base is None:
        raise RuntimeError('No short Host temporary directory available for vmrun transfer')
    with tempfile.TemporaryDirectory(prefix='rak_', dir=base) as temporary:
        staging = Path(temporary) / 'x'
        args[host_index] = str(staging)
        if upload:
            shutil.copyfile(host, staging)
        result = execute(args, **kwargs)
        if not upload and result.returncode == 0:
            host.parent.mkdir(parents=True, exist_ok=True)
            try:
                # 同一ボリュームでは巨大ログを再コピーせず、名前変更で確定する。
                os.replace(staging, host)
                return result
            except OSError as error:
                if error.errno != errno.EXDEV and getattr(error, 'winerror', None) != 17:
                    raise
            pending = host.with_name('.rak_' + uuid.uuid4().hex + '.tmp')
            try:
                shutil.copyfile(staging, pending)
                os.replace(pending, host)
            finally:
                pending.unlink(missing_ok=True)
        return result
