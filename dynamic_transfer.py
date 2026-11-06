"""Guest原本の可逆圧縮転送。全原本の検証後だけ既存の変換へ渡す。"""
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid
import zlib

from dynamic_evidence import sha256
from vmrun_errors import ErrorContext, error_details
import tui_runtime


# 設定された固定ファイル名と一致する輸送目録のみ受け入れる。
def validate_transport(value, files, analysis_id, token):
    if (value.get('analysis_id') != analysis_id or value.get('token') != token
            or value.get('success') is not True or value.get('format') != 'gzip'):
        raise RuntimeError('Guest compression failed: ' + str(value.get('error', 'invalid response')))
    entries = value.get('files')
    expected = {item['name']: item for item in files}
    if not isinstance(entries, list) or len(entries) != len(expected):
        raise RuntimeError('Compressed manifest file count mismatch')
    result = {}
    for item in entries:
        name = item.get('name')
        if name not in expected or name in result or item.get('archive') != name + '.gz':
            raise RuntimeError('Unexpected compressed artifact name')
        raw = expected[name]
        if item.get('size') != raw['size'] or item.get('sha256', '').lower() != raw['sha256'].lower():
            raise RuntimeError('Compressed manifest raw identity mismatch')
        size, digest = item.get('compressed_size'), item.get('compressed_sha256')
        if (type(size) is not int or size <= 0 or not isinstance(digest, str)
                or len(digest) != 64 or any(c not in '0123456789abcdefABCDEF' for c in digest)):
            raise RuntimeError('Invalid compressed artifact size/hash')
        result[name] = item
    return result


# 展開上限と原本ハッシュを確認するまで、回収済み原本を置き換えない。
def unpack_verified(archive, destination, item, progress=None):
    destination = Path(destination)
    temporary = destination.with_name(destination.name + '.unpacking')
    digest = hashlib.sha256()
    total = 0
    # 転送・展開・保存のどの境界で失敗したかを呼出し元へ渡す。
    def stage(value):
        if progress:
            progress(value)
    try:
        stage('unpack_open')
        with gzip.open(archive, 'rb') as source, temporary.open('wb') as target:
            while True:
                stage('decompression')
                block = source.read(min(1024 * 1024, item['size'] - total + 1))
                if not block:
                    break
                total += len(block)
                if total > item['size']:
                    stage('raw_verification')
                    raise RuntimeError('Expanded artifact exceeds manifest size')
                stage('host_write')
                target.write(block)
                digest.update(block)
            stage('host_write')
        stage('raw_verification')
        if total != item['size'] or digest.hexdigest().lower() != item['sha256'].lower():
            raise RuntimeError(f"Expanded artifact hash/size mismatch: expected_size={item['size']}, actual_size={total}, expected_sha256={item['sha256']}, actual_sha256={digest.hexdigest()}")
        stage('finalize_file')
        temporary.replace(destination)
    finally:
        # 一時ファイル削除の失敗で元の書込み・照合エラーを隠さない。
        original_error = sys.exc_info()[1]
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            if original_error is None:
                stage('cleanup')
                raise


# 復元後のGuestでも、今回の回収ジョブだけに必要なヘルパーを実行する。
def prepare_transport(session, files):
    bundle = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
    script = bundle / 'VMWARE_GUEST_CONTROL_PACKAGE/guest/compress_dynamic_logs.ps1'
    if not script.is_file():
        raise RuntimeError('Compression helper missing: ' + str(script))
    token = uuid.uuid4().hex
    guest_script = session.run_root + '\\compress_dynamic_logs.ps1'
    session.guest('copyFileFromHostToGuest', script, guest_script)
    # このPowerShellだけ実行を許可する。同期実行で起動拒否・異常終了を即時にHostへ返す。
    # Guest全体の実行ポリシーは変更せず、圧縮時間だけ設定された上限を適用する。
    session.guest('runProgramInGuest', r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                  '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', guest_script,
                  '-RunRoot', session.run_root, '-AnalysisId', session.id, '-Token', token,
                  timeout=session.settings.get('compression_timeout_seconds', 1800))
    # 正常終了後には応答が存在するはずなので、長い圧縮待機を繰り返さず直接回収する。
    target = session.output / ('.transport_' + token + '.json')
    session.guest('copyFileFromGuestToHost', session.run_root + '\\transport_' + token + '.json', target)
    value = json.loads(target.read_text(encoding='utf-8-sig'))
    entries = validate_transport(value, files, session.id, token)
    (session.output / 'transport_manifest.json').write_text(
        json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    return entries


# 圧縮物・原本の二段階照合に成功したファイルだけを後続へ渡す。
def collect_compressed(session, files):
    started = time.monotonic()
    status = {'format': 'gzip', 'success': False, 'files': [], 'attempts': [], 'collection_id': uuid.uuid4().hex}
    current_stage = 'raw_reuse_verification'
    # 段階を記録し、一般例外も転送エラーと誤表示しない。
    def set_stage(value):
        nonlocal current_stage
        current_stage = value
    try:
        # 中断後の再回収では、照合済み原本が全件あればGuest圧縮を再実行しない。
        pending = [item for item in files if not (
            (session.output / item['name']).is_file()
            and (session.output / item['name']).stat().st_size == item['size']
            and sha256(session.output / item['name']).lower() == item['sha256'].lower())]
        if not pending:
            status.update(success=True, reused_all_raw=True)
            return
        tui_runtime.set_stage('ログ回収', 'Guestで原本ログを可逆圧縮しています')
        set_stage('prepare_transport')
        packed = prepare_transport(session, files)
        for item in pending:
            entry = packed[item['name']]
            archive = session.output / entry['archive']
            last_error = None
            tui_runtime.set_stage('ログ回収', '圧縮原本を転送・照合・展開: ' + item['name'])
            file_started = time.monotonic()
            for attempt in range(session.settings['transfer_attempts']):
                try:
                    set_stage('transfer')
                    session.guest('copyFileFromGuestToHost', session.run_root + '\\' + entry['archive'],
                                  archive, timeout=session.settings.get('transfer_timeout_seconds', 1800))
                    set_stage('compressed_verification')
                    actual_size, actual_hash = archive.stat().st_size, sha256(archive).lower()
                    if (actual_size != entry['compressed_size'] or actual_hash != entry['compressed_sha256'].lower()):
                        raise RuntimeError(f"Compressed artifact hash/size mismatch: expected_size={entry['compressed_size']}, actual_size={actual_size}, expected_sha256={entry['compressed_sha256']}, actual_sha256={actual_hash}")
                    unpack_verified(archive, session.output / item['name'], item, progress=set_stage)
                    break
                except (OSError, EOFError, RuntimeError, zlib.error) as error:
                    last_error = error
                    detail = dict(name=item['name'], attempt=attempt + 1, stage=current_stage,
                                  type=type(error).__name__, message=str(error),
                                  errno=getattr(error, 'errno', None), winerror=getattr(error, 'winerror', None),
                                  details=error_details(error), collection_id=status['collection_id'])
                    status['attempts'].append(detail)
                    # 再回収や途中終了でも初回の試行記録を上書きしない。
                    with (session.output / 'transfer_attempts.jsonl').open('a', encoding='utf-8') as log:
                        log.write(json.dumps(detail, ensure_ascii=False) + '\n')
            else:
                raise ErrorContext(f"Compressed artifact failed at {current_stage}: {item['name']}: {last_error}", last_error)
            status['files'].append({'name': item['name'], 'raw_bytes': item['size'],
                                    'compressed_bytes': entry['compressed_size'],
                                    'seconds': round(time.monotonic() - file_started, 3)})
            # 正常展開後の輸送用コピーだけを削除し、原本は保持する。
            set_stage('cleanup')
            archive.unlink()
        status['success'] = True
    except Exception as error:
        status['error'] = str(error)
        status['stage'] = current_stage
        status['error_details'] = error_details(error)
        raise
    finally:
        status['seconds'] = round(time.monotonic() - started, 3)
        (session.output / ('transfer_status_' + status['collection_id'] + '.json')).write_text(
            json.dumps(status, ensure_ascii=False, indent=2), encoding='utf-8')
        (session.output / 'transfer_status.json').write_text(
            json.dumps(status, ensure_ascii=False, indent=2), encoding='utf-8')
