"""Guest原本の全件照合後に限り、Hostで読み取り用データを生成する。"""
from concurrent.futures import ThreadPoolExecutor, wait
import threading
import time
import hashlib
import tui_runtime
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
import re


# 起動区間別ログも平坦な固定形式に限定し、Guest指定の任意ファイル回収を防ぐ。
def allowed_artifact(name):
    return isinstance(name, str) and (name in {
        'sysmon.evtx', 'procmon.pml', 'etw.etl', 'execution.json', 'capture.json',
        'system.evtx', 'tasks.evtx', 'configuration_baseline.json'} or bool(re.fullmatch(
        r'(?:procmon_[a-f0-9]{32}\.pml|etw_[a-f0-9]{32}\.etl|capture_[a-f0-9]{32}\.json|'
        r'configuration_[0-9]{8}T[0-9]{13}Z\.json|(?:processes|shutdown)_[0-9]{8}T[0-9]{13}Z\.jsonl)', name)))


# 設定の現存差分を作り、イベント履歴とは区別してレポートへ渡す。
def configuration_differences(root):
    root = Path(root)
    baseline = root / 'configuration_baseline.json'
    if not baseline.exists():
        return
    first = json.loads(baseline.read_text(encoding='utf-8-sig'))
    results = []
    for path in sorted(root.glob('configuration_*.json')):
        if path == baseline:
            continue
        current = json.loads(path.read_text(encoding='utf-8-sig'))
        changes = {}
        for category, key in (('tasks', 'name'), ('services', 'Name'), ('registry', 'path'), ('startup', 'FullName')):
            before = {item[key]: item for item in first.get(category, [])}
            after = {item[key]: item for item in current.get(category, [])}
            changes[category] = {'added': [after[k] for k in after.keys() - before.keys()],
                                 'removed': [before[k] for k in before.keys() - after.keys()],
                                 'changed': [{'before': before[k], 'after': after[k]} for k in before.keys() & after.keys() if before[k] != after[k]]}
        results.append({'source': path.name, 'boot_id': current.get('boot_id'), 'changes': changes,
                        'baseline_errors': first.get('errors', []), 'current_errors': current.get('errors', [])})
    (root / 'configuration_diff.json').write_text(json.dumps({'comparisons': results,
        'meaning': 'Present-state differences, not proof of actor identity or complete change history.'}, ensure_ascii=False, indent=2), encoding='utf-8')


# 大きな原本もメモリへ一括展開せず照合する。
def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


# Guestが指定するパスを信頼せず、原本の固定名だけを許可する。
def validate_manifest(manifest, analysis_id):
    if manifest.get('analysis_id') != analysis_id:
        raise RuntimeError('Dynamic manifest belongs to another run')
    seen = set()
    for item in manifest.get('files', []):
        name = item.get('name')
        if not allowed_artifact(name) or name in seen:
            raise RuntimeError('Unexpected or duplicate dynamic artifact')
        if not isinstance(item.get('size'), int) or item['size'] < 0:
            raise RuntimeError('Invalid artifact size')
        digest = item.get('sha256', '')
        if len(digest) != 64 or any(c not in '0123456789abcdefABCDEF' for c in digest):
            raise RuntimeError('Invalid artifact digest')
        seen.add(name)
    if 'capture.json' not in seen:
        raise RuntimeError('Capture status is missing')
    return manifest['files']


# 変換コマンドの失敗を証拠欠損として残し、正常なログに見せない。
def convert_command(command, log, timeout):
    with Path(log).open('wb') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                timeout=timeout, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise RuntimeError(f'Converter exited with {result.returncode}; see {Path(log).name}')


# ネイティブAPIのXMLを従来と同じJSONL項目へ変換し、全イベントを保持する。
def convert_evtx(source, destination, progress=None, timeout=None):
    from native_evtx import event_xml
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    started = time.monotonic()
    count = 0
    events = event_xml(Path(source).resolve())
    try:
        with Path(destination).open('w', encoding='utf-8') as output:
            for raw in events:
                if timeout is not None and time.monotonic() - started > timeout:
                    raise TimeoutError('EVTX conversion timed out')
                root = ET.fromstring(raw)
                data = {node.get('Name'): node.text for node in root.findall('e:EventData/e:Data', ns)}
                timestamp = root.find('e:System/e:TimeCreated', ns)
                value = {'record_id': int(root.findtext('e:System/e:EventRecordID', namespaces=ns)),
                         'event_id': root.findtext('e:System/e:EventID', namespaces=ns),
                         'utc': timestamp.get('SystemTime') if timestamp is not None else None,
                         'data': data, 'xml': raw}
                output.write(json.dumps(value, ensure_ascii=False) + '\n')
                count += 1
                if progress and count % 1000 == 0:
                    progress(count)
    finally:
        events.close()
    if progress:
        progress(count)
    return count


# 全原本を再照合してから、Host上の変換ツールだけを呼び出す。
def convert_all(root, manifest, settings):
    root = Path(root)
    files = validate_manifest(manifest, manifest['analysis_id'])
    for item in files:
        path = root / item['name']
        if path.stat().st_size != item['size'] or sha256(path).lower() != item['sha256'].lower():
            raise RuntimeError('Integrity failure before conversion: ' + item['name'])
    configuration_differences(root)
    status = {'analysis_id': manifest['analysis_id'], 'all_raw_hashes_verified': True,
              'capture': json.loads((root / 'capture.json').read_text(encoding='utf-8-sig')),
              'conversions': {}, 'artifacts': []}
    # 最後の起動区間が成功しても、前区間の欠損・停止中断を消さない。
    segments = [json.loads((root / item['name']).read_text(encoding='utf-8-sig'))
                for item in files if re.fullmatch(r'capture_[a-f0-9]{32}\.json', item['name'])]
    status['capture_segments'] = segments
    if any(not segment.get('success') or not segment.get('observation_complete') for segment in segments):
        status['capture']['success'] = False
        status['capture']['observation_complete'] = False
        status['capture'].setdefault('errors', []).append('Earlier boot segment was incomplete; inspect capture_segments')
    timeout = settings['conversion_timeout_seconds']
    progress_lock = threading.Lock()
    procmon_lock = threading.Lock()
    progress_state = {}
    # 独立した出力先を持つ変換だけを最大2件並列で進める。
    def convert_one(item):
        source = root / item['name']
        if source.suffix not in {'.evtx', '.pml', '.etl'}:
            return
        target = source.with_suffix({'.evtx': '.jsonl', '.pml': '.csv', '.etl': '.xml'}[source.suffix])
        entry = {'success': False, 'source': source.name, 'output': target.name}
        started = time.monotonic()
        with progress_lock:
            progress_state[source.name] = {'started': started, 'target': target, 'count': None, 'state': '変換中'}
        # ワーカーは件数だけ共有し、端末描画は管理スレッドで行う。
        def report(count):
            with progress_lock:
                progress_state[source.name]['count'] = count
        try:
            if source.suffix == '.evtx':
                entry['records'] = convert_evtx(source, target, progress=report, timeout=timeout)
                entry['reader'] = 'Windows Event Log API'
            elif source.suffix == '.pml':
                # /OpenLogと/SaveAsだけを使い、Hostでキャプチャを開始しない。
                tool = Path(settings['host_procmon_path'])
                if not tool.is_absolute():
                    from config import APPLICATION_DIR
                    external = APPLICATION_DIR / tool
                    tool = external if external.exists() else Path(__file__).resolve().parent / tool
                # Procmonの複数区間変換は同一アプリの取り合いを避けて直列化する。
                with procmon_lock:
                    convert_command([str(tool), '/AcceptEula', '/Quiet', '/OpenLog', str(source), '/SaveAs', str(target)],
                                    root / (source.stem + '_conversion.log'), timeout)
            else:
                convert_command(['tracerpt.exe', str(source), '-o', str(target), '-of', 'XML', '-y',
                                 '-summary', str(root / (source.stem + '_summary.txt')), '-report', str(root / (source.stem + '_report.xml'))],
                                root / (source.stem + '_conversion.log'), timeout)
            if not target.is_file() or target.stat().st_size == 0:
                raise RuntimeError('Converter produced no readable output')
            entry.update(success=True, sha256=sha256(target), size=target.stat().st_size)
        except Exception as error:
            entry['error'] = str(error)
            if target.exists():
                partial = target.with_name(target.name + '.partial')
                target.replace(partial)
                entry['partial_output'] = partial.name
        entry['seconds'] = round(time.monotonic() - started, 3)
        with progress_lock:
            progress_state[source.name]['state'] = '完了' if entry['success'] else '失敗'
            progress_state[source.name]['elapsed'] = entry['seconds']
        return source.name, entry

    # ワーカーの出力サイズ・件数を1秒ごとにまとめ、更新競合を防ぐ。
    def show_progress():
        rows = []
        with progress_lock:
            snapshot = {name: dict(value) for name, value in progress_state.items()}
        for name, value in snapshot.items():
            elapsed = value.get('elapsed', time.monotonic() - value['started'])
            try:
                size = value['target'].stat().st_size / 1000000
            except OSError:
                size = 0
            count = f" / {value['count']:,}件" if value['count'] is not None else ''
            rows.append(f"{name}: {value['state']}{count} / 出力{size:.1f}MB / 経過{elapsed:.0f}秒")
        tui_runtime.set_status('全原本照合済み。Hostで最大2件を並列変換しています\n' + '\n'.join(rows))

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix='log-convert') as pool:
        pending = {pool.submit(convert_one, item) for item in files
                   if Path(item['name']).suffix in {'.evtx', '.pml', '.etl'}}
        while pending:
            done, pending = wait(pending, timeout=1)
            for future in done:
                name, entry = future.result()
                status['conversions'][name] = entry
            show_progress()
    status['conversion_complete'] = bool(status['conversions']) and all(e['success'] for e in status['conversions'].values())
    execution = root / 'execution.json'
    status['execution'] = json.loads(execution.read_text(encoding='utf-8-sig')) if execution.exists() else {'started': False, 'reason': 'execution_status_missing'}
    # ログ変換成功だけで、未完了のLLM調査や観測タイムアウトを成功扱いしない。
    execution, capture = status['execution'], status['capture']
    status['dynamic_success'] = bool(capture.get('success') and capture.get('observation_complete')
        and execution.get('started') and not execution.get('error')
        and execution.get('reason') in ('process_tree_exited', 'investigation_finished')
        and status['conversion_complete'])
    for path in sorted(root.iterdir()):
        if path.is_file() and path.name != 'dynamic_status.json' and not path.name.startswith(('.', 'request_', 'active.')):
            status['artifacts'].append({'name': path.name, 'size': path.stat().st_size, 'sha256': sha256(path)})
    status['interpretation'] = 'Missing, failed, truncated or undecoded evidence is not evidence of absent behavior.'
    (root / 'dynamic_status.json').write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding='utf-8')
    return root / 'dynamic_status.json'
