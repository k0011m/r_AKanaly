"""フォルダ内の検体を単一VMで順番に既存解析へ渡す。"""
import copy
import json
import os
import re
from pathlib import Path
import stat
import uuid
import time
import zipfile
from datetime import datetime, timezone
import tui_runtime
from vmrun_errors import error_details


# 一時的な停止・状態照会エラーを再試行し、秘密を除いたvmrun情報を結果へ残す。
def recover_after_failure(cache, entry):
    entry['recovery_attempts'] = []
    for attempt in range(3):
        try:
            cache['recover_vm']()
            entry['recovery'] = 'success'
            return True
        except Exception as error:
            detail = error_details(error)
            entry['recovery_attempts'].append({
                'attempt': attempt + 1, 'error_type': type(error).__name__,
                'vmrun_errors': detail['vmrun_errors']})
            entry['recovery_error_type'] = type(error).__name__
            if attempt < 2:
                tui_runtime.set_status(f'VM復旧を再試行します（{attempt + 2}/3）')
                time.sleep(2)
    entry['recovery'] = 'failed'
    return False


# フルオートの型と項目を検証し、綴り間違いで別モードを実行しない。
def options(data):
    value = data.get('full_auto', {})
    if not isinstance(value, dict) or set(value) - {'enabled', 'recursive'}:
        raise ValueError('full_auto accepts enabled and recursive only')
    result = dict(enabled=False, recursive=True)
    result.update(value)
    if any(type(v) is not bool for v in result.values()):
        raise ValueError('full_auto.enabled / recursive must be boolean')
    return result


# 再解析で生成されるファイルを拾わないよう、開始時に一覧を確定する。
def discover(folder, recursive):
    folder = Path(folder).resolve()
    if not folder.is_dir():
        raise ValueError('フルオートのmalware_transfer.host_pathにはフォルダを指定してください')
    found = []
    for root, dirs, names in os.walk(folder, followlinks=False):
        # ジャンクション等で指定範囲の外を走査しない。
        dirs[:] = sorted(d for d in dirs if not (Path(root, d).lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)) if os.name == 'nt' else sorted(d for d in dirs if not Path(root, d).is_symlink())
        for name in sorted(names):
            path = Path(root, name)
            if path.suffix.lower() not in ('.exe', '.zip') or path.is_symlink():
                continue
            if os.name == 'nt' and path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                continue
            if path.is_file():
                found.append(path)
        if not recursive:
            break
    if not found:
        raise ValueError('指定フォルダにEXE・ZIPがありません')
    return sorted(found, key=lambda p: str(p).casefold())


# ZIPは目録だけを読み、対象EXEを一意に決める。Hostでは復号・展開しない。
def child_settings(data, source):
    from r_akanaly import validate_zip_member_name
    child = copy.deepcopy(data)
    child['full_auto'] = {'enabled': False, 'recursive': False}
    transfer = child['malware_transfer']
    transfer['host_path'] = str(source)
    transfer['source_type'] = 'zip' if source.suffix.lower() == '.zip' else 'file'
    transfer['zip_member'] = None
    if source.suffix.lower() == '.zip':
        try:
            with zipfile.ZipFile(source) as archive:
                names = [i.filename for i in archive.infolist() if not i.is_dir() and i.filename.lower().endswith('.exe')]
        except zipfile.BadZipFile as error:
            raise ValueError('ZIPの目録を読めません: ' + str(source)) from error
        if len(names) != 1:
            raise ValueError('ZIP内のEXEは1件にしてください: ' + str(source))
        transfer['zip_member'] = validate_zip_member_name(names[0])
    return child


# 検体ごとの失敗を保存して順次続行し、キャンセルやVM復旧不能時だけ全体を停止する。
def run_batch(data, settings_path, argv, dry_run, runner):
    from config import APPLICATION_DIR
    config = options(data)
    raw = data.get('malware_transfer', {}).get('host_path')
    if not raw:
        raise ValueError('フルオートの対象フォルダが未設定です')
    folder = Path(raw).expanduser()
    if not folder.is_absolute():
        folder = Path(settings_path).resolve().parent / folder
    sources = discover(folder, config['recursive'])
    jobs = []
    input_errors = {}
    for index, path in enumerate(sources):
        try:
            jobs.append(child_settings(data, path))
        except (ValueError, OSError) as error:
            jobs.append(None)
            input_errors[index] = str(error)
    if dry_run:
        print('Full auto dry-run: ' + str(len(jobs)) + ' samples')
        for index, path in enumerate(sources):
            print(str(path) + (': ' + input_errors[index] if index in input_errors else ''))
        return 1 if input_errors else 0
    # レポート保存先を基準に、一括実行全体を衝突しない親フォルダへまとめる。
    base = (data.get('llm', {}).get('analysis_output_dir')
            or data.get('output_directories', {}).get('common_output_dir')
            or str(APPLICATION_DIR / 'output'))
    base = Path(base).expanduser()
    if not base.is_absolute():
        base = Path(settings_path).resolve().parent / base
    root = base.resolve() / ('batch_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:8])
    root.mkdir(parents=True)
    destinations = [root / (f'{i + 1:03d}_' + re.sub(r'[^\w.-]', '_', p.stem)[:100])
                    for i, p in enumerate(sources)]
    state = {'started_utc': datetime.now(timezone.utc).isoformat(), 'state': 'running',
             'output_directory': str(root),
             'jobs': [{'input': str(p), 'state': 'pending', 'output_directory': str(destinations[i])}
                      for i, p in enumerate(sources)]}
    # パスワードや設定全体は保存せず、キュー状態だけを原子的に更新する。
    def save():
        temp = root / 'batch_status.tmp'
        temp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')
        temp.replace(root / 'batch_status.json')
        # 初期化前の失敗も、検体別フォルダから理由を確認できるようにする。
        for entry in state['jobs']:
            destination = Path(entry['output_directory'])
            if destination.is_dir():
                pending = destination / 'batch_job_status.tmp'
                pending.write_text(json.dumps(entry, ensure_ascii=False, indent=2), encoding='utf-8')
                pending.replace(destination / 'batch_job_status.json')
    save()
    cache = {'batch_inputs': [str(p) for p in sources], 'batch_folder': str(folder.resolve())}
    try:
        if any(job is not None and job['malware_transfer']['source_type'] == 'zip' for job in jobs):
            from r_akanaly import collect_zip_password, parse_settings
            cache['zip_password'] = collect_zip_password(parse_settings(data).malware_transfer)
        for index, job in enumerate(jobs):
            entry = state['jobs'][index]
            tui_runtime.set_sample_progress(index + 1, len(jobs), sources[index].name)
            destinations[index].mkdir()
            cache['sample_output_dir'] = str(destinations[index])
            cache.pop('archive_report', None)
            cache.pop('operation_exit_code', None)
            cache.pop('final_result_directory', None)
            if job is None:
                entry.update(state='failed', exit_code=1, error=input_errors[index], stages={})
                save()
                continue
            entry['state'] = 'running'
            save()
            tui_runtime.set_status(f'フルオート {index + 1}/{len(jobs)}: {sources[index].name}')
            tui_runtime.reset_results()
            tui_runtime.show_error('')
            tui_runtime.set_outputs([])
            try:
                code = runner(argv, settings_override=job, batch_cache=cache,
                              batch_confirmed=cache.get('execution_confirmed', False))
            except Exception as error:
                # 詳細は単体側のログに残し、ここへ認証情報を含み得る例外文字列を複製しない。
                code = 1
                entry['error_type'] = type(error).__name__
            entry['exit_code'] = code
            entry['stages'] = copy.deepcopy(tui_runtime.STAGE_RESULTS)
            if code == 130 or any(v['state'] == 'cancelled' for v in entry['stages'].values()):
                entry['state'] = 'cancelled'
                state['state'] = 'cancelled'
                return code
            from report_outcome import inspect_report
            entry['operation_exit_code'] = cache.get('operation_exit_code', code)
            destinations[index] = Path(cache.get('final_result_directory', destinations[index]))
            entry['output_directory'] = str(destinations[index])
            entry['report_result'] = inspect_report(destinations[index])
            good = entry['report_result']['success']
            needs_recovery = entry['operation_exit_code'] != 0 or any(v['state'] != 'success' for v in entry['stages'].values())
            entry['exit_code'] = 0 if good else 1
            entry['state'] = 'success' if good else 'failed'
            save()
            # 単体の後処理と検体別結果の保存後、毎回ZIP化してから次の解析へ進む。
            report = cache.pop('archive_report', None)
            if report:
                from result_archive import archive_results
                try:
                    entry['archive_path'] = str(archive_results(destinations[index], report))
                    entry['source_directory_removed'] = True
                except RuntimeError as error:
                    entry.update(archive_error=str(error), operation_exit_code=1)
                    needs_recovery = True
                entry['report_result'] = inspect_report(destinations[index])
                good = entry['report_result']['success']
                entry.update(state='success' if good else 'failed', exit_code=0 if good else 1)
                save()
            if not good or needs_recovery:
                # 初回の実行承認前の問題は、次の検体へ承認を流用せず停止する。
                if not cache.get('execution_confirmed'):
                    state['state'] = 'stopped'
                    return code or 1
                tui_runtime.set_status('失敗した検体を記録し、次の解析に向けてVMの停止状態を確認しています')
                if not recover_after_failure(cache, entry):
                    state['state'] = 'stopped'
                    state['stop_reason'] = 'VM recovery failed after 3 attempts'
                    return 1
                save()
        failed = sum(entry['state'] == 'failed' for entry in state['jobs'])
        state['state'] = 'completed_with_errors' if failed else 'success'
        return 1 if failed else 0
    finally:
        if state['state'] == 'running':
            state['state'] = 'interrupted'
            for entry in state['jobs']:
                if entry['state'] == 'running':
                    entry['state'] = 'interrupted'
        save()
        tui_runtime.set_sample_progress(0, 0, '')
        print('フルオート結果: ' + str(root / 'batch_status.json'))
        summary = f"一括解析: {state['state']} / 成功 {sum(j['state'] == 'success' for j in state['jobs'])}件 / 失敗 {sum(j['state'] == 'failed' for j in state['jobs'])}件"
        print(summary)
        tui_runtime.set_status(summary)
        tui_runtime.set_outputs([('一括解析の保存先', str(root)), ('全件の結果', str(root / 'batch_status.json'))])
