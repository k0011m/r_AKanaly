"""Guest内の検体配置、表層解析、追加ツール、回収専用ZIPを処理する。"""
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import time
import uuid
import zipfile

TOOLS = Path(r'C:\Users\Public\r_AKanaly\static-tools.json')


# 通常実行せず読み取った検体情報をフェーズ間の照合に使う。
def fingerprint(path):
    path = Path(path)
    hashes = {}
    for algorithm in ('md5', 'sha1', 'sha256'):
        with path.open('rb') as stream:
            hashes[algorithm] = hashlib.file_digest(stream, algorithm).hexdigest()
    return dict(hashes, size=path.stat().st_size, path=str(path), name=path.name)


# 配置定義を正本として追加ツールの実行条件を解決する。
def tool_command(tool, sample=None):
    config = json.loads(TOOLS.read_text(encoding='utf-8-sig'))
    paths = config['paths']
    commands = {'die': [paths['diec'], '-j'], 'floss': [paths['floss'], '-j'],
                'capa': [paths['capa'], '-j'],
                'ilspy': [paths['dotnet'], paths['ilspycmd_dll'], '--disable-updatecheck']}
    if tool not in commands:
        raise ValueError('Unknown registered tool')
    command = commands[tool]
    if sample is not None:
        command.append(str(sample))
    return command, dict(os.environ, **config.get('dotnet_environment', {})), config


# CLIの出力をファイルへ流し、長大な出力をプロセスメモリに保持しない。
def run_tool(request, root):
    tool = request['tool']
    command, environment, config = tool_command(tool, request['sample_path'])
    output = Path(root) / 'results' / request['analysis_id'] / request['request_id']
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with (output / 'stdout.txt').open('wb') as stdout, (output / 'stderr.txt').open('wb') as stderr:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   env=environment, creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            code = process.wait(timeout=min(1800, max(1, int(request.get('tool_timeout', 600)))))
        except subprocess.TimeoutExpired:
            # 子プロセスも残さず停止し、取得済み出力は根拠として保持する。
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True)
            process.wait(timeout=20)
            code = None
    record = {'tool': tool, 'command': command, 'exit_code': code, 'timed_out': code is None,
              'elapsed_seconds': time.monotonic() - started, 'result_id': request['request_id'],
              'version_info': config.get('packages', {}), 'output_path': str(output)}
    (output / 'manifest.json').write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    return dict(record, preview=(output / 'stdout.txt').read_bytes()[:12000].decode('utf-8', errors='replace'))


# 結果IDと固定ファイル名からだけ読み出し、検体ファイルの回収口にしない。
def read_result(request, root):
    result_id = uuid.UUID(request['result_id']).hex
    stream = request.get('stream', 'stdout')
    if stream not in ('stdout', 'stderr'):
        raise ValueError('Invalid result stream')
    path = Path(root) / 'results' / request['analysis_id'] / result_id / (stream + '.txt')
    offset = max(0, int(request.get('offset', 0)))
    length = min(64000, max(1, int(request.get('limit', 12000))))
    with path.open('rb') as handle:
        handle.seek(offset)
        data = handle.read(length)
    return {'text': data.decode('utf-8', errors='replace'), 'offset': offset,
            'next_offset': offset + len(data), 'total_bytes': path.stat().st_size,
            'has_more': offset + len(data) < path.stat().st_size}


# 登録済みGUIアプリを通常の子プロセスとして起動し、直接の検体起動は提供しない。
def launch_application(request):
    config = json.loads(TOOLS.read_text(encoding='utf-8-sig'))
    app = request.get('app')
    if app == 'notepad':
        executable = r'C:\Windows\System32\notepad.exe'
    elif app in ('die_gui', 'ilspy_gui'):
        executable = config['paths'][app]
    else:
        raise ValueError('App must be registered in static-tools.json')
    command = [executable]
    if request.get('open_sample') and app != 'notepad':
        command.append(request['sample_path'])
    process = subprocess.Popen(command, cwd=Path(executable).parent)
    return {'app': app, 'pid': process.pid}


# 検体投入前に保存領域、ツール本体、依存環境を実動作で確認する。
def check_tools(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    probe = root / (uuid.uuid4().hex + '.probe')
    probe.write_text('ready', encoding='ascii')
    probe.unlink()
    if shutil.disk_usage(root).free < 1024**3:
        raise RuntimeError('Guest needs at least 1 GiB free space')
    config = json.loads(TOOLS.read_text(encoding='utf-8-sig'))
    for name, path in config['paths'].items():
        if not Path(path).is_file():
            raise RuntimeError('Missing configured tool: ' + name)
    for tool in ('die', 'floss', 'capa', 'ilspy'):
        command, environment, _ = tool_command(tool)
        if tool in ('die', 'floss', 'capa'):
            command = command[:1]
        command.append('--help' if tool == 'die' else '--version')
        completed = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL,
                                   capture_output=True, timeout=40, creationflags=subprocess.CREATE_NO_WINDOW)
        if completed.returncode:
            raise RuntimeError('CLI readiness failed: ' + tool)
    return {'tools': list(config['paths']), 'free_bytes': shutil.disk_usage(root).free}


# ZIPはGuestでのみ展開し、対象メンバーを動的・静的解析の指定先へ配置する。
def prepare_sample(request):
    source, target = Path(request['source']), Path(request['target'])
    if request.get('archive'):
        from archive_ops import extract_zip
        destination = source.parent / ('expanded_' + uuid.uuid4().hex)
        result = extract_zip(str(source), str(destination), request.get('password'),
                             max_total_bytes=request.get('max_bytes', 4 * 1024**3))
        wanted = destination.joinpath(*request['member'].replace('\\', '/').split('/'))
        if not wanted.resolve().is_relative_to(destination.resolve()) or str(wanted) not in {x['path'] for x in result['files']}:
            raise ValueError('Configured ZIP member not found')
        source = wanted
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    result = fingerprint(target)
    result['original_name'] = request.get('original_name', target.name)
    if request.get('expected_sha256') and result['sha256'] != request['expected_sha256']:
        raise RuntimeError('Sample SHA-256 differs from surface analysis')
    if request.get('yara_rule'):
        import yara
        rules = yara.compile(filepath=request['yara_rule'])
        result['yara'] = [str(x) for x in rules.match(str(target), timeout=60)]
    else:
        result['yara'] = None
    return result


# 保存済みプロジェクトと指定形式の結果だけを回収し、検体領域を含めない。
def export_artifacts(request, root):
    root = Path(root)
    analysis = request['analysis_id']
    if not analysis.startswith('analysis_') or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789_' for c in analysis):
        raise ValueError('Invalid analysis ID')
    export = root / 'exports'
    export.mkdir(exist_ok=True)
    target = export / (analysis + '.zip')
    manifest = {'analysis_id': analysis, 'files': [], 'contains_original_sample': False,
                'ghidra_may_contain_sample_bytes': True}
    candidates = []
    if request.get('project_saved'):
        projects = root / 'projects'
        markers = [p for p in projects.glob(analysis + '*.gpr')
                   if p.stem == analysis or re.fullmatch(re.escape(analysis) + r'_artifact_\d+', p.stem)]
        if not markers:
            raise RuntimeError('Saved Ghidra project marker not found')
        # 切替時に保存した子のプロジェクトも、元検体と一緒に回収する。
        for marker in markers:
            candidates.append((marker, Path('ghidra') / marker.name))
            repository = marker.with_suffix('.rep')
            if not repository.is_dir():
                raise RuntimeError('Saved Ghidra repository not found')
            candidates += [(p, Path('ghidra') / p.relative_to(projects)) for p in repository.rglob('*') if p.is_file()]
    results = root / 'results' / analysis
    if results.exists():
        candidates += [(p, Path('tools') / p.relative_to(results)) for p in results.rglob('*') if p.is_file() and p.suffix in ('.txt', '.json')]
    with zipfile.ZipFile(target.with_suffix('.tmp'), 'w', zipfile.ZIP_DEFLATED) as archive:
        for path, name in candidates:
            if any(getattr(p.lstat(), 'st_file_attributes', 0) & 0x400 for p in (path, *path.parents)):
                raise ValueError('Reparse points are not exported')
            archive.write(path, name.as_posix())
            manifest['files'].append(dict(fingerprint(path), archive_path=name.as_posix()))
        for role in ('os', 'ghidra'):
            for directory in ('accepted', 'responses'):
                for path in (root / role / directory).glob('*.json'):
                    record = json.loads(path.read_text(encoding='utf-8'))
                    if record.get('analysis_id') == analysis:
                        archive.writestr('operations/' + role + '/' + directory + '/' + path.name,
                                         json.dumps(record, ensure_ascii=False))
        archive.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
    target.with_suffix('.tmp').replace(target)
    return fingerprint(target)


# 秘密値を常駐受付の台帳へ渡さず、Guest Operationsの一時要求で配置する。
def main():
    import sys
    request_path, response_path = map(Path, sys.argv[1:3])
    request = {}
    try:
        request = json.loads(request_path.read_text(encoding='utf-8'))
        request_path.unlink()
        result = {'ok': True, 'result': prepare_sample(request)}
    except Exception as error:
        # 診断に必要な原因を残しつつ、入力した秘密値は応答から除去する。
        message = str(error)
        if request.get('password'):
            message = message.replace(request['password'], '[REDACTED]')
        result = {'ok': False, 'error': type(error).__name__, 'message': message}
    finally:
        request_path.unlink(missing_ok=True)
    response_path.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')


if __name__ == '__main__':
    main()
