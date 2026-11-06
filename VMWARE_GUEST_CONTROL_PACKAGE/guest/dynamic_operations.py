"""動的解析だけの非同期起動。UAC待機をOSエージェントの受付から分離する。"""
import ctypes
from ctypes import wintypes as wt
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import time
import uuid
import struct
from analysis_runtime import write_json

ACTIONS = ('launch_sample', 'launch_analysis_app', 'process_status', 'stop_process')


# Guest上のヘッダーだけを読み、拡張子に依存せずDLL属性を記録する。コードはロードしない。
def inspect_pe(path):
    try:
        with Path(path).open('rb') as stream:
            size = stream.seek(0, 2)
            stream.seek(0)
            dos = stream.read(64)
            if len(dos) != 64 or dos[:2] != b'MZ':
                raise ValueError('Missing DOS header')
            offset = struct.unpack_from('<I', dos, 60)[0]
            if offset < 64 or offset > size - 26:
                raise ValueError('Invalid PE header offset')
            stream.seek(offset)
            header = stream.read(26)
            if header[:4] != b'PE\0\0':
                raise ValueError('Missing PE signature')
            machine, = struct.unpack_from('<H', header, 4)
            characteristics, = struct.unpack_from('<H', header, 22)
            return {'format': 'PE', 'machine': machine, 'characteristics': characteristics,
                    'is_dll': bool(characteristics & 0x2000)}
    except (OSError, ValueError, struct.error) as error:
        return {'format': 'unknown', 'is_dll': None, 'error': str(error)}


# 起動前にHostが配置した対象と権限を正本とし、MCP要求で上書きしない。
def binding(root, request):
    policy = json.loads((Path(root) / 'dynamic-session.json').read_text(encoding='utf-8'))
    if request.get('analysis_id') != policy['analysis_id'] or policy.get('phase') != 'dynamic':
        raise PermissionError('Dynamic session mismatch')
    if (Path(root) / 'closed.json').exists() and request.get('action') != 'process_status':
        raise PermissionError('Dynamic session is closed')
    return policy


# 起動対象はGuest絶対パスとして検証し、シェル文字列として展開しない。
def launch_spec(request, policy):
    arguments = request.get('arguments', [])
    if not isinstance(arguments, list) or any(not isinstance(v, str) or '\0' in v for v in arguments):
        raise ValueError('arguments must be a string array')
    elevation = request.get('elevation', 'normal')
    if elevation not in ('normal', 'runas'):
        raise ValueError('elevation must be normal or runas')
    if elevation == 'runas' and not policy['allow_guest_elevation']:
        raise PermissionError('Guest elevation is not enabled for this run')
    sample = request['action'] == 'launch_sample'
    if sample:
        executable = policy['sample_path']
    elif request.get('executable'):
        executable = request['executable']
    else:
        import production_operations
        app = request.get('app')
        if app == 'notepad':
            executable = r'C:\Windows\System32\notepad.exe'
        elif app in ('die_gui', 'ilspy_gui'):
            executable = json.loads(production_operations.TOOLS.read_text(encoding='utf-8-sig'))['paths'][app]
        else:
            raise ValueError('Specify app or an absolute Guest executable')
    if not isinstance(executable, str) or not PureWindowsPath(executable).is_absolute() or executable.startswith('\\\\'):
        raise ValueError('A local absolute Guest executable is required')
    if not Path(executable).is_file():
        raise FileNotFoundError(executable)
    cwd = request.get('cwd') or str(Path(executable).parent)
    if not isinstance(cwd, str) or not PureWindowsPath(cwd).is_absolute() or not Path(cwd).is_dir():
        raise ValueError('cwd must be an existing absolute Guest directory')
    if sample:
        with Path(executable).open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != policy['sha256']:
                raise RuntimeError('Sample changed before launch')
    return {'executable': executable, 'arguments': arguments, 'cwd': cwd,
            'elevation': elevation, 'sample': sample, 'sha256': policy['sha256'] if sample else None}


# 固定ジョブIDだけを解決し、別runのファイルやプロセスを操作しない。
def job_directory(root, identity):
    return Path(root) / 'jobs' / uuid.UUID(identity).hex


# 起動は専用子プロセスへ委譲し、UACが開いても画面操作要求を処理し続ける。
def operate(request, root):
    policy = binding(root, request)
    action = request['action']
    if action in ('launch_sample', 'launch_analysis_app'):
        spec = launch_spec(request, policy)
        job_id = uuid.UUID(request['request_id']).hex
        directory = job_directory(root, job_id)
        directory.mkdir(parents=True, exist_ok=False)
        spec.update(analysis_id=policy['analysis_id'], job_id=job_id, created_utc=time.time())
        write_json(directory / 'request.json', spec)
        if spec['sample']:
            pe = inspect_pe(spec['executable'])
            if pe['is_dll']:
                result = dict(spec, state='failed', started=False, pe=pe,
                              error_code='sample_is_dll', reason='unsupported_direct_launch',
                              error='DLL属性の検体は通常EXEとして直接起動できません。DLLの自動実行は行いません。')
                write_json(directory / 'status.json', result)
                return result
        write_json(directory / 'status.json', dict(spec, state='launch_pending', started=False))
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--job', str(directory)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return {'job_id': job_id, 'state': 'launch_pending', 'started': False}
    if action == 'process_status':
        paths = ([job_directory(root, request['job_id'])] if request.get('job_id') else
                 sorted((Path(root) / 'jobs').glob('*')))
        return {'jobs': [json.loads((p / 'status.json').read_text(encoding='utf-8')) for p in paths]}
    if action == 'stop_process':
        directory = job_directory(root, request['job_id'])
        if not (directory / 'status.json').exists():
            raise ValueError('Unknown job')
        write_json(directory / 'stop.json', {'requested_utc': time.time()})
        return {'job_id': directory.name, 'termination_requested': True, 'termination_verified': False}
    raise ValueError('Unknown dynamic operation')


# 実際に起動したプロセスのトークンを読み、親タスクの権限を代用しない。
def token_information(handle):
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
    advapi.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    advapi.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wt.DWORD]
    advapi.GetSidSubAuthority.restype = ctypes.POINTER(wt.DWORD)
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    token = wt.HANDLE()
    if not advapi.OpenProcessToken(handle, 0x0008, ctypes.byref(token)):
        return {'verified': False, 'winerror': ctypes.get_last_error()}
    try:
        elevation, size = wt.DWORD(), wt.DWORD()
        if not advapi.GetTokenInformation(token, 20, ctypes.byref(elevation), ctypes.sizeof(elevation), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        advapi.GetTokenInformation(token, 25, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token, 25, buffer, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        count = advapi.GetSidSubAuthorityCount(sid)[0]
        level = advapi.GetSidSubAuthority(sid, count - 1)[0]
        return {'verified': True, 'is_elevated': bool(elevation.value), 'integrity_rid': level,
                'integrity_level': {4096: 'low', 8192: 'medium', 12288: 'high', 16384: 'system'}.get(level, str(level)),
                'source': 'launched process token'}
    except OSError as error:
        return {'verified': False, 'error': str(error)}
    finally:
        kernel.CloseHandle(token)


# UAC待機は別プロセス内で行い、戻されたHANDLEを終了まで保持してPID再利用を避ける。
def run_job(directory):
    directory = Path(directory)
    spec = json.loads((directory / 'request.json').read_text(encoding='utf-8'))
    result = dict(spec, state='launch_pending', started=False)
    handle = None
    process = None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetProcessId.argtypes = [wt.HANDLE]
    kernel.GetProcessId.restype = wt.DWORD
    kernel.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    kernel.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
    kernel.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    try:
        if (directory.parent.parent / 'closed.json').exists():
            raise RuntimeError('Investigation closed before launch')
        if spec.get('sample'):
            result['pe'] = inspect_pe(spec['executable'])
            if result['pe']['is_dll']:
                result.update(error_code='sample_is_dll', reason='unsupported_direct_launch')
                raise ValueError('DLL属性の検体は通常EXEとして直接起動できません。')
        if spec['elevation'] == 'runas':
            class ShellExecuteInfo(ctypes.Structure):
                _fields_ = [('cbSize', wt.DWORD), ('fMask', wt.ULONG), ('hwnd', wt.HWND),
                            ('lpVerb', wt.LPCWSTR), ('lpFile', wt.LPCWSTR), ('lpParameters', wt.LPCWSTR),
                            ('lpDirectory', wt.LPCWSTR), ('nShow', ctypes.c_int), ('hInstApp', wt.HINSTANCE),
                            ('lpIDList', ctypes.c_void_p), ('lpClass', wt.LPCWSTR), ('hkeyClass', wt.HKEY),
                            ('dwHotKey', wt.DWORD), ('hIcon', wt.HANDLE), ('hProcess', wt.HANDLE)]
            shell = ctypes.WinDLL('shell32', use_last_error=True)
            shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
            info = ShellExecuteInfo()
            info.cbSize, info.fMask, info.nShow = ctypes.sizeof(info), 0x40 | 0x100, 1
            info.lpVerb, info.lpFile = 'runas', spec['executable']
            info.lpParameters, info.lpDirectory = subprocess.list2cmdline(spec['arguments']), spec['cwd']
            if not shell.ShellExecuteExW(ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            handle = info.hProcess
            if not handle:
                raise RuntimeError('No process handle returned; launch outcome unknown')
        else:
            process = subprocess.Popen([spec['executable'], *spec['arguments']], cwd=spec['cwd'],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            handle = int(process._handle)
        result.update(state='running', started=True, pid=kernel.GetProcessId(handle),
                      start_utc=time.time(), launch_context=token_information(handle))
        write_json(directory / 'status.json', result)
        while True:
            state = kernel.WaitForSingleObject(handle, 250)
            if state == 0:
                break
            if state != 258:
                raise ctypes.WinError(ctypes.get_last_error())
            if (directory / 'stop.json').exists() or (directory.parent.parent / 'closed.json').exists():
                result['termination_requested'] = True
                if not kernel.TerminateProcess(handle, 1):
                    result['termination_error'] = ctypes.get_last_error()
                    write_json(directory / 'status.json', result)
                (directory / 'stop.json').unlink(missing_ok=True)
        code = wt.DWORD()
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise ctypes.WinError(ctypes.get_last_error())
        result.update(state='exited', exit_code=code.value)
        if process is not None:
            process.wait(timeout=5)
    except Exception as error:
        result.update(state='failed', error=str(error))
    finally:
        result['updated_utc'] = time.time()
        write_json(directory / 'status.json', result)
        if handle and process is None:
            kernel.CloseHandle(handle)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--job', required=True)
    run_job(parser.parse_args().job)
