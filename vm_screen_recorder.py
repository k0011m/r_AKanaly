"""利用者の事後確認用にVM画面をHostへ保存する。MCPやLLMへ画像を送らない。"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid


# PNGとは別に取得時刻・エラーを追記し、撮影漏れを後から確認できるようにする。
def append_event(directory, event):
    with (Path(directory) / 'captures.jsonl').open('a', encoding='utf-8') as output:
        output.write(json.dumps(dict(event, recorded_at=datetime.now(timezone.utc).isoformat()), ensure_ascii=False) + '\n')


# 親のプロセスHANDLEを保持し、本体異常終了やPID再利用後に撮影を続けない。
@contextmanager
def parent_liveness(pid):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x00100000, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield lambda: bool(handle) and kernel.WaitForSingleObject(handle, 0) == 258
    finally:
        if handle:
            kernel.CloseHandle(handle)


# 独立プロセスで撮影し、遅いコンソール通信がCodexの操作要求をブロックしないようにする。
def record_loop(backend, directory, interval, parent_alive):
    directory = Path(directory)
    stop = directory / 'stop.request'
    sequence = 0
    append_event(directory, {'event': 'started', 'interval_seconds': interval})
    while not stop.exists() and parent_alive():
        started = time.monotonic()
        sequence += 1
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
        target = directory / f'{sequence:06d}_{timestamp}.png'
        temporary = target.with_suffix('.png.tmp')
        try:
            width, height, picture = backend.observe()
            # 停止要求後に別工程の画面を記録しない。完成したPNGだけを公開する。
            if stop.exists() or not parent_alive():
                break
            temporary.write_bytes(picture)
            temporary.replace(target)
            append_event(directory, {'event': 'captured', 'file': target.name,
                'width': width, 'height': height, 'capture_started_at': timestamp})
        except Exception as error:
            temporary.unlink(missing_ok=True)
            append_event(directory, {'event': 'capture_failed', 'error': type(error).__name__, 'message': str(error)})
        deadline = max(started + interval, time.monotonic() + 0.1)
        while time.monotonic() < deadline and not stop.exists() and parent_alive():
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    append_event(directory, {'event': 'stopped'})


class DynamicRecordingSession:
    # LLM・OS Agentを起動せず、固定実行でも撮影専用のコンソールを管理する。
    def __init__(self, dynamic, settings_dir):
        sys.path.insert(0, str(Path(__file__).resolve().parent / 'VMWARE_GUEST_CONTROL_PACKAGE/host'))
        from console_lifecycle import ConsoleLease
        self.options = dynamic.settings['llm_control']
        self.settings_dir = Path(settings_dir)
        self.analysis_id = dynamic.id
        self.lease = ConsoleLease(dynamic.vmware.vmx_path, dynamic.output / 'screen_state')
        self.recorder = None

    # VM復元後・起動前に既存と同じlocalhost限定の画面経路を準備する。
    def prepare(self):
        from console_lifecycle import ConsoleLease
        ConsoleLease.recover_managed(self.lease.vmx)
        self.lease.prepare()

    # Guest準備完了後に保存だけを開始し、画像をLLMへ渡さない。
    def start(self):
        self.lease.verify()
        output = Path(self.options['screenshot_output_dir']).expanduser()
        if not output.is_absolute():
            output = self.settings_dir / output
        self.recorder = ScreenRecorder(self.lease.port, output,
            self.options['screenshot_interval_seconds'], self.analysis_id)
        try:
            self.recorder.start()
        except OSError as error:
            print('ユーザー用画面記録を開始できません: ' + str(error))
            return
        print('ユーザー用VM画面の保存先: ' + str(self.recorder.directory))

    # 例外時にも停止し、静的解析へ画像記録を持ち越さない。
    def stop(self):
        if self.recorder is not None:
            self.recorder.stop()
            self.recorder = None

    # VMの正常停止後だけ一時コンソール設定を戻す。
    def restore(self):
        self.lease.restore()


class ScreenRecorder:
    # 専用保存先を使い、MCPフレーム・動的証拠一覧・LLM入力への混入を避ける。
    def __init__(self, port, output_dir, interval, analysis_id):
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self.directory = Path(output_dir) / f'{stamp}_{analysis_id}_{uuid.uuid4().hex[:8]}'
        self.port, self.interval, self.process = port, interval, None

    # exe版も自身の専用入口から起動し、HostにPythonを別途要求しない。
    def start(self):
        self.directory.mkdir(parents=True, exist_ok=False)
        command = ([sys.executable, '--record-vm-screen'] if getattr(sys, 'frozen', False)
                   else [sys.executable, str(Path(__file__).resolve())])
        command += ['--port', str(self.port), '--output', str(self.directory.resolve()),
                    '--interval', str(self.interval), '--parent-pid', str(os.getpid())]
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))

    # 撮影が通信待ちでも専用プロセスだけを終了し、VM復元後まで撮影を持ち越さない。
    def stop(self):
        if self.process is None:
            return
        try:
            (self.directory / 'stop.request').touch()
            self.process.wait(timeout=3)
        except (subprocess.TimeoutExpired, OSError):
            self.process.terminate()
            self.process.wait(timeout=5)
        finally:
            code = self.process.poll()
            try:
                append_event(self.directory, {'event': 'host_stop', 'exit_code': code})
            except OSError:
                pass
            if code is not None:
                self.process = None


# 取得対象は既存のlocalhost VMコンソールだけで、画像を外部送信する入口は持たない。
def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--interval', type=int, required=True)
    parser.add_argument('--parent-pid', type=int, required=True)
    args = parser.parse_args(argv)
    if args.interval <= 0:
        parser.error('interval must be positive')
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'VMWARE_GUEST_CONTROL_PACKAGE/host'))
    from console_input import ConsoleInput
    try:
        with parent_liveness(args.parent_pid) as alive:
            record_loop(ConsoleInput(args.port), args.output, args.interval, alive)
    except Exception as error:
        append_event(args.output, {'event': 'recorder_failed', 'error': type(error).__name__, 'message': str(error)})
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
