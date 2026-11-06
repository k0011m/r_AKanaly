import argparse
import getpass
import json
import locale
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config" / "guest_control.json"
LOCAL_AGENT = ROOT / "guest" / "guest_agent.py"
LOCAL_PS_AGENT = ROOT / "guest" / "guest_agent.ps1"
LOCAL_RESIDENT_AGENT = ROOT / "guest" / "resident_agent.py"
LOCAL_RUNS = ROOT / "runs"
OUTPUT_ENCODING = locale.getpreferredencoding(False) or "utf-8"
sys.path.insert(0, str(ROOT.parent))
from vmrun_errors import VmrunError, decode_output as decode_vmrun_output, from_result, operation_name, redact, error_details


# 設定ファイルを読み込み、Host側とGuest側の既定パスをまとめて扱う。
def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


# VMXを読み取り専用で検査し、ネットワーク設定が期待値から変わっていないことを保証する。
def assert_vmx_network(config):
    vmx_path = Path(config["vmx_path"])
    if not vmx_path.exists():
        raise FileNotFoundError(f"VMX not found: {vmx_path}")

    settings = {}
    for line in vmx_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        settings[key.strip()] = value.strip().strip('"')

    expected = config["expected_network"]
    mismatches = {
        key: {"expected": value, "actual": settings.get(key)}
        for key, value in expected.items()
        if settings.get(key) != value
    }
    if mismatches:
        raise RuntimeError(f"VMX network settings mismatch: {mismatches}")
    return {key: settings.get(key) for key in expected}


# vmrun呼び出しを一箇所に集約し、診断しやすい形で結果を返す。
def run_vmrun(config, args, check=False):
    command = [config["vmrun_path"], "-T", "ws"]
    if config.get("vm_password"):
        command.extend(["-vp", config["vm_password"]])
    command.extend(args)
    started = time.time()
    try:
        from vmrun_transfer import run_staged
        completed = run_staged(
            command, subprocess.run,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=config.get("vmrun_timeout_seconds", 120)
        )
    except subprocess.TimeoutExpired:
        # TimeoutExpiredの文字列には認証引数が入るため、そのまま外へ出さない。
        raise VmrunError(None, operation=operation_name(command), timed_out=True) from None
    except OSError as error:
        raise VmrunError(None, redact(str(error), command), operation=operation_name(command)) from None
    failure = from_result(command, completed)
    output = failure.output
    for key in ("vm_password", "guest_password"):
        if config.get(key):
            output = output.replace(config[key], "[REDACTED]")
    result = {
        "exit_code": completed.returncode,
        "output": output,
        "elapsed_sec": round(time.time() - started, 3)
    }
    if completed.returncode != 0:
        result['error_details'] = error_details(failure)
    if check and completed.returncode != 0:
        raise failure
    return result


# Guest内のcmd.exeを使い、標準出力をGuest内ファイルに落としてからHostへ回収する。
def run_guest_cmd_capture(config, command_line, label):
    guest_dir = config["guest_agent_dir"]
    guest_out = f"{guest_dir}\\{label}.txt"
    host_out = LOCAL_RUNS / f"{label}.txt"
    # 実行ファイルパスが引用符で始まる場合でも cmd.exe が誤解釈しないように call 経由で実行する。
    wrapped = f'call {command_line} > "{guest_out}" 2>&1'
    result = run_vmrun(config, guest_program_args(config, "C:\\Windows\\System32\\cmd.exe", [f"/c {wrapped}"]))
    copied = run_vmrun(
        config,
        ["-gu", config["guest_user"], "-gp", config["guest_password"],
         "copyFileFromGuestToHost", config["vmx_path"], guest_out, str(host_out)]
    )
    output = host_out.read_text(encoding="utf-8", errors="replace") if host_out.exists() else ""
    return {"run": result, "copy": copied, "output": output}


# vmrun runProgramInGuest用の共通引数を作る。
def guest_program_args(config, program, args=None, no_wait=False, active_window=False):
    cmd = [
        "-gu", config["guest_user"],
        "-gp", config["guest_password"],
        "runProgramInGuest"
    ]
    cmd.append(config["vmx_path"])
    if no_wait:
        cmd.append("-noWait")
    if active_window:
        cmd.extend(["-activeWindow", "-interactive"])
    cmd.append(program)
    cmd.extend(args or [])
    return cmd


# Guest側の作業ディレクトリを作る。
def ensure_guest_dir(config):
    command = f'if not exist "{config["guest_agent_dir"]}" mkdir "{config["guest_agent_dir"]}"'
    return run_vmrun(config, guest_program_args(config, "C:\\Windows\\System32\\cmd.exe", [f"/c {command}"]), check=True)


# Guestへエージェント本体を転送する。
def deploy_agent(config):
    ensure_guest_dir(config)
    run_vmrun(config, ["-gu", config["guest_user"], "-gp", config["guest_password"],
                      "copyFileFromHostToGuest", config["vmx_path"],
                      str(ROOT / "guest" / "archive_ops.py"),
                      f'{config["guest_agent_dir"]}\\archive_ops.py'], check=True)
    guest_agent = f'{config["guest_agent_dir"]}\\guest_agent.py'
    python_deploy = run_vmrun(
        config,
        ["-gu", config["guest_user"], "-gp", config["guest_password"],
         "copyFileFromHostToGuest", config["vmx_path"], str(LOCAL_AGENT), guest_agent],
        check=True
    )
    guest_ps_agent = f'{config["guest_agent_dir"]}\\guest_agent.ps1'
    ps_deploy = run_vmrun(
        config,
        ["-gu", config["guest_user"], "-gp", config["guest_password"],
         "copyFileFromHostToGuest", config["vmx_path"], str(LOCAL_PS_AGENT), guest_ps_agent],
        check=True
    )
    return {"python": python_deploy, "powershell": ps_deploy}


# 常駐agent本体と起動用cmdをGuestへ配置し、ログオン時に起動するStartupへ登録する。
def deploy_resident_agent(config):
    ensure_guest_dir(config)
    deploy_agent(config)
    guest_resident = f'{config["guest_agent_dir"]}\\resident_agent.py'
    resident_deploy = run_vmrun(
        config,
        ["-gu", config["guest_user"], "-gp", config["guest_password"],
         "copyFileFromHostToGuest", config["vmx_path"], str(LOCAL_RESIDENT_AGENT), guest_resident],
        check=True
    )

    pythonw = f'{config["guest_agent_dir"]}\\python\\pythonw.exe'
    startup_cmd = LOCAL_RUNS / "codex_guest_resident_agent.cmd"
    startup_cmd.write_text(
        "@echo off\r\n"
        f'cd /d "{config["guest_agent_dir"]}"\r\n'
        f'start "" /min "{pythonw}" "{guest_resident}" --agent-dir "{config["guest_agent_dir"]}"\r\n',
        encoding="utf-8"
    )
    guest_startup = (
        f'C:\\Users\\{config["guest_user"]}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\'
        "Programs\\Startup\\codex_guest_resident_agent.cmd"
    )
    guest_startup_dir = str(Path(guest_startup).parent)
    startup_dir = run_vmrun(
        config,
        guest_program_args(
            config,
            "C:\\Windows\\System32\\cmd.exe",
            [f'/c if not exist "{guest_startup_dir}" mkdir "{guest_startup_dir}"']
        ),
        check=True
    )
    # 二重起動を避けるため、Startupフォルダ方式は使わずHKCU Runへ一本化する。
    startup_cleanup = run_vmrun(
        config,
        guest_program_args(config, "C:\\Windows\\System32\\cmd.exe", [f'/c if exist "{guest_startup}" del /F /Q "{guest_startup}"']),
        check=True
    )
    run_value = (
        f'"{config["guest_agent_dir"]}\\python\\pythonw.exe" '
        f'"{guest_resident}" --agent-dir "{config["guest_agent_dir"]}"'
    )
    run_key = run_vmrun(
        config,
        guest_program_args(
            config,
            "C:\\Windows\\System32\\reg.exe",
            ["add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
             "/v", "CodexGuestResident", "/t", "REG_SZ", "/d", run_value, "/f"]
        ),
        check=True
    )
    make_dirs = (
        f'for %D in ("{config["guest_agent_dir"]}\\queue" "{config["guest_agent_dir"]}\\processing" '
        f'"{config["guest_agent_dir"]}\\responses" "{config["guest_agent_dir"]}\\logs") do '
        'if not exist %D mkdir %D'
    )
    dirs = run_vmrun(config, guest_program_args(config, "C:\\Windows\\System32\\cmd.exe", [f"/c {make_dirs}"]), check=True)
    return {"resident": resident_deploy, "startup_dir": startup_dir, "startup_cleanup": startup_cleanup, "run_key": run_key, "dirs": dirs}


# Guest起動後にtestユーザーで対話セッションを作るため、AutoAdminLogonを設定する。
def enable_autologon(config):
    key = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    values = [
        ("AutoAdminLogon", "1"),
        ("ForceAutoLogon", "1"),
        ("DefaultDomainName", config.get("guest_domain", config["guest_user"])),
        ("DefaultUserName", config["guest_user"]),
        ("DefaultPassword", config["guest_password"])
    ]
    results = []
    for name, value in values:
        # 空白を含むレジストリキーをcmd.exeに解釈させず、reg.exeへ直接引数として渡す。
        results.append(
            run_vmrun(
                config,
                guest_program_args(
                    config,
                    "C:\\Windows\\System32\\reg.exe",
                    ["add", key, "/v", name, "/t", "REG_SZ", "/d", value, "/f"]
                ),
                check=True
            )
        )
    return results


# 常駐agentのqueueへ要求を置き、responsesに結果が出るまで待つ。
def run_resident_action(config, request, timeout):
    LOCAL_RUNS.mkdir(exist_ok=True)
    ensure_guest_dir(config)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    request_id = f"resident-{stamp}-{uuid.uuid4().hex}.json"
    host_request = LOCAL_RUNS / request_id
    host_response = LOCAL_RUNS / f"response-{request_id}"
    guest_request = f'{config["guest_agent_dir"]}\\queue\\{request_id}'
    guest_request_tmp = f"{guest_request}.tmp"
    guest_response = f'{config["guest_agent_dir"]}\\responses\\{request_id}'
    host_request.write_text(json.dumps(request, ensure_ascii=False, indent=2), encoding="utf-8")
    # resident agentがコピー途中のJSONを読まないよう、一度.tmpへ置いてからGuest内でrenameする。
    try:
        copy_request = run_vmrun(
            config,
            ["-gu", config["guest_user"], "-gp", config["guest_password"],
             "copyFileFromHostToGuest", config["vmx_path"], str(host_request), guest_request_tmp],
            check=True
        )
    finally:
        # ZIPパスワード入りHost要求は転送直後に削除し、履歴に残さない。
        if request.get("action") == "extract_zip":
            host_request.unlink(missing_ok=True)
    publish_request = run_vmrun(
        config,
        guest_program_args(
            config,
            "C:\\Windows\\System32\\cmd.exe",
            [f'/c move /Y "{guest_request_tmp}" "{guest_request}"']
        ),
        check=True
    )
    deadline = time.time() + timeout
    last_copy = None
    while time.time() < deadline:
        last_copy = run_vmrun(
            config,
            ["-gu", config["guest_user"], "-gp", config["guest_password"],
             "copyFileFromGuestToHost", config["vmx_path"], guest_response, str(host_response)],
            check=False
        )
        if last_copy["exit_code"] == 0 and host_response.exists():
            response = json.loads(host_response.read_text(encoding="utf-8-sig"))
            response["_vmrun"] = {"copy_request": copy_request, "publish_request": publish_request, "copy_response": last_copy}
            return response
        time.sleep(0.5)
    return {"ok": False, "error": "ResidentResponseTimeout", "request": {k: v for k, v in request.items() if k != "password"}, "copy_request": copy_request, "publish_request": publish_request, "last_copy": last_copy}


# 画面認識用にVMware ToolsのスクリーンショットをHost側へ保存する。
def capture_screen(config, output_path):
    output = Path(output_path)
    if not output.is_absolute():
        output = LOCAL_RUNS / output
    output.parent.mkdir(parents=True, exist_ok=True)
    return {
        "path": str(output),
        "capture": run_vmrun(
            config,
            ["-gu", config["guest_user"], "-gp", config["guest_password"],
             "captureScreen", config["vmx_path"], str(output)],
            check=True
        )
    }


# 指定スナップショットへ戻し、配置前のGuest状態をそろえる。
def restore_snapshot(config, snapshot_name):
    assert_vmx_network(config)
    return run_vmrun(config, ["revertToSnapshot", config["vmx_path"], snapshot_name], check=True)


# VMを起動し、Guest Operationsを受け付ける状態へ進める。
def start_vm(config, nogui=False):
    args = ["start", config["vmx_path"]]
    if nogui:
        args.append("nogui")
    return run_vmrun(config, args, check=True)


# Guest上で利用可能なPythonコマンドを探す。
def probe_guest_python(config):
    LOCAL_RUNS.mkdir(exist_ok=True)
    ensure_guest_dir(config)
    results = []
    for index, candidate in enumerate(config["guest_python_candidates"]):
        label = f"python-probe-{index}"
        command_line = f'"{candidate}" --version'
        try:
            result = run_guest_cmd_capture(config, command_line, label)
            ok = result["run"]["exit_code"] == 0 and result["copy"]["exit_code"] == 0
            results.append({"candidate": candidate, "ok": ok, "output": result["output"].strip(), "detail": result})
            if ok:
                return {"selected": candidate, "results": results}
        except Exception as exc:
            results.append({"candidate": candidate, "ok": False, "error": str(exc)})
    return {"selected": None, "results": results}


# HostのJSONリクエストをGuestへ転送し、GuestエージェントのJSONレスポンスを回収する。
def run_agent_action(config, python_cmd, request):
    if request.get("action") == "extract_zip":
        raise ValueError("Use run_resident_action or extract-zip for ZIP extraction")
    LOCAL_RUNS.mkdir(exist_ok=True)
    ensure_guest_dir(config)
    deploy_agent(config)
    needs_interactive = request.get("action") in {"click", "type_text", "press_key"}

    stamp = time.strftime("%Y%m%d-%H%M%S")
    host_request = LOCAL_RUNS / f"request-{stamp}.json"
    host_response = LOCAL_RUNS / f"response-{stamp}.json"
    host_launcher = LOCAL_RUNS / f"launcher-{stamp}.cmd"
    host_trace = LOCAL_RUNS / f"trace-{stamp}.txt"
    guest_request = f'{config["guest_agent_dir"]}\\request-{stamp}.json'
    guest_response = f'{config["guest_agent_dir"]}\\response-{stamp}.json'
    guest_launcher = f'{config["guest_agent_dir"]}\\launcher-{stamp}.cmd'
    guest_trace = f'{config["guest_agent_dir"]}\\trace-{stamp}.txt'
    guest_agent = f'{config["guest_agent_dir"]}\\guest_agent.py'
    guest_ps_agent = f'{config["guest_agent_dir"]}\\guest_agent.ps1'
    host_request.write_text(json.dumps(request, ensure_ascii=False, indent=2), encoding="utf-8")

    run_vmrun(
        config,
        ["-gu", config["guest_user"], "-gp", config["guest_password"],
         "copyFileFromHostToGuest", config["vmx_path"], str(host_request), guest_request],
        check=True
    )
    if python_cmd == "powershell":
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        launcher = (
            "@echo off\r\n"
            f'"{ps}" -NoProfile -ExecutionPolicy Bypass -File "{guest_ps_agent}" '
            f'-Request "{guest_request}" -Response "{guest_response}" > "{guest_trace}" 2>&1\r\n'
            "exit /b %ERRORLEVEL%\r\n"
        )
        host_launcher.write_text(launcher, encoding="utf-8")
        run_vmrun(
            config,
            ["-gu", config["guest_user"], "-gp", config["guest_password"],
             "copyFileFromHostToGuest", config["vmx_path"], str(host_launcher), guest_launcher],
            check=True
        )
        run_args = guest_program_args(config, "C:\\Windows\\System32\\cmd.exe", [f"/c {guest_launcher}"])
    elif "\\" in python_cmd or ":" in python_cmd:
        run_args = guest_program_args(
            config,
            python_cmd,
            [guest_agent, "--request", guest_request, "--response", guest_response],
            active_window=needs_interactive
        )
    else:
        command_line = f'"{python_cmd}" "{guest_agent}" --request "{guest_request}" --response "{guest_response}"'
        run_args = guest_program_args(config, "C:\\Windows\\System32\\cmd.exe", [f"/c {command_line}"], active_window=needs_interactive)
    run_result = run_vmrun(config, run_args)
    copy_response = run_vmrun(
        config,
        ["-gu", config["guest_user"], "-gp", config["guest_password"],
         "copyFileFromGuestToHost", config["vmx_path"], guest_response, str(host_response)],
        check=False
    )
    if copy_response["exit_code"] == 0 and host_response.exists():
        response = json.loads(host_response.read_text(encoding="utf-8-sig"))
        response["_vmrun"] = {"run": run_result, "copy_response": copy_response}
        return response

    copy_trace = run_vmrun(
        config,
        ["-gu", config["guest_user"], "-gp", config["guest_password"],
         "copyFileFromGuestToHost", config["vmx_path"], guest_trace, str(host_trace)],
        check=False
    )
    trace_text = host_trace.read_text(encoding="utf-8", errors="replace") if host_trace.exists() else ""
    return {
        "ok": False,
        "error": "AgentResponseMissing",
        "run": run_result,
        "copy_response": copy_response,
        "copy_trace": copy_trace,
        "trace": trace_text
    }


# 診断情報をJSONで出力し、以後の方式選択に使う。
def diagnose(config):
    data = {
        "paths": {
            "vmrun": {"path": config["vmrun_path"], "exists": Path(config["vmrun_path"]).exists()},
            "vmx": {"path": config["vmx_path"], "exists": Path(config["vmx_path"]).exists()},
            "agent": {"path": str(LOCAL_AGENT), "exists": LOCAL_AGENT.exists()},
            "ps_agent": {"path": str(LOCAL_PS_AGENT), "exists": LOCAL_PS_AGENT.exists()},
            "resident_agent": {"path": str(LOCAL_RESIDENT_AGENT), "exists": LOCAL_RESIDENT_AGENT.exists()}
        },
        "vmx_network": assert_vmx_network(config),
        "vmrun_list": run_vmrun(config, ["list"]),
        "tools_state": run_vmrun(config, ["checkToolsState", config["vmx_path"]])
    }
    return data


def print_json(data):
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    sys.stdout.buffer.write(payload.encode("utf-8", errors="replace"))
    sys.stdout.buffer.write(b"\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Control VMware Guest GUI through vmrun and a Guest agent.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("diagnose")
    subparsers.add_parser("deploy-agent")
    subparsers.add_parser("deploy-resident")
    subparsers.add_parser("enable-autologon")
    subparsers.add_parser("probe-python")
    zip_parser = subparsers.add_parser("extract-zip", help="Extract an existing Guest ZIP through the resident agent")
    zip_parser.add_argument("--archive-path", required=True)
    zip_parser.add_argument("--destination", required=True)
    password_group = zip_parser.add_mutually_exclusive_group()
    password_group.add_argument("--password-stdin", action="store_true")
    password_group.add_argument("--no-password", action="store_true")
    zip_parser.add_argument("--timeout", type=float, default=360)

    restore_parser = subparsers.add_parser("restore-snapshot")
    restore_parser.add_argument("name")

    start_parser = subparsers.add_parser("start-vm")
    start_parser.add_argument("--nogui", action="store_true")

    capture_parser = subparsers.add_parser("capture-screen")
    capture_parser.add_argument("--output", default=f"screen-{time.strftime('%Y%m%d-%H%M%S')}.bmp")

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("action", choices=["observe", "launch_app", "click", "type_text", "press_key", "open_url", "open_text_in_notepad", "spawn_messageboxes"])
    run_parser.add_argument("--python", dest="python_cmd")
    run_parser.add_argument("--path")
    run_parser.add_argument("--url")
    run_parser.add_argument("--text")
    run_parser.add_argument("--keys")
    run_parser.add_argument("--x", type=int)
    run_parser.add_argument("--y", type=int)
    run_parser.add_argument("--count", type=int)
    run_parser.add_argument("--title")

    resident_parser = subparsers.add_parser("run-resident")
    resident_parser.add_argument("action", choices=["observe", "launch_app", "click", "type_text", "press_key", "open_url", "open_text_in_notepad", "spawn_messageboxes"])
    resident_parser.add_argument("--path")
    resident_parser.add_argument("--url")
    resident_parser.add_argument("--text")
    resident_parser.add_argument("--keys")
    resident_parser.add_argument("--x", type=int)
    resident_parser.add_argument("--y", type=int)
    resident_parser.add_argument("--count", type=int)
    resident_parser.add_argument("--title")
    resident_parser.add_argument("--timeout", type=float, default=20.0)

    args = parser.parse_args(argv)
    config = load_config(Path(args.config))
    LOCAL_RUNS.mkdir(exist_ok=True)

    if args.command == "extract-zip":
        assert_vmx_network(config)
        password = None if args.no_password else (sys.stdin.buffer.readline().decode("utf-8").rstrip("\r\n") if args.password_stdin else getpass.getpass("ZIP password: "))
        response = run_resident_action(config, {"action": "extract_zip", "archive_path": args.archive_path,
                                               "destination": args.destination, "password": password}, args.timeout)
        print_json(response)
        return 0 if response.get("ok") else 1
    if args.command == "diagnose":
        print_json(diagnose(config))
        return 0
    if args.command == "deploy-agent":
        print_json({"deploy": deploy_agent(config)})
        return 0
    if args.command == "deploy-resident":
        print_json({"deploy_resident": deploy_resident_agent(config)})
        return 0
    if args.command == "enable-autologon":
        print_json({"enable_autologon": enable_autologon(config)})
        return 0
    if args.command == "probe-python":
        print_json(probe_guest_python(config))
        return 0
    if args.command == "restore-snapshot":
        print_json({"restore": restore_snapshot(config, args.name)})
        return 0
    if args.command == "start-vm":
        print_json({"start": start_vm(config, args.nogui)})
        return 0
    if args.command == "capture-screen":
        print_json(capture_screen(config, args.output))
        return 0
    if args.command == "run":
        python_cmd = args.python_cmd
        if not python_cmd:
            probe = probe_guest_python(config)
            python_cmd = probe["selected"]
            if not python_cmd:
                python_cmd = "powershell"

        request = {"action": args.action}
        if args.action == "launch_app":
            request["path"] = args.path
        elif args.action == "click":
            request.update({"x": args.x, "y": args.y})
        elif args.action == "type_text":
            request["text"] = args.text or ""
        elif args.action == "press_key":
            request["keys"] = args.keys
        elif args.action == "open_url":
            request["url"] = args.url
        elif args.action == "open_text_in_notepad":
            request["text"] = args.text or ""
            if args.path:
                request["path"] = args.path
        elif args.action == "spawn_messageboxes":
            request["text"] = args.text or "Click OK to continue"
            request["count"] = args.count or 3
            if args.title:
                request["title"] = args.title

        print_json(run_agent_action(config, python_cmd, request))
        return 0
    if args.command == "run-resident":
        request = {"action": args.action}
        if args.action == "launch_app":
            request["path"] = args.path
        elif args.action == "click":
            request.update({"x": args.x, "y": args.y})
        elif args.action == "type_text":
            request["text"] = args.text or ""
        elif args.action == "press_key":
            request["keys"] = args.keys
        elif args.action == "open_url":
            request["url"] = args.url
        elif args.action == "open_text_in_notepad":
            request["text"] = args.text or ""
            if args.path:
                request["path"] = args.path
        elif args.action == "spawn_messageboxes":
            request["text"] = args.text or "Click OK to continue"
            request["count"] = args.count or 3
            if args.title:
                request["title"] = args.title
        print_json(run_resident_action(config, request, args.timeout))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
