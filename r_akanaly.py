from __future__ import annotations
from vmrun_errors import VmrunError, from_result, operation_name, redact, error_details, ErrorContext

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import warnings
from getpass import GetPassWarning
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import config as app_config
import llm_operate
from console_io import read_secret, read_user_input, user_input_available
import tui_runtime


CONFIG_FILE_NAME = app_config.CONFIG_FILE_NAME
VM_START_MODE = app_config.VM_START_MODE
DEFAULT_VMRUN_PATH = app_config.DEFAULT_VMRUN_PATH
_VMRUN_CONFIGURED: str | None = None
_VMRUN_SELECTED: str | None = None


# 設定ファイルや実行時検証のエラーをまとめて扱います。
ConfigError = app_config.ConfigError

VmwareSettings = app_config.VmwareSettings
GuestSettings = app_config.GuestSettings
CredentialSettings = app_config.CredentialSettings
CredentialSecrets = app_config.CredentialSecrets
MalwareTransferSettings = app_config.MalwareTransferSettings
StaticAnalysisSettings = app_config.StaticAnalysisSettings
OutputDirectorySettings = app_config.OutputDirectorySettings
DeveloperVariableSettings = app_config.DeveloperVariableSettings
LlmSettings = app_config.LlmSettings
LlmTimeoutSettings = app_config.LlmTimeoutSettings
LlmAnalysisInputs = app_config.LlmAnalysisInputs
LlmAnalysisResult = app_config.LlmAnalysisResult
LlmRunPreparation = app_config.LlmRunPreparation
GhidraToolVerification = app_config.GhidraToolVerification
Settings = app_config.Settings
GuestCredentials = app_config.GuestCredentials
MalwareTransferPaths = app_config.MalwareTransferPaths
PreparedMalwareSource = app_config.PreparedMalwareSource


# VMware起動に必要な設定を保持します。
# Guest OSのユーザー名取得方法を保持します。
# マルウェア転送に必要な設定を保持します。
# 動的解析のGuest OS上の実行設定を保持します。
# 設定ファイル全体をアプリケーション内で扱いやすい形にまとめます。
# 開発者向けの環境差し替え値を保持し、未指定なら通常の自動検出へ任せます。
# Holds developer override values and leaves auto-detection active when unset.
# Guest OSへログイン・操作するための認証情報を保持します。
# マルウェア転送元と転送先のパスを保持します。
# exe化された場合はexeの場所、通常実行ではこのpyファイルの場所を基準にします。
def get_application_dir() -> Path:
    return app_config.APPLICATION_DIR


# 設定されたログ出力先をカテゴリごとのPathへ変換します。
def resolve_output_directory(
    settings: OutputDirectorySettings,
    category: str,
) -> Path:
    if settings.use_common_output_dir:
        if settings.common_output_dir is None:
            raise ConfigError("'output_directories.common_output_dir' is required.")
        return Path(settings.common_output_dir)

    directory_by_category = {
        "surface_analysis": settings.surface_analysis_output_dir,
        "static_analysis": settings.static_analysis_output_dir,
        "dynamic_analysis": settings.dynamic_analysis_output_dir,
    }
    if category not in directory_by_category:
        raise ConfigError(f"Unknown output directory category: {category}")
    directory = directory_by_category[category]
    if directory is None:
        raise ConfigError(f"'output_directories.{category}_output_dir' is required.")
    return Path(directory)


# Host OS側のログ保存前に、設定された出力先フォルダを作成可能な状態へ整えます。
def ensure_output_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


# JSON設定ファイルを読み込み、最低限の形式チェックを行います。
def load_json(path: Path) -> dict[str, Any]:
    return app_config.load_json(path)


# 既定設定はconfig.pyで集約した値を使い、明示指定された設定ファイルだけ個別に読みます。
def load_settings_json(path: Path) -> dict[str, Any]:
    if path.resolve() == app_config.DEFAULT_SETTINGS_PATH.resolve():
        if app_config.SETTINGS_JSON_ERROR is not None:
            raise app_config.SETTINGS_JSON_ERROR
        return app_config.SETTINGS_JSON
    return load_json(path)


# 指定キーの値がJSONオブジェクトであることを確認します。
def require_object(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"'{key}' must be a JSON object.")
    return value


# 必須文字列項目を取得します。
def require_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"'{key}' must be a non-empty string.")
    return value.strip()


# 任意文字列項目を取得します。
def optional_string(data: dict[str, Any], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"'{key}' must be a non-empty string when provided.")
    return value.strip()


# 任意の真偽値項目を取得し、未指定ならデフォルト値を使います。
def optional_bool(data: dict[str, Any], key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"'{key}' must be true or false.")
    return value


# 任意の整数項目を取得し、未指定ならデフォルト値を使います。
def optional_int(data: dict[str, Any], key: str, default: int) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"'{key}' must be an integer.")
    return value


# 外部コマンドの出力をUTF-8優先で安全に文字列化し、vmrunの文字化けやデコード例外を避けます。
def decode_command_output(output: bytes | None) -> str:
    if output is None:
        return ""
    for encoding in ("utf-8", "cp932"):
        try:
            return output.decode(encoding)
        except UnicodeDecodeError:
            continue
    return output.decode("utf-8", errors="replace")


# 外部コマンドの出力を安全に文字列化し、Windowsのデコード不能バイトで落ちないようにします。
def run_command_capture_text(
    command: list[str],
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        from vmrun_transfer import run_staged
        result = run_staged(command, subprocess.run, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        if Path(command[0]).name.lower() in ('vmrun', 'vmrun.exe'):
            raise VmrunError(None, operation=operation_name(command), timed_out=True) from None
        raise
    except OSError as error:
        if Path(command[0]).name.lower() in ('vmrun', 'vmrun.exe'):
            raise VmrunError(None, redact(str(error), command), operation=operation_name(command)) from None
        raise
    return subprocess.CompletedProcess(
        result.args,
        result.returncode,
        # 後続のエラー判定やログ表示で扱いやすい文字列へ変換します。
        stdout=redact(decode_command_output(result.stdout), command),
        # 標準エラーも同じ変換経路に通して、vmrun.exe の文字化けを抑えます。
        stderr=redact(decode_command_output(result.stderr), command),
    )


# stdout/stderrがNoneでも安全にエラー詳細を作ります。
def get_command_error_details(
    result: subprocess.CompletedProcess[str],
    fallback: str,
) -> str:
    stderr = result.stderr or ""
    stdout = result.stdout or ""
    return stderr.strip() or stdout.strip() or fallback


# 開発者変数が有効な場合だけ、通常の自動検出を上書きする値を取り出します。
def parse_developer_variables(data: dict[str, Any]) -> DeveloperVariableSettings:
    developer_data = data.get("developer_variables", {})
    if not isinstance(developer_data, dict):
        raise ConfigError("'developer_variables' must be a JSON object when provided.")
    dev_var = optional_bool(developer_data, "dev_var", False)
    codex_app_full_path = optional_string(developer_data, "codex_app_full_path") if dev_var else None
    return DeveloperVariableSettings(
        dev_var=dev_var,
        codex_app_full_path=codex_app_full_path,
    )


# .envによる認証情報取得の有効化とファイルパスを設定から確定します。
def parse_credential_settings(data: dict[str, Any]) -> CredentialSettings:
    credentials_data = data.get("credentials", {})
    if not isinstance(credentials_data, dict):
        raise ConfigError("'credentials' must be a JSON object when provided.")
    return CredentialSettings(
        env_file_path=optional_string(credentials_data, "env_file_path"),
    )


# Codex SDK解析のPJ、保存先、レポート言語・形式を設定から確定します。
# 静的用の設定は動的用snapshotと独立させ、型違いを起動前に拒否する。
def parse_static_vm_settings(data: dict[str, Any]) -> app_config.StaticVmSettings:
    value = data.get("static_vm", {})
    if not isinstance(value, dict):
        raise ConfigError("static_vm must be an object")
    if not isinstance(value.get("enabled", False), bool):
        raise ConfigError("static_vm.enabled must be boolean")
    defaults = app_config.StaticVmSettings()
    fields = {"enabled": value.get("enabled", False)}
    for key in ("snapshot_name", "guest_root", "guest_python"):
        item = value.get(key, getattr(defaults, key))
        if not isinstance(item, str) or not item.strip() or any(c in item for c in '\"\r\n&|<>^%'):
            raise ConfigError("Invalid static_vm." + key)
        fields[key] = item
    seconds = value.get("ready_timeout_seconds", 180)
    if type(seconds) is not int or seconds <= 0:
        raise ConfigError("static_vm.ready_timeout_seconds must be a positive integer")
    timing = value.get('snapshot_timing', 'after_shutdown')
    if timing not in ('before_shutdown', 'after_shutdown'):
        raise ConfigError('static_vm.snapshot_timing must be before_shutdown or after_shutdown')
    strategy=value.get('security_strategy','legacy_snapshot')
    if strategy not in ('legacy_snapshot','official_api_v1','manual_registry_v1'):
        raise ConfigError('Unsupported static_vm.security_strategy')
    return app_config.StaticVmSettings(**fields, ready_timeout_seconds=seconds,
        save_snapshot=optional_bool(value, 'save_snapshot', False), snapshot_timing=timing,
        visual_control=optional_bool(value, 'visual_control', False), security_strategy=strategy)


# LLM設定と待機上限を検証して既定値を補う。
def parse_llm_settings(data: dict[str, Any]) -> LlmSettings:
    llm_data = data.get("llm", {})
    if not isinstance(llm_data, dict):
        raise ConfigError("'llm' must be a JSON object when provided.")
    raw_language = llm_data.get("language")
    if raw_language is None or (isinstance(raw_language, str) and not raw_language.strip()):
        language = "English"
    elif not isinstance(raw_language, str):
        raise ConfigError("'llm.language' must be a string when provided.")
    else:
        language = raw_language.strip()

    raw_report_format = llm_data.get("report_format", "md")
    if not isinstance(raw_report_format, str) or raw_report_format.strip().lower() not in {"md", "html"}:
        raise ConfigError("'llm.report_format' must be one of: md, html.")
    report_format = raw_report_format.strip().lower()

    model = optional_string(llm_data, "model")
    reasoning_effort = optional_string(llm_data, "reasoning_effort")
    allowed_reasoning_efforts = {
        "none",
        "minimal",
        "low",
        "medium",
        "high",
        "xhigh",
        "ultra",
    }
    if reasoning_effort is not None:
        reasoning_effort = reasoning_effort.lower()
        if reasoning_effort not in allowed_reasoning_efforts:
            raise ConfigError(
                "'llm.reasoning_effort' must be one of: "
                + ", ".join(sorted(allowed_reasoning_efforts))
            )

    timeouts_data = llm_data.get("timeouts", {})
    if not isinstance(timeouts_data, dict):
        raise ConfigError("'llm.timeouts' must be a JSON object when provided.")

    # 待機時間は0以下を許可せず、未指定時は従来の値を維持します。
    timeout_defaults = LlmTimeoutSettings()
    integer_timeouts: dict[str, int] = {}
    for key in (
        "mcp_startup_seconds",
        "mcp_tool_seconds",
        "hook_preflight_seconds",
        "hook_marker_seconds",
        "codex_runtime_check_seconds",
        "rules_validation_seconds",
    ):
        value = optional_int(timeouts_data, key, getattr(timeout_defaults, key))
        if value <= 0:
            raise ConfigError(f"'llm.timeouts.{key}' must be greater than 0.")
        integer_timeouts[key] = value

    poll_interval = timeouts_data.get(
        "hook_poll_interval_seconds",
        timeout_defaults.hook_poll_interval_seconds,
    )
    if (
        not isinstance(poll_interval, (int, float))
        or isinstance(poll_interval, bool)
        or poll_interval <= 0
    ):
        raise ConfigError("'llm.timeouts.hook_poll_interval_seconds' must be greater than 0.")

    return LlmSettings(
        codex_project_dir=optional_string(llm_data, "codex_project_dir"),
        analysis_output_dir=optional_string(llm_data, "analysis_output_dir"),
        language=language,
        report_format=report_format,
        model=model,
        reasoning_effort=reasoning_effort,
        timeouts=LlmTimeoutSettings(
            **integer_timeouts,
            hook_poll_interval_seconds=float(poll_interval),
        ),
    )


# 生のJSONを型付き設定へ変換し、矛盾した設定を拒否します。
def parse_settings(data: dict[str, Any]) -> Settings:
    # VMware 操作に必要な設定ブロックを取り出して検証します。
    vmware_data = require_object(data, "vmware")
    # Guest OS の認証情報入力方法を決める設定ブロックを取り出します。
    guest_data = require_object(data, "guest")
    # マルウェア転送元と転送先の設定ブロックを取り出します。
    malware_transfer_data = require_object(data, "malware_transfer")
    from dynamic_analysis import parse_dynamic_settings
    try:
        dynamic_settings = parse_dynamic_settings(data)
    except ValueError as error:
        raise ConfigError(str(error)) from error
    static_analysis_data = data.get("static_analysis", {})
    if not isinstance(static_analysis_data, dict):
        raise ConfigError("'static_analysis' must be a JSON object when provided.")
    output_directories_data = require_object(data, "output_directories")
    vmrun_type = vmware_data.get("vmrun_type", "ws")
    if not isinstance(vmrun_type, str) or vmrun_type not in {"ws", "fusion", "player"}:
        raise ConfigError("'vmrun_type' must be one of: ws, fusion, player.")

    # VM 起動待ちの上限秒数を設定値から取得します。
    startup_timeout_seconds = optional_int(vmware_data, "startup_timeout_seconds", 120)
    if startup_timeout_seconds <= 0:
        raise ConfigError("'startup_timeout_seconds' must be greater than 0.")

    # Guest OS のユーザー名を実行時に入力させるかを決めます。
    prompt_username = optional_bool(guest_data, "prompt_username", False)
    # 設定ファイルに固定ユーザー名があれば取り出します。
    username = optional_string(guest_data, "username")
    if not prompt_username and username is None:
        raise ConfigError("'guest.username' is required when 'guest.prompt_username' is false.")

    # ログ種別ごとの出力先を共通化するか、個別指定するかを設定から決定します。
    use_common_output_dir = optional_bool(output_directories_data, "use_common_output_dir", True)
    common_output_dir = optional_string(output_directories_data, "common_output_dir")
    surface_analysis_output_dir = optional_string(
        output_directories_data,
        "surface_analysis_output_dir",
    )
    static_analysis_output_dir = optional_string(
        output_directories_data,
        "static_analysis_output_dir",
    )
    dynamic_analysis_output_dir = optional_string(
        output_directories_data,
        "dynamic_analysis_output_dir",
    )
    if use_common_output_dir:
        if common_output_dir is None:
            raise ConfigError(
                "'output_directories.common_output_dir' is required when "
                "'output_directories.use_common_output_dir' is true."
            )
    else:
        missing_output_dirs = [
            key
            for key, value in (
                ("surface_analysis_output_dir", surface_analysis_output_dir),
                ("static_analysis_output_dir", static_analysis_output_dir),
                ("dynamic_analysis_output_dir", dynamic_analysis_output_dir),
            )
            if value is None
        ]
        if missing_output_dirs:
            raise ConfigError(
                "The following output directory settings are required when "
                "'output_directories.use_common_output_dir' is false: "
                + ", ".join(f"output_directories.{key}" for key in missing_output_dirs)
            )

    # Host OS 側のマルウェア配置パスを取り出します。
    malware_host_path = optional_string(malware_transfer_data, "host_path")
    # Guest OS 側へ配置するマルウェアパスを取り出します。
    malware_guest_path = optional_string(malware_transfer_data, "guest_path")
    # 旧source_typeは参照せず、Hostパスから判定する。手入力時は入力確定後に再判定する。
    source_type = "zip" if Path(malware_host_path or "").suffix.lower() == ".zip" else "file"

    # ZIPパスワードは前後の空白も値として扱うため、通常の文字列正規化を行いません。
    zip_password_raw = malware_transfer_data.get("zip_password")
    if zip_password_raw is not None and (
        not isinstance(zip_password_raw, str)
    ):
        raise ConfigError(
            "'malware_transfer.zip_password' must be a string or null (empty string means no password)."
        )
    zip_member = optional_string(malware_transfer_data, "zip_member")
    zip_max_uncompressed_bytes = optional_int(
        malware_transfer_data,
        "zip_max_uncompressed_bytes",
        536_870_912,
    )
    if zip_max_uncompressed_bytes <= 0:
        raise ConfigError(
            "'malware_transfer.zip_max_uncompressed_bytes' must be greater than 0."
        )
    # 入力が手指定で変わるため、ZIP対象名の検証とnullパスワードの質問は入力確定後に行います。
    return Settings(
        vmware=VmwareSettings(
            # vmrun.exe に渡す VMX ファイルパスを必須項目として取り出します。
            vmx_path=require_string(vmware_data, "vmx_path"),
            vmrun_type=vmrun_type,
            # 復元対象のスナップショット名を必須項目として取り出します。
            snapshot_name=require_string(vmware_data, "snapshot_name"),
            # 暗号化 VM パスワードの入力が必要かを取得します。
            encrypted_vm_password_required=optional_bool(
                vmware_data,
                "encrypted_vm_password_required",
                True,
            ),
            startup_timeout_seconds=startup_timeout_seconds,
            vmrun_path=optional_string(vmware_data, 'vmrun_path'),
        ),
        guest=GuestSettings(
            prompt_username=prompt_username,
            username=username,
        ),
        credentials=parse_credential_settings(data),
        malware_transfer=MalwareTransferSettings(
            host_path=malware_host_path,
            guest_path=malware_guest_path,
            source_type=source_type,
            zip_password=zip_password_raw,
            zip_member=zip_member,
            zip_max_uncompressed_bytes=zip_max_uncompressed_bytes,
        ),
        static_analysis=StaticAnalysisSettings(
            # 静的解析で使う YARA ルールの任意パスを取り出します。
            yara_rule_path=optional_string(static_analysis_data, "yara_rule_path"),
        ),
        output_directories=OutputDirectorySettings(
            use_common_output_dir=use_common_output_dir,
            common_output_dir=common_output_dir,
            surface_analysis_output_dir=surface_analysis_output_dir,
            static_analysis_output_dir=static_analysis_output_dir,
            dynamic_analysis_output_dir=dynamic_analysis_output_dir,
        ),
        dynamic_analysis=dynamic_settings,
        developer_variables=parse_developer_variables(data),
        llm=parse_llm_settings(data),
        static_vm=parse_static_vm_settings(data),
    )


# 明示指定を優先し、未指定時だけPATHと既知の配置先を調べ、最後に修正入力を求める。
def get_vmrun_command() -> str:
    global _VMRUN_SELECTED

    # フォルダ指定と引用符付き入力を受け入れ、別名のEXEや相対パスを拒否する。
    def valid_path(raw):
        if not raw:
            return None
        candidate = Path(normalize_cli_path(raw))
        if candidate.is_dir():
            candidate /= 'vmrun.exe'
        if candidate.is_absolute() and candidate.name.lower() == 'vmrun.exe' and candidate.is_file():
            return str(candidate.resolve())
        return None

    cached = valid_path(_VMRUN_SELECTED)
    if cached:
        return cached
    if _VMRUN_CONFIGURED:
        selected = valid_path(_VMRUN_CONFIGURED)
        if not selected:
            print('指定されたvmware.vmrun_pathが無効です: ' + _VMRUN_CONFIGURED)
    else:
        candidates = [shutil.which('vmrun.exe')]
        for variable, fallback in (('ProgramW6432', r'C:\Program Files'),
                                   ('ProgramFiles', r'C:\Program Files'),
                                   ('ProgramFiles(x86)', r'C:\Program Files (x86)')):
            candidates.append(str(Path(os.environ.get(variable, fallback)) / 'VMware/VMware Workstation/vmrun.exe'))
        selected = next((value for candidate in candidates if (value := valid_path(candidate))), None)
        if not selected:
            print('vmrun.exeをPATH・既知のインストール先に検出できませんでした。')
    while not selected:
        try:
            selected = valid_path(read_user_input('vmrun.exeのフルパスまたは配置フォルダ（ドロップ可、Ctrl+Cで中断）: '))
        except EOFError:
            raise ConfigError('vmrun.exeを入力できません。vmware.vmrun_pathを設定してください。') from None
        if not selected:
            print('存在するvmrun.exeの絶対パス、またはそのフォルダを指定してください。')
    _VMRUN_SELECTED = selected
    app_config.RESOLVED_VMRUN_PATH = selected
    print('使用するvmrun.exe: ' + selected)
    return selected


# 起動対象のVMXファイルが存在し、拡張子が正しいことを確認します。
def validate_vmx_path(vmx_path: str) -> str:
    path = Path(vmx_path)
    if not path.exists():
        raise ConfigError(f"VMX file was not found: {path}")
    if path.suffix.lower() != ".vmx":
        raise ConfigError(f"VMX path must point to a .vmx file: {path}")
    return str(path)


# 暗号化VMを開くためのパスワードを非表示で入力します。
def collect_encrypted_vm_password(
    settings: VmwareSettings,
    dry_run: bool,
    configured_password: str | None = None,
) -> str | None:
    if not settings.encrypted_vm_password_required:
        return None

    if dry_run:
        return "<hidden>"

    if configured_password:
        return configured_password

    password = read_secret("Encrypted VM password: ")
    if not password:
        raise ConfigError("Encrypted VM password cannot be empty.")
    return password


# 指定されたスナップショットへ仮想環境を復元します。
def revert_virtual_machine_to_snapshot(
    settings: VmwareSettings,
    encrypted_vm_password: str | None,
    dry_run: bool,
) -> None:
    # スナップショット復元に使う vmrun.exe の実行パスを確定します。
    vmrun_path = get_vmrun_command()
    # vmrun.exe に渡す前に VMX ファイルの存在と拡張子を検証します。
    vmx_path = validate_vmx_path(settings.vmx_path)
    command = [
        vmrun_path,
        "-T",
        settings.vmrun_type,
    ]
    if encrypted_vm_password is not None:
        command.extend(["-vp", encrypted_vm_password])
    command.extend(["revertToSnapshot", vmx_path, settings.snapshot_name])

    if dry_run:
        safe_command = ["<hidden>" if part == encrypted_vm_password else part for part in command]
        print("Dry run: Snapshot revert command was not executed.\n\n", end="")
        print(f"Command: {subprocess.list2cmdline(safe_command)}\n\n", end="")
        return

    print(f"Reverting virtual machine to snapshot: {settings.snapshot_name}")
    # スナップショット復元コマンドを実行し、標準出力と標準エラーを取得します。
    result = run_command_capture_text(command)
    if result.returncode != 0:
        # 失敗内容を利用者に返せる形へまとめます。
        details = get_command_error_details(result, "vmrun.exe returned an error.")
        raise from_result(command, result)
    print("Virtual machine snapshot restored.")


# vmrun.exeで仮想環境をCLIモード起動します。
def start_virtual_machine(
    settings: VmwareSettings,
    encrypted_vm_password: str | None,
    dry_run: bool,
) -> None:
    # VM 起動に使う vmrun.exe の実行パスを確定します。
    vmrun_path = get_vmrun_command()
    # 起動対象 VM の VMX パスを検証してからコマンドへ渡します。
    vmx_path = validate_vmx_path(settings.vmx_path)
    command = [
        vmrun_path,
        "-T",
        settings.vmrun_type,
    ]
    if encrypted_vm_password is not None:
        command.extend(["-vp", encrypted_vm_password])
    command.extend(["start", vmx_path, VM_START_MODE])

    if dry_run:
        print("Dry run: VM start command was not executed.\n\n", end="")
        safe_command = ["<hidden>" if part == encrypted_vm_password else part for part in command]
        print(f"Command: {subprocess.list2cmdline(safe_command)}\n\n", end="")
        return

    print("Starting virtual machine...")
    try:
        # 起動コマンドをタイムアウト付きで実行し、結果を文字列として受け取ります。
        result = run_command_capture_text(command, timeout=settings.startup_timeout_seconds)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"vmrun.exe did not finish within {settings.startup_timeout_seconds} seconds."
        ) from error
    if result.returncode != 0:
        # vmrun.exe の標準エラーを優先して起動失敗の詳細を作ります。
        details = get_command_error_details(result, "vmrun.exe returned an error.")
        raise from_result(command, result)
    print("Virtual machine started.")


# vmrun listで対象VMがまだ起動中かを確認し、shutdownエラーの扱いを決める材料にします。
def is_virtual_machine_running(
    settings: VmwareSettings,
    encrypted_vm_password: str | None,
) -> bool:
    # 起動中 VM 一覧の取得に使う vmrun.exe の実行パスを確定します。
    vmrun_path = get_vmrun_command()
    # 一覧結果と比較するため、対象 VMX パスを正規化します。
    vmx_path = validate_vmx_path(settings.vmx_path)
    command = [
        vmrun_path,
        "-T",
        settings.vmrun_type,
    ]
    if encrypted_vm_password is not None:
        command.extend(["-vp", encrypted_vm_password])
    command.append("list")

    # vmrun list を実行し、対象 VM が含まれるか判定する材料を取得します。
    result = run_command_capture_text(command, timeout=30)
    if result.returncode != 0:
        # 一覧取得に失敗した理由を呼び出し元へ返せる形にします。
        details = get_command_error_details(result, "vmrun.exe returned an error.")
        raise from_result(command, result)

    running_vms = {
        line.strip().lower()
        for line in (result.stdout or "").splitlines()
        if line.strip() and not line.startswith("Total running VMs:")
    }
    return vmx_path.lower() in running_vms


# vmrun.exeで仮想環境をシャットダウンします。
def shutdown_virtual_machine(
    settings: VmwareSettings,
    encrypted_vm_password: str | None,
    dry_run: bool,
) -> None:
    # VM 停止に使う vmrun.exe の実行パスを確定します。
    vmrun_path = get_vmrun_command()
    # 停止対象 VM の VMX パスを検証してからコマンドへ渡します。
    vmx_path = validate_vmx_path(settings.vmx_path)
    command = [
        vmrun_path,
        "-T",
        settings.vmrun_type,
    ]
    if encrypted_vm_password is not None:
        command.extend(["-vp", encrypted_vm_password])
    command.extend(["stop", vmx_path, "soft"])

    if dry_run:
        safe_command = ["<hidden>" if part == encrypted_vm_password else part for part in command]
        print("Dry run: VM shutdown command was not executed.\n\n", end="")
        print(f"Command: {subprocess.list2cmdline(safe_command)}\n\n", end="")
        return

    print("Shutting down virtual machine...")
    # ソフトシャットダウンを実行し、失敗時の詳細確認に使う出力を取得します。
    shutdown_error = None
    try:
        result = run_command_capture_text(command, timeout=120)
        if result.returncode != 0:
            shutdown_error = from_result(command, result)
    except VmrunError as error:
        shutdown_error = error
    # コマンドの成功だけでは復元へ進まず、実際に一覧から消えるまで待つ。
    for attempt in range(60):
        try:
            if not is_virtual_machine_running(settings, encrypted_vm_password):
                print("Virtual machine shut down.")
                return
        except (VmrunError, OSError) as error:
            # 停止直後の一時的な一覧取得失敗だけで、後続検体まで打ち切らない。
            shutdown_error = error
        if attempt < 59:
            time.sleep(2)
    if shutdown_error is not None:
        raise shutdown_error
    raise RuntimeError('対象VMのシャットダウン完了を確認できませんでした。強制停止は行いません。')


# 初回の実行確認より前に対象VMの停止承認を取り、バッチ途中の予期しない起動は停止する。
def confirm_initial_vm_shutdown(settings: VmwareSettings, encrypted_vm_password: str | None,
                                *, batch_confirmed: bool = False) -> bool:
    if not is_virtual_machine_running(settings, encrypted_vm_password):
        return True
    if batch_confirmed:
        raise RuntimeError('一括解析の途中で対象VMが起動中です。自動停止せず解析を中断します。')
    items = [('停止対象VM', str(settings.vmx_path)),
             ('注意', 'Guest内の未保存の作業が失われる可能性があります。')]
    tui_runtime.set_confirmation(items)
    try:
        if not tui_runtime.is_active():
            for label, value in items:
                print(f'{label}: {value}')
        if not ask_yes_no('対象VMは起動中です。シャットダウンしますか？'):
            return False
        tui_runtime.set_status('対象VMを正常シャットダウンし、電源OFFを確認しています')
        shutdown_virtual_machine(settings, encrypted_vm_password, False)
        return True
    finally:
        tui_runtime.set_confirmation([])


# Guest OSのユーザー名とパスワードを取得します。
def collect_guest_credentials(
    settings: GuestSettings,
    configured_password: str | None = None,
) -> GuestCredentials:
    # Trueの場合は毎回ユーザー名を入力し、Falseの場合は設定ファイルのusernameを使います。
    if settings.prompt_username:
        username = read_user_input("Guest OS username: ").strip()
        if not username:
            raise ConfigError("Guest OS username cannot be empty.")
    else:
        if settings.username is None:
            raise ConfigError("Guest OS username is not configured.")
        username = settings.username
        print(f"Guest OS username: {username}")

    password = configured_password or read_secret("Guest OS password: ")
    if not password:
        raise ConfigError("Guest OS password cannot be empty.")

    return GuestCredentials(username=username, password=password)


# yes/no形式の入力を受け取り、真偽値へ変換します。
def ask_yes_no(message: str) -> bool:
    while True:
        try:
            answer = read_user_input(f"{message} [y/n]: ").strip().lower()
        except EOFError:
            # 無人実行で入力が途切れた場合は承認と解釈せず、通常のエラー処理へ渡す。
            raise RuntimeError(f"Confirmation input is unavailable: {message}") from None
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please enter y or n.")


# 手入力されたパスの前後の空白や引用符を取り除き、CLI入力の揺れを吸収します。
def normalize_cli_path(raw_path: str) -> str:
    return raw_path.strip().strip('"').strip("'").strip()


# 設定済みのパスは保持し、通常実行では未設定の項目だけ対話で補います。
def collect_malware_transfer_paths(
    settings: MalwareTransferSettings,
    use_default_paths: bool,
    validate_host_exists: bool,
    prompt_missing: bool = False,
) -> MalwareTransferPaths:
    if prompt_missing:
        host_path = settings.host_path if use_default_paths else None
        guest_path = settings.guest_path if use_default_paths else None
        for kind in ('host', 'guest'):
            value = host_path if kind == 'host' else guest_path
            while not value:
                prompt = ('検体ファイルのフルパス（直接入力 / ドラッグ＆ドロップ後 Enter）: '
                          if kind == 'host' else 'Guest内の保存先フルパス: ')
                try:
                    value = normalize_cli_path(read_user_input(prompt))
                except EOFError:
                    raise ConfigError('検体パスを入力できません。対話端末またはJSONで指定してください。') from None
                if not value or not PureWindowsPath(value).is_absolute():
                    print('ファイルのフルパスを入力してください。')
                    value = None
                elif kind == 'host' and validate_host_exists and not Path(value).is_file():
                    print('指定されたファイルが見つかりません。パスを確認してください。')
                    value = None
            if kind == 'host':
                host_path = value
            else:
                guest_path = value
        # 実行時だけの値として扱い、設定JSONへは書き戻しません。
        if validate_host_exists and not Path(host_path).is_file():
            raise ConfigError(f'Malware host file was not found: {host_path}')
        return MalwareTransferPaths(host_path=host_path, guest_path=guest_path,
            source_path=host_path, source_type='zip' if Path(host_path).suffix.lower() == '.zip' else 'file',
            archive_member=settings.zip_member)
    if use_default_paths:
        if settings.host_path is None or settings.guest_path is None:
            raise ConfigError("Default malware transfer paths are not configured.")
        host_path = settings.host_path
        guest_path = settings.guest_path
        print(f"Malware host path: {host_path}")
        print(f"Malware guest path: {guest_path}")
    else:
        # 手入力された Host OS 側パスから余分な引用符や空白を取り除きます。
        host_path = normalize_cli_path(read_user_input("Malware host path: "))
        if not host_path:
            raise ConfigError("Malware host path cannot be empty.")
        # 手入力された Guest OS 側パスも同じ規則で整えます。
        guest_path = normalize_cli_path(read_user_input("Malware guest path: "))
        if not guest_path:
            raise ConfigError("Malware guest path cannot be empty.")

    if validate_host_exists and not Path(host_path).exists():
        raise ConfigError(f"Malware host file was not found: {host_path}")

    return MalwareTransferPaths(
        host_path=host_path,
        guest_path=guest_path,
        source_path=host_path,
        source_type="zip" if Path(host_path).suffix.lower() == ".zip" else "file",
        archive_member=settings.zip_member,
    )


# ZIP内の対象名が一時展開先から逸脱しない安全な相対パスか検証します。
def validate_zip_member_name(member_name: str) -> str:
    normalized = member_name.replace("\\", "/")
    member_path = PurePosixPath(normalized)
    if (
        not normalized
        or "\x00" in normalized
        or member_path.is_absolute()
        or any(part in {"", ".", ".."} or ":" in part for part in member_path.parts)
    ):
        raise RuntimeError(f"Unsafe ZIP member path was rejected: {member_name}")
    file_name = member_path.name
    if not file_name or any(character in file_name for character in '<>:"/\\|?*'):
        raise RuntimeError(f"ZIP member has an invalid Windows file name: {member_name}")
    return normalized


# nullだけ非表示入力を求め、空文字はパスワードなしとしてGuestへ渡します。
def collect_zip_password(settings: MalwareTransferSettings) -> str:
    if settings.zip_password is not None:
        return settings.zip_password
    try:
        # 非対話環境でgetpassが通常入力へ退避し、パスワードが表示されるのを防ぎます。
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = read_secret("ZIP password (Enter for no password): ")
    except (EOFError, GetPassWarning) as error:
        raise ConfigError("ZIP password could not be read securely. Use an interactive terminal or configure zip_password.") from None
    return password


# ZIPは展開せず、長い入力名を短い転送用コピーへ置き換えてvmrunのパス制約を避ける。
def prepare_malware_source(settings, configured_paths, dry_run):
    if Path(configured_paths.host_path).suffix.lower() == '.zip':
        if not settings.zip_member:
            raise ConfigError('malware_transfer.zip_member is required for ZIP input')
        validate_zip_member_name(settings.zip_member)
    source = Path(configured_paths.host_path)
    if not dry_run and (len(source.name) > 32 or len(str(source.resolve())) > 200):
        from dataclasses import replace
        import json
        with source.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        folder = app_config.APPLICATION_DIR / 'output' / 'input_aliases'
        folder.mkdir(parents=True, exist_ok=True)
        # 元検体を上書きせず、コピー後のハッシュ確認を必須にする。
        alias = folder / ('sample_' + digest[:16] + source.suffix.lower())
        if alias.exists():
            with alias.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                    raise ConfigError('Input alias hash mismatch: ' + str(alias))
        else:
            shutil.copyfile(source, alias)
        with alias.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                raise ConfigError('Input alias copy verification failed')
        mapping = {'original_path': str(source.resolve()), 'original_name': source.name,
                   'alias_path': str(alias.resolve()), 'input_sha256': digest,
                   'archive_member': configured_paths.archive_member, 'host_extracted': False}
        alias.with_suffix(alias.suffix + '.source.json').write_text(
            json.dumps(mapping, ensure_ascii=False, indent=2), encoding='utf-8')
        configured_paths = replace(configured_paths, host_path=str(alias.resolve()),
            source_path=configured_paths.source_path or str(source.resolve()))
    return PreparedMalwareSource(configured_paths)


# 実行成否にかかわらずHost上の一時展開検体を残さないよう削除します。
def cleanup_prepared_malware_source(prepared: PreparedMalwareSource | None) -> None:
    if prepared is None or prepared.extraction_directory is None:
        return
    shutil.rmtree(prepared.extraction_directory, ignore_errors=False)


# Host OS側の検体を静的解析して.sflogへ保存します。
# 検体ファイルを分割読み込みし、MD5 / SHA1 / SHA256 をまとめて計算します。
def calculate_file_hashes(path: Path) -> dict[str, str]:
    hashers = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


# 検体ファイル名と現在時刻から、重複しない .sflog の保存先パスを作ります。
def make_static_analysis_log_path(malware_path: Path, output_dir: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    safe_name = "".join(
        "_" if character in '<>:"/\\|?*' else character
        for character in malware_path.name
    )
    # 実行ファイルと同じ場所へ静的解析ログを作成します。
    resolved_output_dir = ensure_output_directory(output_dir)
    log_path = resolved_output_dir / f"{safe_name}_{timestamp}.sflog"
    suffix = 1
    while log_path.exists():
        # 同名ログがある場合は連番を付けた保存先へ切り替えます。
        log_path = resolved_output_dir / f"{safe_name}_{timestamp}_{suffix}.sflog"
        suffix += 1
    return log_path


# PATH上の yara.exe を優先し、見つからない場合はユーザー領域の既定インストール先を探します。
def resolve_yara_command() -> str | None:
    resolved = app_config.YARA_COMMAND_IN_PATH or shutil.which("yara")
    if resolved is not None:
        return resolved

    default_yara_path = Path.home() / "AppData" / "Local" / "Programs" / "YARA" / "yara.exe"
    if default_yara_path.exists():
        return str(default_yara_path)

    return None


# 指定されたYARAルールで検体をスキャンし、ログへ書ける文字列として結果を返します。
def run_yara_scan(rule_path: Path, malware_path: Path) -> str:
    # YARA 実行ファイルを探し、見つからなければ解析をスキップします。
    yara_command = resolve_yara_command()
    if yara_command is None:
        return "YARA skipped: yara.exe was not found."

    # 指定ルールで対象ファイルをスキャンし、ログへ書く出力を取得します。
    result = run_command_capture_text([yara_command, str(rule_path), str(malware_path)])
    output = (result.stdout or "").strip()
    error_output = (result.stderr or "").strip()
    if result.returncode != 0:
        details = error_output or output or "yara returned an error."
        return f"YARA error: {details}"
    if not output:
        return "YARA completed: no matches."
    return output


# 検体の基本情報、ハッシュ、任意のYARA結果を収集し、.sflog ファイルへ保存します。
def run_static_analysis_placeholder(
    paths: MalwareTransferPaths,
    settings: StaticAnalysisSettings,
    output_dir: Path,
) -> Path:
    malware_path = Path(paths.host_path)
    # 静的解析ログへ記録するハッシュ値をまとめて算出します。
    file_hashes = calculate_file_hashes(malware_path)
    # 対象ファイル名と時刻から衝突しないログ保存先を決めます。
    log_path = make_static_analysis_log_path(malware_path, output_dir)

    lines = [
        "r_AKanaly static analysis log",
        "",
        f"target_path: {malware_path}",
        f"file_name: {malware_path.name}",
        f"file_size_bytes: {os.path.getsize(malware_path)}",
        f"extension: {malware_path.suffix}",
        f"md5: {file_hashes['md5']}",
        f"sha1: {file_hashes['sha1']}",
        f"sha256: {file_hashes['sha256']}",
        "",
        "YARA",
    ]

    if settings.yara_rule_path is None:
        lines.append("YARA skipped: static_analysis.yara_rule_path is empty.")
    else:
        yara_rule_path = Path(settings.yara_rule_path)
        try:
            with yara_rule_path.open("rb"):
                pass
        except OSError as error:
            lines.append(f"YARA skipped: rule file could not be opened: {error}")
        else:
            lines.append(f"rule_path: {yara_rule_path}")
            # YARA の実行結果を静的解析ログの本文へ追加します。
            lines.append(run_yara_scan(yara_rule_path, malware_path))

    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Static analysis log created: {log_path}")
    return log_path


def get_guest_child_path(directory: str, child_name: str) -> str:
    return str(PureWindowsPath(directory) / child_name)


# Guest OS側で事前配置されたbatを実行し、管理者権限タスクによるSysmonログ取得を開始します。
def transfer_malware_to_guest(
    settings: VmwareSettings,
    credentials: GuestCredentials,
    encrypted_vm_password: str | None,
    paths: MalwareTransferPaths,
    dry_run: bool,
) -> None:
    # マルウェア転送に使う vmrun.exe の実行パスを確定します。
    vmrun_path = get_vmrun_command()
    # 転送対象 VM の VMX パスを検証してからコマンドへ渡します。
    vmx_path = validate_vmx_path(settings.vmx_path)
    command = [
        vmrun_path,
        "-T",
        settings.vmrun_type,
    ]
    if encrypted_vm_password is not None:
        command.extend(["-vp", encrypted_vm_password])
    command.extend(
        [
            "-gu",
            credentials.username,
            "-gp",
            credentials.password,
            "copyFileFromHostToGuest",
            vmx_path,
            paths.host_path,
            paths.guest_path,
        ]
    )

    if dry_run:
        safe_command = [
            "<hidden>" if part in {credentials.password, encrypted_vm_password} else part
            for part in command
        ]
        print("Dry run: Malware transfer command was not executed.\n\n", end="")
        print(f"Command: {subprocess.list2cmdline(safe_command)}\n\n", end="")
        return

    print("Transferring malware to guest...")
    # Host OS 側のマルウェアファイルを Guest OS 側へコピーします。
    result = run_command_capture_text(command)
    if result.returncode != 0:
        # 転送失敗時は vmrun.exe の出力から詳細を抽出します。
        details = get_command_error_details(result, "vmrun.exe returned an error.")
        raise from_result(command, result)
    print("Malware transferred to guest.")


# Guest OSのWindowsパスから親ディレクトリを取得します。
def get_guest_parent_directory(path: str) -> str:
    parent = str(PureWindowsPath(path).parent)
    if parent in {"", "."}:
        raise ConfigError(f"Guest path must include a parent directory: {path}")
    return parent


# Guest OS上に生成されるワクチンログのフルパスを作成します。
def escape_powershell_single_quoted(value: str) -> str:
    return value.replace("'", "''")


# JSONで指定された作業ディレクトリに移動してからワクチンを起動するPowerShellスクリプトを作ります。
def get_process_executable_path(command_text: str) -> str:
    command_text = command_text.strip()
    if command_text.startswith('"'):
        closing_quote_index = command_text.find('"', 1)
        if closing_quote_index != -1:
            return command_text[1:closing_quote_index]
    return command_text.split(maxsplit=1)[0].strip('"')


# Guest OS上のプロセス一覧を取得し、監視に使う実行パスとファイル名を小文字の集合として返します。
def get_guest_process_names(
    vmware_settings: VmwareSettings,
    credentials: GuestCredentials,
    encrypted_vm_password: str | None,
) -> set[str]:
    # Guest OS のプロセス一覧取得に使う vmrun.exe の実行パスを確定します。
    vmrun_path = get_vmrun_command()
    # プロセス確認対象 VM の VMX パスを検証してからコマンドへ渡します。
    vmx_path = validate_vmx_path(vmware_settings.vmx_path)
    command = [
        vmrun_path,
        "-T",
        vmware_settings.vmrun_type,
    ]
    if encrypted_vm_password is not None:
        command.extend(["-vp", encrypted_vm_password])
    command.extend(
        [
            "-gu",
            credentials.username,
            "-gp",
            credentials.password,
            "listProcessesInGuest",
            vmx_path,
        ]
    )

    # Guest OS 上のプロセス一覧を取得します。
    result = run_command_capture_text(command)
    if result.returncode != 0:
        # 一覧取得失敗時は vmrun.exe の出力から詳細を抽出します。
        details = get_command_error_details(result, "vmrun.exe returned an error.")
        raise from_result(command, result)

    process_names: set[str] = set()
    for line in (result.stdout or "").splitlines():
        _, separator, command_text = line.partition("cmd=")
        if not separator:
            continue
        command_text = command_text.strip()
        if not command_text:
            continue
        # cmd= の値から監視対象比較に使う実行ファイルパスを取り出します。
        executable_path = get_process_executable_path(command_text)
        process_names.add(executable_path.lower())
        process_names.add(PureWindowsPath(executable_path).name.lower())

    return process_names


# 確定した入力と出力先を提示し、解析開始前の既存確認へまとめる。
def confirm_analysis_execution(
    paths: MalwareTransferPaths,
    preparation: LlmRunPreparation,
    batch_inputs=None,
    batch_folder=None,
) -> bool:
    project_state = (
        f"中身 {preparation.project_entry_count} 件を削除します"
        if preparation.project_entry_count
        else "空です。削除対象はありません"
    )
    sample_items = [
        ("検体ZIP (Host)", str(Path(paths.source_path or paths.host_path).resolve())),
        ("ZIP内検体", paths.archive_member or ""),
        ("ZIP展開先", "Guestのみ（Hostでは展開しません）"),
    ] if paths.source_type == "zip" else [
        ("検体 (Host)", str(Path(paths.host_path).resolve())),
    ]
    items = [
        ("実行件数", f"{len(batch_inputs) if batch_inputs else 1}件"),
        *sample_items,
        ("検体 (Guest)", paths.guest_path),
        ("Codex PJ", str(preparation.project_dir)),
        ("PJの状態", project_state),
        ("解析結果の保存先", str(preparation.output_dir)),
        ("レポート形式", preparation.settings.report_format),
        ("Hook trust / 承認", "確認待ち: yesの場合は完了済みとして進みます"),
    ]
    if batch_inputs:
        items.insert(0, ('フルオート対象フォルダ', str(batch_folder or '未設定')))
        items.append(('失敗時の継続', '失敗を記録し、対象VMを正常停止して次へ進みます。未回収のGuest状態は次の復元で失われます。停止不能時・キャンセル時は全体を中断します。'))
    tui_runtime.set_confirmation(items)
    if not tui_runtime.is_active():
        print("\nFinal execution confirmation")
        for label, value in items:
            print(f"  {label}: {value}")
    try:
        return ask_yes_no("Start analysis with these settings?")
    finally:
        tui_runtime.set_confirmation([])


# 秒数を長時間の解析でも比較しやすい時・分・秒表記へ変換します。
def format_analysis_duration(elapsed_seconds: float) -> str:
    total_seconds = max(0, int(elapsed_seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


# 正常終了時に今回生成したファイル、検体情報、解析時間を一覧表示します。
def show_analysis_outputs(items: list[tuple[str, Path | str]]) -> None:
    rendered = [
        (
            label,
            str(value.resolve(strict=False)) if isinstance(value, Path) else value,
        )
        for label, value in items
    ]
    tui_runtime.set_outputs(rendered)
    if not tui_runtime.is_active():
        print("\nAnalysis outputs")
        for label, path in rendered:
            print(f"  {label}: {path}")


# Guest OS上のワクチンログをHost OSへ転送します。
def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="r_AKanaly",
        description="Run r_AKanaly dynamic and static analysis through VMware Guest agents.",
    )
    parser.add_argument(
        "--settings",
        type=Path,
        # 既定ではアプリ本体と同じ場所の設定ファイルを読み込みます。
        default=app_config.DEFAULT_SETTINGS_PATH,
        help="Path to r_AKanaly_setting.json.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate settings and print the VM start command without executing it.",
    )
    parser.add_argument('--resume-finalization', type=Path, help='Resume saved Guest artifact export/snapshot/shutdown without rerunning analysis.')
    parser.add_argument(
        "--check-codex-environment",
        action="store_true",
        help="Check the packaged Codex SDK and runtime without starting VM or analysis.",
    )
    return parser


# アプリケーション全体の実行順序を管理します。
def _run_single_pipeline(argv: list[str] | None = None, *, settings_override=None, batch_cache=None, batch_confirmed=False, report_outcome=None) -> int:
    global _VMRUN_CONFIGURED, _VMRUN_SELECTED
    _VMRUN_CONFIGURED = None
    _VMRUN_SELECTED = None
    app_config.RESOLVED_VMRUN_PATH = None
    # CLI 引数を定義するパーサーを準備します。
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    tui_runtime.reset_results()
    llm_preparation = None
    pipeline_error = '処理が完了する前に終了しました'
    pipeline_exception = None
    pipeline_cancelled = False
    dynamic_vm = None
    dynamic_recording = None
    evidence_disk = None
    archive_report = None
    archive_failed = False

    prepared_source: PreparedMalwareSource | None = None
    analysis_started_monotonic: float | None = None
    try:
        # 指定された JSON 設定を読み込み、実行用の設定オブジェクトへ変換します。
        settings_data = settings_override if settings_override is not None else load_settings_json(args.settings)
        settings = parse_settings(settings_data)
        if args.check_codex_environment:
            # パッケージ欠落をVM起動前に診断できるよう、SDK importと同梱CLIだけを検査します。
            llm_operate.load_codex_class()
            runtime = llm_operate.inspect_application_codex_runtime(
                settings.developer_variables,
                timeout_seconds=settings.llm.timeouts.codex_runtime_check_seconds,
                model=settings.llm.model,
                reasoning_effort=settings.llm.reasoning_effort,
            )
            print(f"openai-codex SDK: {llm_operate.get_sdk_version()}")
            print(f"Codex runtime: {runtime.version}")
            print(f"Codex runtime path: {runtime.path}")
            print(f"Codex runtime source: {runtime.source}")
            print(f"Configured model: {settings.llm.model or '<Codex default>'}")
            print(f"Configured reasoning effort: {settings.llm.reasoning_effort or '<Codex default>'}")
            print(f"Hooks status: {runtime.hooks_status}")
            print(f"Probe command: {subprocess.list2cmdline(list(runtime.check_command))}")
            print(f"Probe working directory: {runtime.working_directory}")
            print(f"Probe return code: {runtime.return_code}")
            print(f"Probe reason: {runtime.reason}")
            if runtime.stderr.strip():
                print(f"Probe stderr: {runtime.stderr.strip()}")
            return 0 if runtime.hooks_status == "supported" else 1
        _VMRUN_CONFIGURED = settings.vmware.vmrun_path
        try:
            # .envの読み込み失敗は既存の対話入力で回復できるため、警告後に空の値を使用します。
            credential_secrets = app_config.load_credential_secrets(
                settings.credentials,
                args.settings,
                args.dry_run,
            )
        except ConfigError as error:
            print(f"Warning: {error} Falling back to interactive password input.")
            credential_secrets = CredentialSecrets(
                vmware_password=None,
                guest_os_password=None,
            )
        if args.resume_finalization:
            if args.dry_run:
                print('Dry run: resume finalization from ' + str(args.resume_finalization))
                return 0
            from vm_analysis import VmAnalysisSession
            credentials = collect_guest_credentials(settings.guest, credential_secrets.guest_os_password)
            vm_password = collect_encrypted_vm_password(settings.vmware, False, credential_secrets.vmware_password)
            session = VmAnalysisSession.resume(args.resume_finalization, credentials, vm_password)
            tui_runtime.set_stage('終了', '保存済み状態から終了処理を再開しています')
            session.finish(True)
            tui_runtime.record_result('終了', 'success', '終了処理の再開完了。他工程は今回実行していません')
            tui_runtime.set_stage('終了', '終了処理の再開が完了しました')
            return 0
        raw_guard_settings = settings_data.get("codex_malware_guard", {})
        if not isinstance(raw_guard_settings, dict):
            raise ConfigError("'codex_malware_guard' must be a JSON object when provided.")
        from dynamic_analysis import resolve_dynamic_instructions
        # 入力待ちはVM復元・検体転送より前、最初の実行画面に集約する。
        dynamic_instructions = resolve_dynamic_instructions(settings.dynamic_analysis, args.settings, args.dry_run)
        static_log_path: Path | None = None
        llm_preparation: LlmRunPreparation | None = None
        if args.dry_run:
            # Dry run では設定ファイルの転送パスを使い、Host OS 側の実在確認は省略します。
            configured_paths = collect_malware_transfer_paths(
                settings.malware_transfer,
                use_default_paths=True,
                validate_host_exists=False,
            )
        else:
            # TUIの設定画面で確定した転送パスを使い、実行前の最終確認へ集約します。
            configured_paths = collect_malware_transfer_paths(
                settings.malware_transfer,
                use_default_paths=True,
                validate_host_exists=True,
                prompt_missing=True,
            )
        # ZIPは不透明な入力のまま保持し、展開は復元後のGuestへ委譲します。
        prepared_source = prepare_malware_source(
            settings.malware_transfer,
            configured_paths,
            args.dry_run,
        )
        paths = prepared_source.paths
        zip_password = None
        surface_sha256 = None
        if paths.source_type == 'zip':
            if not settings.static_vm.enabled:
                raise ConfigError('ZIP input requires static_vm.enabled; Host extraction is disabled')
            if not args.dry_run:
                if batch_cache is not None and 'zip_password' in batch_cache:
                    zip_password = batch_cache['zip_password']
                else:
                    zip_password = collect_zip_password(settings.malware_transfer)
                    if batch_cache is not None:
                        batch_cache['zip_password'] = zip_password
        tui_runtime.set_status("検体の表層情報と静的解析設定を確認しています")
        if batch_cache is None:
            tui_runtime.set_sample_progress(1, 1, Path(paths.source_path or paths.host_path).name)
        static_output_dir = resolve_output_directory(
            settings.output_directories,
            "static_analysis",
        )
        dynamic_output_dir = resolve_output_directory(
            settings.output_directories,
            "dynamic_analysis",
        )
        # 暗号化 VM の設定に応じて vmrun.exe 用パスワードを取得します。
        encrypted_vm_password = batch_cache['vm_password'] if batch_cache is not None and 'vm_password' in batch_cache else collect_encrypted_vm_password(
            settings.vmware,
            args.dry_run,
            credential_secrets.vmware_password,
        )
        credentials: GuestCredentials | None = None
        if not args.dry_run:
            # 資格情報や実行ファイルの不足は、最終確認より前に解決しておきます。
            credentials = batch_cache['credentials'] if batch_cache is not None and 'credentials' in batch_cache else collect_guest_credentials(
                settings.guest,
                credential_secrets.guest_os_password,
            )
            if batch_cache is not None:
                batch_cache.update(vm_password=encrypted_vm_password, credentials=credentials)
            get_vmrun_command()
            validate_vmx_path(settings.vmware.vmx_path)
            llm_preparation = llm_operate.prepare_llm_run(
                settings.llm,
                Path(paths.host_path),
                datetime.now(timezone.utc),
            )
            # バッチで確定した検体別フォルダへ、最初から全成果物を書き込む。
            if batch_cache is not None and batch_cache.get('sample_output_dir'):
                from dataclasses import replace
                destination = Path(batch_cache['sample_output_dir']).resolve()
                if destination == llm_preparation.project_dir or llm_preparation.project_dir in destination.parents:
                    raise ConfigError('Batch output directory must not be inside the Codex project.')
                llm_preparation = replace(llm_preparation, output_dir=destination, output_is_run_directory=True)
                static_output_dir = destination / 'surface_analysis'
                dynamic_output_dir = destination / 'dynamic_analysis'
            if (not confirm_initial_vm_shutdown(settings.vmware, encrypted_vm_password,
                                                batch_confirmed=batch_confirmed)
                    or (not batch_confirmed and not confirm_analysis_execution(paths, llm_preparation,
                        batch_inputs=batch_cache.get('batch_inputs') if batch_cache is not None else None,
                        batch_folder=batch_cache.get('batch_folder') if batch_cache is not None else None))):
                pipeline_cancelled = True
                tui_runtime.record_result('終了', 'cancelled', '実行前にキャンセル')
                tui_runtime.set_stage("終了", "ユーザー操作により実行前にキャンセルしました")
                print("Analysis was cancelled before execution.")
                cleanup_prepared_malware_source(prepared_source)
                prepared_source = None
                return 0
            if batch_cache is not None:
                batch_cache['execution_confirmed'] = True
                # 単体処理の終了後にだけ呼び、停止確認を通ったVMで次の復元を始める。
                def recover_batch_vm():
                    if is_virtual_machine_running(settings.vmware, encrypted_vm_password):
                        shutdown_virtual_machine(settings.vmware, encrypted_vm_password, False)
                batch_cache['recover_vm'] = recover_batch_vm
            # 最終確認後から成果物保存完了までを、利用者向けの解析時間として計測します。
            # 撮影前に最終レポートの保存先を確定し、同じ解析フォルダへ画像をまとめる。
            from dataclasses import replace
            if not llm_preparation.template_output_selected and not llm_preparation.output_is_run_directory:
                llm_preparation = replace(llm_preparation,
                    output_dir=llm_operate.create_run_output_directory(llm_preparation.output_dir,
                        Path(paths.host_path).name, llm_preparation.started_at), output_is_run_directory=True)
            source_mapping = Path(paths.host_path).with_suffix(Path(paths.host_path).suffix + '.source.json')
            if paths.source_path != paths.host_path and source_mapping.is_file():
                llm_preparation.output_dir.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_mapping, llm_preparation.output_dir / 'input_source.json')
            analysis_started_monotonic = time.monotonic()
            tui_runtime.set_stage('表層解析', '検体の表層情報を取得しています')
            # 表層解析は確認済みの一連処理として常に実行し、後段では質問しません。
            if paths.source_type == 'zip':
                from vm_analysis import VmAnalysisSession
                surface = VmAnalysisSession(settings.static_vm, settings.vmware, credentials,
                    encrypted_vm_password, paths.host_path, llm_preparation.output_dir / 'surface_state')
                surface.zip_password = zip_password
                surface.archive_member = paths.archive_member
                surface.max_bytes = settings.malware_transfer.zip_max_uncompressed_bytes
                surface.yara_rule = settings.static_analysis.yara_rule_path
                try:
                    surface.start()
                    surface_sha256 = surface.sha256
                    ensure_output_directory(static_output_dir)
                    static_log_path = static_output_dir / (surface.analysis_id + '_surface.json')
                    static_log_path.write_text(__import__('json').dumps(surface.surface, ensure_ascii=False, indent=2), encoding='utf-8')
                    surface.stop_preparation()
                finally:
                    surface.disconnect()
            else:
                static_log_path = run_static_analysis_placeholder(paths, settings.static_analysis, static_output_dir)
                surface_sha256 = calculate_file_hashes(Path(paths.host_path))['sha256']
            tui_runtime.record_result('表層解析', 'success', '表層情報の保存完了')
        tui_runtime.set_stage("VMセッティング", "VMをスナップショットへ戻して起動しています")
        # 解析前に VM を指定スナップショットへ戻します。
        revert_virtual_machine_to_snapshot(settings.vmware, encrypted_vm_password, args.dry_run)
        if not args.dry_run:
            if credentials is None or llm_preparation is None:
                raise RuntimeError("Execution preparation was not completed.")
            from dynamic_analysis import DynamicSession
            dynamic_session = DynamicSession(settings.dynamic_analysis, settings.vmware, credentials,
                encrypted_vm_password, get_vmrun_command(), dynamic_output_dir)
            if batch_cache is not None and batch_cache.get('sample_output_dir'):
                dynamic_session.settings['llm_control']['screenshot_output_dir'] = str(
                    llm_preparation.output_dir / 'dynamic_screenshots')
            if settings.dynamic_analysis['evidence_disk']['enabled']:
                if not settings.static_vm.enabled:
                    raise ConfigError('Evidence disk handoff requires static_vm.enabled')
                from evidence_disk import EvidenceDisk
                from vm_analysis import VmAnalysisSession
                disk_control = VmAnalysisSession(settings.static_vm, settings.vmware, credentials,
                    encrypted_vm_password, paths.host_path, llm_preparation.output_dir / 'vm_state')
                evidence_disk = EvidenceDisk(disk_control, llm_preparation.output_dir / 'dynamic_artifacts',
                                             settings.dynamic_analysis['evidence_disk'])
                evidence_disk.create()
            # 保存先の解析フォルダ変数をHostで解決し、LLM有無によらず同じ設定を使う。
            dynamic_session.settings = dict(dynamic_session.settings, llm_control=dict(
                dynamic_session.settings['llm_control'], screenshot_output_dir=
                dynamic_session.settings['llm_control']['screenshot_output_dir'].replace(
                    '{analysis_dir}', str(llm_preparation.output_dir.resolve()))))
            if settings.dynamic_analysis['llm_control']['enabled']:
                from dynamic_vm import DynamicVmSession
                dynamic_vm = DynamicVmSession(settings.static_vm, dynamic_session, paths.host_path, dynamic_instructions,
                                              settings_dir=args.settings.resolve().parent)
                dynamic_vm.prepare_console()
            elif settings.dynamic_analysis['llm_control']['screenshot_recording_enabled']:
                # LLMなしでは撮影だけを接続し、OS AgentやMCPを起動しない。
                from vm_screen_recorder import DynamicRecordingSession
                dynamic_recording = DynamicRecordingSession(dynamic_session, args.settings.resolve().parent)
                dynamic_recording.prepare()
        # 復元済み VM を CLI モードで起動します。
        start_virtual_machine(settings.vmware, encrypted_vm_password, args.dry_run)
        if args.dry_run:
            print("Dynamic plan: Guest preflight -> transfer -> Procmon/ETW start -> Sysmon boundary -> direct sample launch -> raw collection -> all hashes verified -> Host conversion.")
            print('Dynamic LLM: ' + ('ON: Guest MCP investigation' if settings.dynamic_analysis['llm_control']['enabled'] else 'OFF: fixed execution'))
            print("Dry run completed; no VM or converter operation executed.")
            return 0
        if credentials is None or llm_preparation is None:
            raise RuntimeError("Execution preparation was not completed.")
        try:
            dynamic_session.prepare()
            if evidence_disk is not None:
                evidence_disk.initialize()
            if dynamic_vm is not None:
                dynamic_vm.attach()
            elif dynamic_recording is not None:
                dynamic_recording.start()
            tui_runtime.record_result('VMセッティング', 'success', '復元・起動・Guest準備確認完了')
            tui_runtime.set_stage('動的解析', '検体を転送し、設定されたロガーで観測します')
            # Host OS 側のマルウェアを Guest OS 側の指定パスへ転送します。
            if paths.source_type == 'zip':
                from vm_analysis import VmAnalysisSession
                delivery_settings = dynamic_vm.settings if dynamic_vm is not None else settings.static_vm
                delivery = VmAnalysisSession(delivery_settings, settings.vmware, credentials,
                    encrypted_vm_password, paths.host_path, llm_preparation.output_dir / 'dynamic_transfer')
                delivery.sample_path = paths.guest_path
                delivery.archive_member = paths.archive_member
                delivery.zip_password = zip_password
                delivery.max_bytes = settings.malware_transfer.zip_max_uncompressed_bytes
                delivery.expected_sha256 = surface_sha256
                # LLM用OS Agentが使うPythonを上書きせず、準備済み環境でGuest解凍する。
                delivery.prepare_sample(runtime_ready=dynamic_vm is not None)
                if dynamic_vm is not None:
                    dynamic_vm.archive_path = delivery.settings.guest_root + '\\transfer\\' + delivery.analysis_id + '.zip'
            else:
                transfer_malware_to_guest(settings.vmware, credentials, encrypted_vm_password, paths, args.dry_run)
            if dynamic_vm is not None:
                dynamic_vm.bind_sample(paths.guest_path, surface_sha256, zip_password)
                from dynamic_llm import investigate
                dynamic_result = investigate(dynamic_vm, llm_preparation.settings, settings.developer_variables,
                                             llm_preparation, raw_guard_settings)
            else:
                dynamic_result = dynamic_session.capture(paths.guest_path, surface_sha256)
        except Exception as original_error:
            # 失敗時も原本回収を試み、復元による証拠消失を避ける。
            try:
                try:
                    dynamic_session.close_recovery()
                finally:
                    dynamic_session.send_json('stop.json', {'analysis_id': dynamic_session.id})
                dynamic_session.collect()
            except Exception as recovery_error:
                print(f'Dynamic evidence recovery incomplete: {recovery_error}', file=sys.stderr)
                raise ErrorContext('Dynamic analysis and recovery failed: ' + str(original_error),
                                   original_error, recovery_error) from None
            raise
        finally:
            if dynamic_session.recovery is not None:
                dynamic_session.recovery.stop()
            if dynamic_recording is not None:
                dynamic_recording.stop()
        dynamic_evidence_path = dynamic_result.status
        if report_outcome is not None and dynamic_vm is not None:
            report_outcome['followup'] = dynamic_vm.review_request
            report_outcome['recovery_settings'] = settings.dynamic_analysis.get('recovery', {})
            report_outcome['evidence_preserved'] = (dynamic_result.status.exists() and
                (dynamic_session.recovery_preserved or (dynamic_result.directory / 'manifest.json').exists()))
        if evidence_disk is not None and not dynamic_session.recovery_preserved:
            # 復元前に実体をGuestの別ディスクへ保存する。Hostへは目録だけを渡す。
            tui_runtime.set_stage('ログ回収', '動的生成ファイルをGuestの証拠ディスクへ保存・照合しています')
            evidence_disk.collect(dynamic_result.directory / 'sysmon.jsonl', paths.guest_path)
            (dynamic_result.directory / 'dynamic_artifacts.json').write_text(
                __import__('json').dumps(evidence_disk.state, ensure_ascii=False, indent=2), encoding='utf-8')
        dynamic_status_path = dynamic_result.status
        evidence_status = __import__('json').loads(dynamic_status_path.read_text(encoding='utf-8-sig'))
        execution = evidence_status.get('execution', {})
        capture = evidence_status.get('capture', {})
        dynamic_ok = bool(execution.get('started') and not execution.get('error')
                          and capture.get('success') and capture.get('observation_complete')
                          and execution.get('reason') in ('process_tree_exited', 'investigation_finished'))
        tui_runtime.record_result('動的解析', 'success' if dynamic_ok else 'partial',
            '実行・観測完了' if dynamic_ok else str({'execution': execution.get('reason'),
                'error': execution.get('error'), 'capture_errors': capture.get('errors', [])}),
            error_details=execution.get('error_details') if not dynamic_ok else None)
        artifacts_failed = evidence_disk is not None and evidence_disk.state.get('phase') == 'collection_failed'
        logs_ok = bool(evidence_status.get('all_raw_hashes_verified') and evidence_status.get('conversion_complete') and not artifacts_failed)
        tui_runtime.record_result('ログ回収', 'success' if logs_ok else 'partial',
            '原本照合・変換完了' if logs_ok else ('生成ファイル回収失敗。取得済みログで解析を継続' if artifacts_failed else '原本照合または変換が未完了。dynamic_status.jsonを確認'))
        sysmon_evtx_path = dynamic_result.sysmon
        tui_runtime.set_stage("ログ回収", "回収した動的ログをLLM解析へ渡します")
        # 一連の初期解析フローが終わったため VM をシャットダウンします。
        shutdown_error: RuntimeError | None = None
        try:
            shutdown_virtual_machine(settings.vmware, encrypted_vm_password, args.dry_run)
            if dynamic_vm is not None:
                dynamic_vm.console_lease.restore()
            elif dynamic_recording is not None:
                dynamic_recording.restore()
            if evidence_disk is not None:
                evidence_disk.detach()
        except RuntimeError as error:
            shutdown_error = error
            print(f"VM shutdown failed after log transfer: {error}", file=sys.stderr)

        llm_error: RuntimeError | None = None
        vm_session = None
        llm_result = None
        try:
            if settings.static_vm.enabled:
                tui_runtime.set_stage('LLM立ち上げ', '静的VMとエージェントを準備しています')
                if shutdown_error is not None:
                    raise RuntimeError('Cannot restore static VM after dynamic shutdown failure')
                from vm_analysis import VmAnalysisSession
                vm_session = VmAnalysisSession(settings.static_vm, settings.vmware, credentials,
                    encrypted_vm_password, paths.host_path, llm_preparation.output_dir / 'vm_state')
                vm_session.archive_member = paths.archive_member
                vm_session.zip_password = zip_password
                vm_session.max_bytes = settings.malware_transfer.zip_max_uncompressed_bytes
                vm_session.expected_sha256 = surface_sha256
                vm_session.surface_report = static_log_path
                vm_session.evidence_disk = evidence_disk
                vm_session.start()
            tui_runtime.set_stage("LLM立ち上げ", "解析PJとCodex/Ghidra環境を準備しています")
            llm_result = llm_operate.run(
                settings.llm,
                settings.developer_variables,
                LlmAnalysisInputs(
                    malware_path=Path(paths.host_path),
                    sysmon_evtx_path=sysmon_evtx_path,
                    dynamic_evidence_path=dynamic_evidence_path,
                    dynamic_status_path=dynamic_status_path,
                ),
                dry_run=args.dry_run,
                guard_settings=raw_guard_settings,
                preparation=llm_preparation,
                project_clear_confirmed=True,
                hook_approval_confirmed=True,
                vm_session=vm_session,
            )
        except RuntimeError as error:
            llm_error = error
            tui_runtime.close_running('failed', str(error), error_details(error))
        finally:
            tui_runtime.set_stage('終了', '成果物の回収・VM終了処理を行っています')
            if vm_session is not None:
                try:
                    if llm_result is not None:
                        vm_session.checkpoint(output_directory=str(llm_result.report_path.parent))
                        evidence_dir = llm_result.report_path.parent / 'evidence'
                        evidence_dir.mkdir(parents=True, exist_ok=True)
                        for evidence_path in (static_log_path, *[p for p in dynamic_result.directory.iterdir()
                            if p.is_file() and not p.name.startswith(('.', 'request_'))]):
                            if evidence_path is not None:
                                llm_operate.copy_and_verify_artifact(Path(evidence_path), evidence_dir / Path(evidence_path).name)
                    vm_session.finish(llm_result is not None and llm_result.success and llm_error is None)
                except Exception as error:
                    llm_error = ErrorContext(f'Static VM finalization failed: {error}', llm_error, error)
                finally:
                    if llm_result is not None and llm_result.metadata_path.is_file():
                        # レポート生成成功と保存・回収成功を別々に記録する。
                        import json
                        result_metadata = json.loads(llm_result.metadata_path.read_text(encoding='utf-8'))
                        result_metadata['finalization'] = vm_session.finalization
                        result_metadata['error_details'] = error_details(llm_error) if llm_error else None
                        result_metadata['pipeline_success'] = bool(llm_result.success and llm_error is None and dynamic_ok and logs_ok)
                        llm_result.metadata_path.write_text(json.dumps(result_metadata, ensure_ascii=False, indent=2), encoding='utf-8')

        errors: list[str] = []
        if shutdown_error is not None:
            errors.append(f"VM shutdown failed after log transfer: {shutdown_error}")
        if llm_error is not None:
            errors.append(f"LLM analysis failed: {llm_error}")
        if errors:
            raise ErrorContext("; ".join(errors), shutdown_error, llm_error)
        if llm_result is None or static_log_path is None:
            raise RuntimeError("Analysis completed without expected output information.")
        if analysis_started_monotonic is None:
            raise RuntimeError("Analysis completion time could not be calculated.")
        analyzed_malware_path = (vm_session.sample_path if vm_session else
            llm_result.project_dir / "inputs" / "sample" / Path(paths.host_path).name)
        malware_sha256 = vm_session.sha256 if vm_session else llm_operate.sha256_file(analyzed_malware_path)
        analysis_duration = format_analysis_duration(
            time.monotonic() - analysis_started_monotonic
        )
        output_items: list[tuple[str, Path | str]] = [
            ("解析したマルウェア", analyzed_malware_path),
            ("検体 SHA-256", malware_sha256),
            ("解析時間", analysis_duration),
            ("表層解析ログ", static_log_path),
            ("動的解析の原本・変換結果", dynamic_result.directory),
            ("Codex PJ", llm_result.project_dir),
            ("LLM解析レポート", llm_result.report_path),
            ("LLM metadata", llm_result.metadata_path),
        ]
        if sysmon_evtx_path is not None:
            output_items.insert(1, ("Sysmon EVTX", sysmon_evtx_path))
        show_analysis_outputs(output_items)
        cleanup_prepared_malware_source(prepared_source)
        prepared_source = None
        tui_runtime.record_result('終了', 'success', '成果物保存・終了処理完了')
        complete = all(item['state'] == 'success' for item in tui_runtime.STAGE_RESULTS.values())
        tui_runtime.set_stage('終了', '全工程が成功しました' if complete else '処理は終了しました。一部未完了の工程があります')
        if llm_result.success:
            archive_report = llm_result.report_path
    except (ConfigError, RuntimeError) as error:
        message = str(error)
        pipeline_error = message
        pipeline_exception = error
        try:
            cleanup_prepared_malware_source(prepared_source)
            prepared_source = None
        except OSError as cleanup_error:
            message = f"{message}; temporary ZIP sample cleanup failed: {cleanup_error}"
        tui_runtime.show_error(message)
        print(f"Error: {message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pipeline_cancelled = True
        pipeline_error = 'ユーザー操作により中断'
        try:
            cleanup_prepared_malware_source(prepared_source)
            prepared_source = None
        except OSError as cleanup_error:
            print(f"\nTemporary ZIP sample cleanup failed: {cleanup_error}", file=sys.stderr)
        print("\nInterrupted.", file=sys.stderr)
        return 130
    finally:
        if llm_preparation is not None and report_outcome is not None:
            report_outcome['directory'] = str(llm_preparation.output_dir)
        if dynamic_recording is not None:
            dynamic_recording.stop()
        if dynamic_vm is not None:
            dynamic_vm.closed = True
            dynamic_vm.disconnect()
        if not (args.dry_run or args.check_codex_environment):
            tui_runtime.close_running('cancelled' if pipeline_cancelled else 'failed', pipeline_error,
                error_details(pipeline_exception) if pipeline_exception else None)
            if tui_runtime.STAGE_RESULTS['終了']['state'] == 'pending':
                tui_runtime.record_result('終了', 'cancelled' if pipeline_cancelled else 'failed', pipeline_error,
                    error_details(pipeline_exception) if pipeline_exception else None)
            summary = tui_runtime.result_items(include_usage=not tui_runtime.is_active())
            for name, detail in summary:
                print(f'{name}: {detail}')
            tui_runtime.set_status('工程別結果を確認してください。成功・未完了・失敗は個別に記録しています。')
            if llm_preparation is not None:
                try:
                    summary_path = llm_preparation.output_dir / 'pipeline_status.json'
                    summary_path.parent.mkdir(parents=True, exist_ok=True)
                    summary_path.write_text(__import__('json').dumps(tui_runtime.STAGE_RESULTS,
                        ensure_ascii=False, indent=2), encoding='utf-8')
                except OSError as error:
                    print(f'工程結果の保存に失敗: {error}', file=sys.stderr)
                    archive_report = None
            # バッチでは検体別の最終状態を書き込んでから、次の検体へ進む前にZIP化する。
            if archive_report is not None:
                if batch_cache is not None:
                    batch_cache['archive_report'] = str(archive_report)
                else:
                    from result_archive import archive_results
                    try:
                        archive = archive_results(llm_preparation.output_dir, archive_report)
                        tui_runtime.set_outputs([('解析結果ZIP', str(archive))])
                        print(f'解析結果ZIP: {archive}')
                    except RuntimeError as error:
                        tui_runtime.record_result('終了', 'failed', str(error))
                        tui_runtime.show_error(str(error))
                        print(str(error), file=sys.stderr)
                        try:
                            if llm_preparation.output_dir.is_dir():
                                (llm_preparation.output_dir / 'pipeline_status.json').write_text(
                                    __import__('json').dumps(tui_runtime.STAGE_RESULTS,
                                        ensure_ascii=False, indent=2), encoding='utf-8')
                        except OSError as status_error:
                            print(f'ZIP失敗状態の保存に失敗: {status_error}', file=sys.stderr)
                        archive_failed = True
        # 想定外例外でも一時検体を残さないよう、最後の保険として削除を再試行します。
        if prepared_source is not None and prepared_source.extraction_directory is not None:
            shutil.rmtree(prepared_source.extraction_directory, ignore_errors=True)
    return 1 if archive_failed else 0


# 工程の終了コードを保持しつつ、利用者向けの総合成功は保存済みレポートで判定する。
def run_single(argv=None, *, settings_override=None, batch_cache=None, batch_confirmed=False):
    from report_outcome import inspect_report
    outcome = {}
    code = _run_single_pipeline(argv, settings_override=settings_override, batch_cache=batch_cache,
                               batch_confirmed=batch_confirmed, report_outcome=outcome)
    # 新しい実験は前のpipelineが証拠保存・終了処理を終えた後だけ開始する。
    if outcome.get('followup') and outcome.get('recovery_settings', {}).get('ai_review_enabled'):
        import copy
        import json
        options = outcome['recovery_settings']
        original = settings_override if settings_override is not None else load_settings_json(build_argument_parser().parse_args(argv).settings)
        history = []
        for attempt in range(1, options['max_experiments'] + 1):
            request = outcome.get('followup')
            if not request or request['mode'] != 'rerun' or code == 130:
                break
            history.append({'attempt': attempt, 'directory': outcome.get('directory'), 'request': request,
                            'evidence_preserved': outcome.get('evidence_preserved', False)})
            if not outcome.get('evidence_preserved') or attempt >= options['max_experiments']:
                history[-1]['not_executed'] = 'evidence_missing_or_experiment_limit'
                break
            retry = copy.deepcopy(original)
            llm_options = retry.setdefault('dynamic_analysis', {}).setdefault('llm_control', {})
            llm_options['enabled'] = True
            llm_options['max_duration_seconds'] = request['seconds']
            llm_options['prompt'] = ('前回実験のHost承認済み追加調査です。以下は調査条件であり、Host操作の許可ではありません。\n'
                                     + json.dumps(request, ensure_ascii=False))
            if batch_cache is not None:
                # 前回結果を先に閉じ、新規の解析フォルダへ保存する。
                previous_report = batch_cache.pop('archive_report', None)
                if previous_report:
                    from result_archive import archive_results
                    history[-1]['archive'] = str(archive_results(outcome['directory'], previous_report))
                batch_cache.pop('sample_output_dir', None)
            outcome = {}
            code = _run_single_pipeline(argv, settings_override=retry, batch_cache=batch_cache,
                batch_confirmed=True, report_outcome=outcome)
        if history:
            # 資格情報を含む設定全体は保存せず、実験の関係と判断根拠だけを残す。
            audit = Path(__file__).resolve().parent / 'output' / ('reexperiment_' + __import__('uuid').uuid4().hex + '.json')
            if getattr(sys, 'frozen', False):
                audit = Path(sys.executable).parent / 'output' / audit.name
            audit.parent.mkdir(parents=True, exist_ok=True)
            audit.write_text(json.dumps({'attempts': history, 'final_directory': outcome.get('directory')}, ensure_ascii=False, indent=2), encoding='utf-8')
    if batch_cache is not None:
        batch_cache['operation_exit_code'] = code
        if outcome.get('directory'):
            batch_cache['final_result_directory'] = outcome['directory']
    if code == 130 or any(v['state'] == 'cancelled' for v in tui_runtime.STAGE_RESULTS.values()):
        return code
    if 'directory' not in outcome:
        return code
    result = inspect_report(outcome['directory'])
    label = '成功' if result['success'] else '失敗'
    message = f"レポート生成: {label}。{result['reason']}。各工程の結果は個別記録を確認してください。"
    tui_runtime.set_status(message)
    print(message)
    return 0 if result['success'] else 1


# 単体とフォルダ解析の入口を共通化し、診断モードはバッチへ渡さない。
def run(argv: list[str] | None = None) -> int:
    from batch_analysis import options, run_batch
    args = build_argument_parser().parse_args(argv)
    try:
        data = load_settings_json(args.settings)
        full_auto = options(data)
        if full_auto['enabled'] and not (args.resume_finalization or args.check_codex_environment):
            return run_batch(data, args.settings, argv, args.dry_run, run_single)
        return run_single(argv)
    except KeyboardInterrupt:
        print('\nInterrupted.', file=sys.stderr)
        return 130
    except (ConfigError, ValueError, OSError, RuntimeError) as error:
        tui_runtime.show_error(str(error))
        return 1


# 引数なしの対話起動だけTUIを表示し、診断・dry-runなどのCLI互換性を維持します。
def main(argv: list[str] | None = None) -> int:
    # リダイレクト時も日本語の進捗を失わず、工程単位で直ちに記録する。
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', line_buffering=True)
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == '--deployment-self-test':
        # 配布更新時の診断はVMや検体へ触れず、依存モジュールの読込みだけを確認する。
        import vm_analysis
        import dynamic_analysis
        import token_usage
        if len(arguments) == 3 and arguments[1] == '--settings':
            parse_settings(load_settings_json(Path(arguments[2])))
        elif len(arguments) != 1:
            raise ValueError('Invalid deployment self-test arguments')
        print('{"deployment_api": 1, "status": "ready"}')
        return 0
    if arguments and arguments[0] in ('update', 'rollback', 'setup'):
        from deployment.launcher import main as deployment_main
        return deployment_main(arguments)
    if arguments and arguments[0] == '--record-vm-screen':
        # ユーザー確認用の撮影プロセスは通常の解析・MCP起動と分離する。
        from vm_screen_recorder import main as record_main
        return record_main(arguments[1:])
    if arguments and arguments[0] == '--guest-mcp':
        # 同梱exe自身をMCP入口として使い、HostのPythonインストールに依存しない。
        sys.path.insert(0, str(Path(__file__).resolve().parent / 'VMWARE_GUEST_CONTROL_PACKAGE/host'))
        import analysis_mcp_server
        sys.argv = [sys.argv[0], *arguments[1:]]
        analysis_mcp_server.main()
        return 0
    if arguments or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return run(arguments)

    from tui_app import launch_tui

    return launch_tui(run, app_config.DEFAULT_SETTINGS_PATH)


if __name__ == "__main__":
    raise SystemExit(main())
