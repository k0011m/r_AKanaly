from __future__ import annotations

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal


CONFIG_FILE_NAME = "r_AKanaly_setting.json"
VM_START_MODE = "nogui"
DEFAULT_VMRUN_PATH = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
# EXEのエントリーポイントと静的VMモジュールで同じ選択結果を共有する。
RESOLVED_VMRUN_PATH: str | None = None
VMWARE_PASSWORD_ENV_KEY = "R_AKANALY_VMWARE_PASSWORD"
GUEST_OS_PASSWORD_ENV_KEY = "R_AKANALY_GUEST_OS_PASSWORD"


# Represents failures while collecting initial configuration values.
class ConfigError(Exception):
    pass


# Holds VMware settings needed to control the target VM.
@dataclass(frozen=True)
class VmwareSettings:
    vmx_path: str
    vmrun_type: str
    snapshot_name: str
    encrypted_vm_password_required: bool
    startup_timeout_seconds: int
    vmrun_path: str | None = None


# Holds Guest OS login settings before the password is collected interactively.
@dataclass(frozen=True)
class GuestSettings:
    prompt_username: bool
    username: str | None


# .envファイルから認証情報を取得するための設定を保持します。
@dataclass(frozen=True)
class CredentialSettings:
    env_file_path: str | None


# 秘密値がデバッグ表示や例外表示へ露出しない形で実行時パスワードを保持します。
@dataclass(frozen=True, repr=False)
class CredentialSecrets:
    vmware_password: str | None
    guest_os_password: str | None


# Host上の保管形式と、VMへ転送する検体の展開条件を保持します。
@dataclass(frozen=True, repr=False)
class MalwareTransferSettings:
    host_path: str | None
    guest_path: str | None
    source_type: Literal["file", "zip"] = "file"
    zip_password: str | None = None
    zip_member: str | None = None
    zip_max_uncompressed_bytes: int = 536_870_912


# Holds static analysis settings such as the optional YARA rule path.
@dataclass(frozen=True)
class StaticAnalysisSettings:
    yara_rule_path: str | None


# Holds per-stage output directory settings.
@dataclass(frozen=True)
class OutputDirectorySettings:
    use_common_output_dir: bool
    common_output_dir: str | None
    surface_analysis_output_dir: str | None
    static_analysis_output_dir: str | None
    dynamic_analysis_output_dir: str | None


# Holds developer override values and leaves auto-detection active when unset.
@dataclass(frozen=True)
class DeveloperVariableSettings:
    dev_var: bool
    codex_app_full_path: str | None


# LLM解析中の外部プロセスとHook検証に使う待機時間を保持します。
@dataclass(frozen=True)
class LlmTimeoutSettings:
    mcp_startup_seconds: int = 120
    mcp_tool_seconds: int = 600
    hook_preflight_seconds: int = 10
    hook_marker_seconds: int = 15
    hook_poll_interval_seconds: float = 0.25
    codex_runtime_check_seconds: int = 10
    rules_validation_seconds: int = 15


# Codex SDKの解析PJ、結果保存先、レポート言語・形式、待機時間を保持します。
@dataclass(frozen=True)
class LlmSettings:
    codex_project_dir: str | None
    analysis_output_dir: str | None
    language: str
    report_format: Literal["md", "html"] = "md"
    model: str | None = None
    reasoning_effort: str | None = None
    timeouts: LlmTimeoutSettings = field(default_factory=LlmTimeoutSettings)


# Groups all parsed settings used by r_AKanaly.
# Guest常駐解析を選択する設定。旧設定ファイルではHost方式を維持する。
@dataclass(frozen=True)
class StaticVmSettings:
    enabled: bool = False
    snapshot_name: str = "r_AKanaly_analysis_bench_20260924"
    guest_root: str = r"C:\Users\Public\CodexGuestAgent\analysis_bench"
    guest_python: str = r"C:\Users\Public\r_AKanaly\runtime\python\pythonw.exe"
    ready_timeout_seconds: int = 180
    save_snapshot: bool = False
    snapshot_timing: str = 'after_shutdown'
    visual_control: bool = False
    security_strategy: str = 'legacy_snapshot'


@dataclass(frozen=True)
class Settings:
    vmware: VmwareSettings
    guest: GuestSettings
    credentials: CredentialSettings
    malware_transfer: MalwareTransferSettings
    static_analysis: StaticAnalysisSettings
    output_directories: OutputDirectorySettings
    developer_variables: DeveloperVariableSettings
    llm: LlmSettings
    static_vm: StaticVmSettings = field(default_factory=StaticVmSettings)
    dynamic_analysis: dict = field(default_factory=dict)


# Holds Guest OS credentials after interactive password collection.
@dataclass(frozen=True, repr=False)
class GuestCredentials:
    username: str
    password: str


# Holds the final host and guest malware paths used for transfer.
@dataclass(frozen=True)
class MalwareTransferPaths:
    host_path: str
    guest_path: str
    source_path: str | None = None
    source_type: Literal["file", "zip"] = "file"
    archive_member: str | None = None


# ZIPから一時展開した検体と、終了時に削除する作業ディレクトリを保持します。
@dataclass(frozen=True)
class PreparedMalwareSource:
    paths: MalwareTransferPaths
    extraction_directory: Path | None = None


# LLM解析へ渡す検体と動的ログの確定済みパスを保持します。
@dataclass(frozen=True)
class LlmAnalysisInputs:
    malware_path: Path
    sysmon_evtx_path: Path | None
    dynamic_evidence_path: Path
    dynamic_status_path: Path | None = None


# Ghidra MCPツールごとの呼び出し結果を検証可能な形で保持します。
@dataclass(frozen=True)
class GhidraToolVerification:
    tool: str
    status: str
    success: bool
    error: str | None
    arguments: dict[str, Any]


# SessionStart Hookの今回実行専用マーカーと診断先を保持します。
@dataclass(frozen=True)
class HookVerificationContext:
    marker_path: Path
    diagnostics_path: Path
    run_id: str
    run_context_path: Path | None = None


# Python SDKが実際に起動するCodexランタイムの検査結果を保持します。
@dataclass(frozen=True)
class CodexRuntimeInfo:
    path: Path
    version: str
    source: str
    hooks_status: Literal[
        "supported",
        "disabled",
        "unsupported",
        "probe_failed",
        "output_unrecognized",
    ]
    check_command: tuple[str, ...]
    return_code: int | None
    stdout: str
    stderr: str
    working_directory: Path
    reason: str

    @property
    def hooks_supported(self) -> bool:
        return self.hooks_status == "supported"


# LLM解析の成否と、保持したPJ・出力ファイルを呼び出し元へ返します。
@dataclass(frozen=True)
class LlmAnalysisResult:
    success: bool
    project_dir: Path
    thread_id: str | None
    report_path: Path
    metadata_path: Path


# 最終確認前に確定したLLM解析先と、削除対象の有無を保持します。
@dataclass(frozen=True)
class LlmRunPreparation:
    settings: LlmSettings
    project_dir: Path
    output_dir: Path
    project_entry_count: int
    template_output_selected: bool
    started_at: datetime
    output_is_run_directory: bool = False


# Resolves the base directory used to locate bundled/default settings.
def resolve_application_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


# Loads JSON settings and returns only a dictionary usable by typed parsing.
def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"Settings file was not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as error:
        raise ConfigError(f"Settings file is not valid JSON: {error}") from error

    if not isinstance(data, dict):
        raise ConfigError("Settings root must be a JSON object.")

    return data


# 設定ファイルの位置を基準に.envファイルの絶対パスを確定します。
def resolve_env_file_path(env_file_path: str | None, settings_path: Path) -> Path | None:
    if env_file_path is None or not env_file_path.strip():
        return None

    path = Path(env_file_path.strip()).expanduser()
    if not path.is_absolute():
        path = settings_path.resolve().parent / path
    return path.resolve()


# 外部ライブラリや環境変数展開を使わず.envファイルを辞書として読み取ります。
def parse_env_file(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as error:
        raise ConfigError(f"Credential .env file could not be read: {path}") from error

    values: dict[str, str] = {}
    key_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigError(f"Credential .env file has invalid syntax at line {line_number}.")

        raw_key, raw_value = line.split("=", 1)
        key = raw_key.strip()
        if key_pattern.fullmatch(key) is None:
            raise ConfigError(f"Credential .env file has an invalid key at line {line_number}.")

        value = raw_value.strip()
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise ConfigError(
                    f"Credential .env file has an unmatched quote at line {line_number}."
                )
            value = value[1:-1]
        values[key] = value
    return values


# .envの固定キーから空文字を除外して実行時パスワードを構築します。
def load_credential_secrets(
    settings: CredentialSettings,
    settings_path: Path,
    dry_run: bool,
) -> CredentialSecrets:
    if dry_run:
        return CredentialSecrets(vmware_password=None, guest_os_password=None)

    env_path = resolve_env_file_path(settings.env_file_path, settings_path)
    if env_path is None:
        # ランチャーがDPAPIから復号した子プロセス環境を使用し、平文.envを不要にする。
        return CredentialSecrets(vmware_password=os.environ.get(VMWARE_PASSWORD_ENV_KEY) or None,
                                 guest_os_password=os.environ.get(GUEST_OS_PASSWORD_ENV_KEY) or None)

    values = parse_env_file(env_path)
    return CredentialSecrets(
        vmware_password=values.get(VMWARE_PASSWORD_ENV_KEY) or None,
        guest_os_password=values.get(GUEST_OS_PASSWORD_ENV_KEY) or None,
    )


APPLICATION_DIR = resolve_application_dir()
DEFAULT_SETTINGS_PATH = Path(os.environ.get("R_AKANALY_SETTINGS_PATH", str(APPLICATION_DIR / CONFIG_FILE_NAME)))
WINDOWS_PATH = os.environ.get("PATH", "")
VMRUN_COMMAND_IN_PATH = shutil.which("vmrun.exe")
YARA_COMMAND_IN_PATH = shutil.which("yara")

SETTINGS_JSON_ERROR: ConfigError | None = None
try:
    SETTINGS_JSON = load_json(DEFAULT_SETTINGS_PATH)
except ConfigError as error:
    SETTINGS_JSON_ERROR = error
    SETTINGS_JSON = {}

VMWARE = SETTINGS_JSON.get("vmware", {})
GUEST = SETTINGS_JSON.get("guest", {})
CREDENTIALS = SETTINGS_JSON.get("credentials", {})
MALWARE_TRANSFER = SETTINGS_JSON.get("malware_transfer", {})
STATIC_ANALYSIS = SETTINGS_JSON.get("static_analysis", {})
OUTPUT_DIRECTORIES = SETTINGS_JSON.get("output_directories", {})
CODEX_MALWARE_GUARD = SETTINGS_JSON.get("codex_malware_guard", {})
DEVELOPER_VARIABLES = SETTINGS_JSON.get("developer_variables", {})
LLM = SETTINGS_JSON.get("llm", {})

VMWARE_VMRUN_TYPE = VMWARE.get("vmrun_type")
VMWARE_VMX_PATH = VMWARE.get("vmx_path")
VMWARE_SNAPSHOT_NAME = VMWARE.get("snapshot_name")
VMWARE_ENCRYPTED_VM_PASSWORD_REQUIRED = VMWARE.get("encrypted_vm_password_required")
VMWARE_STARTUP_TIMEOUT_SECONDS = VMWARE.get("startup_timeout_seconds")

GUEST_PROMPT_USERNAME = GUEST.get("prompt_username")
GUEST_USERNAME = GUEST.get("username")

CREDENTIALS_ENV_FILE_PATH = CREDENTIALS.get("env_file_path")

MALWARE_TRANSFER_HOST_PATH = MALWARE_TRANSFER.get("host_path")
MALWARE_TRANSFER_GUEST_PATH = MALWARE_TRANSFER.get("guest_path")
# 設定の旧source_typeではなく、Host側の入力拡張子に合わせる。
MALWARE_TRANSFER_SOURCE_TYPE = "zip" if Path(MALWARE_TRANSFER_HOST_PATH or "").suffix.lower() == ".zip" else "file"
MALWARE_TRANSFER_ZIP_MEMBER = MALWARE_TRANSFER.get("zip_member")
MALWARE_TRANSFER_ZIP_MAX_UNCOMPRESSED_BYTES = MALWARE_TRANSFER.get(
    "zip_max_uncompressed_bytes",
    536_870_912,
)


STATIC_ANALYSIS_YARA_RULE_PATH = STATIC_ANALYSIS.get("yara_rule_path")

OUTPUT_DIRECTORIES_USE_COMMON_OUTPUT_DIR = OUTPUT_DIRECTORIES.get("use_common_output_dir")
OUTPUT_DIRECTORIES_COMMON_OUTPUT_DIR = OUTPUT_DIRECTORIES.get("common_output_dir")
OUTPUT_DIRECTORIES_SURFACE_ANALYSIS_OUTPUT_DIR = OUTPUT_DIRECTORIES.get("surface_analysis_output_dir")
OUTPUT_DIRECTORIES_STATIC_ANALYSIS_OUTPUT_DIR = OUTPUT_DIRECTORIES.get("static_analysis_output_dir")
OUTPUT_DIRECTORIES_DYNAMIC_ANALYSIS_OUTPUT_DIR = OUTPUT_DIRECTORIES.get("dynamic_analysis_output_dir")


CODEX_MALWARE_GUARD_ENABLED = CODEX_MALWARE_GUARD.get("enabled")
CODEX_MALWARE_GUARD_MODE = CODEX_MALWARE_GUARD.get("mode")
CODEX_MALWARE_GUARD_FAIL_CLOSED = CODEX_MALWARE_GUARD.get("fail_closed")
CODEX_MALWARE_GUARD_EXTRA_PROTECTED_PATHS = CODEX_MALWARE_GUARD.get("extra_protected_paths")
CODEX_MALWARE_GUARD_DANGEROUS_TOKENS = CODEX_MALWARE_GUARD.get("dangerous_tokens")

DEVELOPER_VARIABLES_DEV_VAR = DEVELOPER_VARIABLES.get("dev_var")
DEVELOPER_VARIABLES_CODEX_APP_FULL_PATH = DEVELOPER_VARIABLES.get("codex_app_full_path")

LLM_CODEX_PROJECT_DIR = LLM.get("codex_project_dir")
LLM_ANALYSIS_OUTPUT_DIR = LLM.get("analysis_output_dir")
LLM_LANGUAGE = LLM.get("language") or "English"
LLM_TIMEOUTS = LLM.get("timeouts", {})
