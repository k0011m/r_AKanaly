from __future__ import annotations

import csv
import hashlib
import html
import importlib.metadata
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any, Iterable

from console_io import read_user_input
from config import (
    APPLICATION_DIR,
    CodexRuntimeInfo,
    CODEX_MALWARE_GUARD,
    DeveloperVariableSettings,
    GhidraToolVerification,
    HookVerificationContext,
    LlmAnalysisInputs,
    LlmAnalysisResult,
    LlmRunPreparation,
    LlmSettings,
)
import tui_runtime


GHIDRA_SERVER_NAME = "r_akanaly_ghidra"
REQUIRED_GHIDRA_TOOLS = (
    "ghidra_analyze",
    "ghidra_list_functions",
    "ghidra_get_strings",
    "ghidra_decompile_function",
)
# 展開型配布はexe隣、単体exeはPyInstaller同梱資材からHookを取得する。
def resolve_hook_template_dir() -> Path:
    adjacent = APPLICATION_DIR / "hookrules"
    if adjacent.is_dir() or not getattr(sys, "frozen", False):
        return adjacent
    return Path(getattr(sys, "_MEIPASS", APPLICATION_DIR)) / "hookrules"


HOOK_TEMPLATE_DIR = resolve_hook_template_dir()
PROMPT_TEMPLATE_PATH = APPLICATION_DIR / "prompts" / "ghidra_analysis.md"
REPORT_PROMPT_PATHS = {
    "md": APPLICATION_DIR / "prompts" / "create_report_md.md",
    "html": APPLICATION_DIR / "prompts" / "create_report_html.md",
}
GHIDRA_SERVER_PATH = APPLICATION_DIR / "ghidra-mcp-ghidra-headless" / "ghidra_mcp_server.py"
GUARD_EXECUTABLE_NAME = "r_AKanaly_guard.exe"
GHIDRA_MCP_EXECUTABLE_NAME = "r_AKanaly_ghidra_mcp.exe"
HOOK_INITIALIZATION_PROMPT = (
    "Session initialization only. Reply exactly SESSION_READY. "
    "Do not inspect workspace files, call any tool, access the network, request permissions, "
    "or reference the malware sample or Ghidra."
)


# Hook確認失敗を機械判定できる原因コードと診断情報付きで通知します。
class HookVerificationError(RuntimeError):
    def __init__(self, code: str, message: str, diagnostics: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.diagnostics = diagnostics or {}


# ---------------------------------------------------------------------------
# 設定値とユーザー入力から解析先ディレクトリを確定する処理
# ---------------------------------------------------------------------------


# JSON値やユーザー入力から空白と外側の引用符を除去します。
def normalize_path_value(raw_path: str | None) -> str | None:
    if raw_path is None:
        return None
    value = raw_path.strip().strip('"')
    return value or None


# null設定がある場合にテンプレート生成か従来の手入力かを選択させます。
def ask_llm_directory_mode() -> str:
    while True:
        answer = read_user_input(
            "LLM directory setting is null. Use template paths or enter paths? [template/input]: "
        ).strip().lower()
        if answer in {"template", "t"}:
            return "template"
        if answer in {"input", "i"}:
            return "input"
        print("Please enter template or input.")


# 検体名と同一日時から衝突しないPJ・出力テンプレートパスを組み立てます。
def build_template_directories(
    sample_path: Path,
    started_at: datetime,
) -> tuple[Path, Path]:
    timestamp = started_at.astimezone().strftime("%Y%m%d_%H%M%S")
    sample_name = sample_path.name
    project_root = APPLICATION_DIR / "codex_pro"
    output_root = APPLICATION_DIR / "output_dir"
    index = 0
    # 同一秒に複数回開始しても既存の解析結果を上書きしない名前を選びます。
    while True:
        suffix = "" if index == 0 else f"_{index}"
        project_dir = project_root / f"{sample_name}_{timestamp}_codex_pro{suffix}"
        output_dir = output_root / f"{sample_name}_{timestamp}_output_dir{suffix}"
        if not project_dir.exists() and not output_dir.exists():
            return project_dir, output_dir
        index += 1


# null項目を選択結果で補い、テンプレート出力へ直接保存するかも返します。
def resolve_llm_directory_settings(
    settings: LlmSettings,
    sample_path: Path,
    started_at: datetime,
) -> tuple[LlmSettings, bool]:
    project_missing = normalize_path_value(settings.codex_project_dir) is None
    output_missing = normalize_path_value(settings.analysis_output_dir) is None
    if not project_missing and not output_missing:
        return settings, False
    if ask_llm_directory_mode() == "input":
        return settings, False

    template_project, template_output = build_template_directories(sample_path, started_at)
    resolved = LlmSettings(
        codex_project_dir=str(template_project) if project_missing else settings.codex_project_dir,
        analysis_output_dir=str(template_output) if output_missing else settings.analysis_output_dir,
        language=settings.language,
        report_format=settings.report_format,
        model=settings.model,
        reasoning_effort=settings.reasoning_effort,
        timeouts=settings.timeouts,
    )
    print(f"Template Codex project directory: {resolved.codex_project_dir}")
    print(f"Template analysis output directory: {resolved.analysis_output_dir}")
    return resolved, output_missing


# null設定を補うため、空でない絶対パスが入力されるまで繰り返します。
def prompt_absolute_directory(label: str) -> Path:
    while True:
        raw_path = read_user_input(f"{label} absolute path: ")
        try:
            return resolve_absolute_directory(raw_path, label)
        except RuntimeError as error:
            print(f"Error: {error}")


# 設定値または入力値を絶対ディレクトリパスとして検証します。
def resolve_absolute_directory(raw_path: str | Path, label: str) -> Path:
    value = normalize_path_value(str(raw_path))
    if value is None:
        raise RuntimeError(f"{label} cannot be empty.")
    candidate = Path(os.path.expandvars(os.path.expanduser(value)))
    if not candidate.is_absolute():
        raise RuntimeError(f"{label} must be an absolute path: {candidate}")
    if is_reparse_point(candidate):
        raise RuntimeError(f"{label} cannot be a symbolic link or junction: {candidate}")
    return candidate.resolve(strict=False)


# Windowsのシンボリックリンクとジャンクションを削除対象から除外します。
def is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    if not path.exists():
        return False
    attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


# ---------------------------------------------------------------------------
# PJの削除対象と出力先を安全に確定する処理
# ---------------------------------------------------------------------------


# PJ内容削除を許可してはならない重要ディレクトリの集合を返します。
def protected_project_directories() -> set[Path]:
    home = Path.home().resolve()
    documents = (home / "Documents").resolve(strict=False)
    codex_home = Path(os.environ.get("CODEX_HOME", str(home / ".codex"))).resolve(strict=False)
    protected = {home, documents, APPLICATION_DIR.resolve(), codex_home}
    for drive in (home.drive, APPLICATION_DIR.drive):
        if drive:
            protected.add(Path(f"{drive}\\").resolve())
    return protected


# PJ候補がファイル、リンク、重要ディレクトリでないことを検証します。
def validate_project_directory(project_dir: Path) -> str | None:
    if not project_dir.is_absolute():
        return f"Project path must be absolute: {project_dir}"
    if project_dir.exists() and not project_dir.is_dir():
        return f"Project path is not a directory: {project_dir}"
    if is_reparse_point(project_dir):
        return f"Symbolic links and junctions are not allowed: {project_dir}"
    resolved = project_dir.resolve(strict=False)
    if resolved in protected_project_directories():
        return f"Protected directory cannot be used as an analysis project: {resolved}"
    return None


# yes/no以外を受理せず、破壊的操作の意思を明示的に確認します。
def ask_yes_no(prompt: str) -> bool:
    while True:
        answer = read_user_input(f"{prompt} [yes/no]: ").strip().lower()
        if answer in {"yes", "y"}:
            return True
        if answer in {"no", "n"}:
            return False
        print("Please enter yes or no.")


# 隠し項目を含むPJの全内容を列挙し、空かどうかを判定します。
def project_entries(project_dir: Path) -> list[Path]:
    if not project_dir.exists():
        return []
    return list(project_dir.iterdir())


# 確認済みPJの直下だけを削除し、PJディレクトリ自体は保持します。
def clear_project_contents(project_dir: Path) -> None:
    validation_error = validate_project_directory(project_dir)
    if validation_error is not None:
        raise RuntimeError(validation_error)
    root = project_dir.resolve(strict=True)
    for child in project_entries(root):
        # リンク先へ追従してPJ外を削除しないよう、リンク自体だけを取り除きます。
        if child.is_symlink() or is_reparse_point(child):
            if child.is_dir():
                child.rmdir()
            else:
                child.unlink()
            continue
        resolved_child = child.resolve(strict=True)
        # 削除直前にもPJ配下であることを確認し、パス差し替えへの防御を重ねます。
        if root not in resolved_child.parents:
            raise RuntimeError(f"Refusing to remove an entry outside the project: {child}")
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


# 旧版がPJ内へ配置したMCPだけを停止し、Windowsの実行中EXEロックを解除します。
def stop_legacy_project_mcp(project_dir: Path, timeout_seconds: float = 10.0) -> list[int]:
    legacy_executable = (
        project_dir / ".codex" / "mcp" / GHIDRA_MCP_EXECUTABLE_NAME
    ).resolve(strict=False)
    if not legacy_executable.is_file():
        return []

    # configを先に外し、Codex Appが停止した旧MCPを同じ設定から再起動しないようにします。
    legacy_config = project_dir / ".codex" / "config.toml"
    legacy_config.unlink(missing_ok=True)
    process_ids = windows_process_ids_for_executable(legacy_executable)
    for process_id in process_ids:
        try:
            completed = subprocess.run(
                ["taskkill", "/PID", str(process_id), "/T", "/F"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"Timed out while stopping the legacy project MCP process: PID {process_id}"
            ) from error
        # 親プロセス停止で子も消えている場合のnot foundは、後続の再確認で判定します。
        if completed.returncode not in (0, 128, 255):
            detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
            raise RuntimeError(
                f"Failed to stop the legacy project MCP process PID {process_id}: {detail}"
            )

    deadline = time.monotonic() + timeout_seconds
    while windows_process_ids_for_executable(legacy_executable):
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "The legacy project MCP process is still using this file. "
                f"Close the Codex project and retry: {legacy_executable}"
            )
        time.sleep(0.1)
    return process_ids


# Windowsの実行ファイルパスを照合し、対象EXEを実行中のPIDだけを列挙します。
def windows_process_ids_for_executable(executable: Path) -> list[int]:
    if os.name != "nt":
        return []

    import ctypes
    from ctypes import wintypes

    process_query_limited_information = 0x1000
    snapshot_process = 0x00000002
    invalid_handle_value = ctypes.c_void_p(-1).value

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(snapshot_process, 0)
    if snapshot == invalid_handle_value:
        raise RuntimeError("Failed to enumerate Windows processes for legacy MCP cleanup.")

    target = os.path.normcase(str(executable.resolve(strict=False)))
    matched: list[int] = []
    entry = ProcessEntry32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        has_entry = bool(kernel32.Process32FirstW(snapshot, ctypes.byref(entry)))
        while has_entry:
            process_id = int(entry.th32ProcessID)
            handle = kernel32.OpenProcess(
                process_query_limited_information,
                False,
                process_id,
            )
            if handle:
                try:
                    size = wintypes.DWORD(32768)
                    buffer = ctypes.create_unicode_buffer(size.value)
                    if kernel32.QueryFullProcessImageNameW(
                        handle,
                        0,
                        buffer,
                        ctypes.byref(size),
                    ):
                        candidate = os.path.normcase(
                            str(Path(buffer.value).resolve(strict=False))
                        )
                        if candidate == target:
                            matched.append(process_id)
                finally:
                    kernel32.CloseHandle(handle)
            has_entry = bool(kernel32.Process32NextW(snapshot, ctypes.byref(entry)))
    finally:
        kernel32.CloseHandle(snapshot)
    return matched


# 空でないPJを削除するか確認し、拒否時は別パスの入力へ戻します。
def handle_non_empty_project(project_dir: Path) -> Path | None:
    if not project_entries(project_dir):
        return project_dir
    print(f"Project directory is not empty: {project_dir}")
    if ask_yes_no("Delete only the contents of this project directory?"):
        clear_project_contents(project_dir)
        return project_dir
    return None


# 設定またはユーザー入力から、安全で空の解析PJを確定します。
def resolve_project_directory(raw_path: str | None) -> Path:
    candidate_raw = raw_path
    while True:
        try:
            project_dir = (
                resolve_absolute_directory(candidate_raw, "Codex project directory")
                if normalize_path_value(candidate_raw) is not None
                else prompt_absolute_directory("Codex project directory")
            )
        except RuntimeError as error:
            print(f"Error: {error}")
            candidate_raw = None
            continue
        validation_error = validate_project_directory(project_dir)
        if validation_error is not None:
            print(f"Error: {validation_error}")
            candidate_raw = None
            continue
        project_dir.mkdir(parents=True, exist_ok=True)
        accepted = handle_non_empty_project(project_dir)
        if accepted is not None:
            return accepted
        candidate_raw = None


# 結果保存先を絶対パスとして確定し、PJとは別の場所へ作成します。
def resolve_output_directory(raw_path: str | None, project_dir: Path | None = None) -> Path:
    candidate_raw = raw_path
    while True:
        try:
            output_dir = (
                resolve_absolute_directory(candidate_raw, "Analysis output directory")
                if normalize_path_value(candidate_raw) is not None
                else prompt_absolute_directory("Analysis output directory")
            )
            if output_dir.exists() and not output_dir.is_dir():
                raise RuntimeError(f"Analysis output path is not a directory: {output_dir}")
            if project_dir is not None:
                resolved_project = project_dir.resolve(strict=False)
                if output_dir == resolved_project or resolved_project in output_dir.parents:
                    raise RuntimeError("Analysis output directory must not be the project or a child of it.")
            output_dir.mkdir(parents=True, exist_ok=True)
            return output_dir
        except RuntimeError as error:
            print(f"Error: {error}")
            candidate_raw = None


# 削除やディレクトリ作成を行わず、最終確認に表示するLLM解析先を確定します。
def prepare_llm_run(
    settings: LlmSettings,
    sample_path: Path,
    started_at: datetime | None = None,
) -> LlmRunPreparation:
    resolved_started_at = started_at or datetime.now(timezone.utc)
    resolved_settings, template_output_selected = resolve_llm_directory_settings(
        settings,
        sample_path,
        resolved_started_at,
    )
    project_dir = (
        resolve_absolute_directory(resolved_settings.codex_project_dir, "Codex project directory")
        if resolved_settings.codex_project_dir is not None
        else prompt_absolute_directory("Codex project directory")
    )
    validation_error = validate_project_directory(project_dir)
    if validation_error is not None:
        raise RuntimeError(validation_error)

    output_dir = (
        resolve_absolute_directory(resolved_settings.analysis_output_dir, "Analysis output directory")
        if resolved_settings.analysis_output_dir is not None
        else prompt_absolute_directory("Analysis output directory")
    )
    if output_dir.exists() and not output_dir.is_dir():
        raise RuntimeError(f"Analysis output path is not a directory: {output_dir}")
    if output_dir == project_dir or project_dir in output_dir.parents:
        raise RuntimeError("Analysis output directory must not be the project or a child of it.")

    return LlmRunPreparation(
        settings=resolved_settings,
        project_dir=project_dir,
        output_dir=output_dir,
        project_entry_count=len(project_entries(project_dir)),
        template_output_selected=template_output_selected,
        started_at=resolved_started_at,
    )


# 最終確認で許可された場合だけPJ内容を削除し、解析用ディレクトリを準備します。
def activate_prepared_project(preparation: LlmRunPreparation, allow_clear: bool) -> Path:
    project_dir = preparation.project_dir
    project_dir.mkdir(parents=True, exist_ok=True)
    if project_entries(project_dir):
        if not allow_clear:
            raise RuntimeError(
                "Codex project directory is not empty and deletion was not confirmed: "
                f"{project_dir}"
            )
        stop_legacy_project_mcp(project_dir)
        clear_project_contents(project_dir)
    return project_dir


# ---------------------------------------------------------------------------
# 検体と動的ログをPJへ完全性検証付きで配置する処理
# ---------------------------------------------------------------------------


# 検体、ログ、設定を分離したPJディレクトリ構造を作成します。
def create_project_layout(project_dir: Path) -> dict[str, Path]:
    paths = {
        "codex": project_dir / ".codex",
        "hooks": project_dir / ".codex" / "hooks",
        "rules": project_dir / ".codex" / "rules",
        "mcp": project_dir / ".codex" / "mcp",
        "sample": project_dir / "inputs" / "sample",
        "logs": project_dir / "inputs" / "dynamic_logs",
        "reports": project_dir / "reports",
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


# ファイルの完全性確認に使うSHA-256をストリーミング計算します。
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# 一時ファイルへコピーし、前後のハッシュ一致後だけ所定名へ確定します。
def copy_and_verify_artifact(source: Path, destination: Path) -> str:
    if not source.is_file():
        raise RuntimeError(f"Required analysis input was not found: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    if temporary.exists():
        temporary.unlink()
    # コピー元と一時コピーのハッシュが一致するまで正式ファイル名へ切り替えません。
    source_hash = sha256_file(source)
    shutil.copy2(source, temporary)
    copied_hash = sha256_file(temporary)
    if copied_hash != source_hash:
        temporary.unlink(missing_ok=True)
        raise RuntimeError(f"SHA-256 mismatch while copying: {source}")
    temporary.replace(destination)
    return source_hash


# 検体と動的ログだけをPJへコピーし、確定パスとハッシュを返します。
def stage_analysis_inputs(
    inputs: LlmAnalysisInputs,
    layout: dict[str, Path],
) -> tuple[LlmAnalysisInputs, dict[str, str | None]]:
    sample_target = layout["sample"] / inputs.malware_path.name
    hashes = {"malware": copy_and_verify_artifact(inputs.malware_path, sample_target)}
    staged, evidence_hashes = stage_dynamic_inputs(inputs, layout)
    from dataclasses import replace
    return replace(staged, malware_path=sample_target), dict(hashes, **evidence_hashes)


# 同じ解析の成果物一覧に登録されたファイルだけをCodexへ配置する。
def stage_dynamic_inputs(inputs, layout):
    from dataclasses import replace
    from dynamic_evidence import sha256
    root = inputs.dynamic_evidence_path.parent
    manifest = json.loads(inputs.dynamic_evidence_path.read_text(encoding='utf-8'))
    hashes = {}
    for entry in manifest['artifacts']:
        name = entry['name']
        if Path(name).name != name or any(c in name for c in '/\\:'):
            raise RuntimeError('Invalid dynamic evidence filename')
        source = root / name
        if source.stat().st_size != entry['size'] or sha256(source) != entry['sha256']:
            raise RuntimeError('Dynamic evidence changed before Codex staging: ' + name)
        hashes[name] = copy_and_verify_artifact(source, layout['logs'] / name)
    target = layout['logs'] / 'dynamic_status.json'
    hashes['dynamic_status'] = copy_and_verify_artifact(inputs.dynamic_evidence_path, target)
    sysmon = layout['logs'] / 'sysmon.evtx'
    return replace(inputs, dynamic_evidence_path=target, dynamic_status_path=target,
                   sysmon_evtx_path=sysmon if sysmon.exists() else None), hashes


# ---------------------------------------------------------------------------
# PJローカルのHook・rules・Ghidra MCP設定を生成する処理
# ---------------------------------------------------------------------------


# ソース実行ではPythonスクリプト、exe実行ではPJローカルのguard専用exeを選択します。
def resolve_guard_command_prefix(hook_script: Path) -> list[str]:
    if getattr(sys, "frozen", False):
        guard_executable = hook_script.with_name(GUARD_EXECUTABLE_NAME)
        if not guard_executable.is_file():
            raise RuntimeError(f"Packaged malware guard executable was not found: {guard_executable}")
        return [str(guard_executable.resolve())]

    python_path = Path(sys.executable)
    if not python_path.is_file():
        raise RuntimeError(f"Python executable used by malware guard was not found: {python_path}")
    if not hook_script.is_file():
        raise RuntimeError(f"Malware guard script was not found: {hook_script}")
    return [str(python_path.resolve()), str(hook_script.resolve())]


# 正本のHookスクリプトとrulesを解析PJへコピーします。
def copy_security_templates(
    layout: dict[str, Path],
    sample_path: Path,
    guard_settings: dict[str, Any] | None = None,
) -> None:
    hook_source = HOOK_TEMPLATE_DIR / "hooks" / "malware_guard.py"
    rules_source = HOOK_TEMPLATE_DIR / "rules" / "malware_guard.rules"
    if not hook_source.is_file() or not rules_source.is_file():
        raise RuntimeError(f"Security templates are incomplete: {HOOK_TEMPLATE_DIR}")
    shutil.copy2(hook_source, layout["hooks"] / "malware_guard.py")
    if getattr(sys, "frozen", False):
        guard_executable = APPLICATION_DIR / GUARD_EXECUTABLE_NAME
        if not guard_executable.is_file():
            raise RuntimeError(f"Packaged malware guard executable was not found: {guard_executable}")
        shutil.copy2(guard_executable, layout["hooks"] / GUARD_EXECUTABLE_NAME)
    rules_text = rules_source.read_text(encoding="utf-8")
    source_guard = guard_settings if isinstance(guard_settings, dict) else CODEX_MALWARE_GUARD
    # 設定モードに応じて、検体起動を即時拒否するかユーザー確認へ回します。
    decision = "prompt" if str(source_guard.get("mode", "block")).lower() == "require_approval" else "forbidden"
    direct_rule = (
        "\n# 保護対象そのものの直接起動を、設定された方式で拒否または確認します。\n"
        "prefix_rule(\n"
        f"    pattern = [[{json.dumps(sample_path.name)}, {json.dumps(str(sample_path.resolve()))}]],\n"
        f"    decision = {json.dumps(decision)},\n"
        '    justification = "Protected analysis samples must not be executed.",\n'
        ")\n"
    )
    (layout["rules"] / "malware_guard.rules").write_text(
        rules_text.replace("test.exe", sample_path.name) + direct_rule,
        encoding="utf-8",
    )


# コピー後の検体パスと厳密なGhidra許可条件をPJ専用設定へ保存します。
def render_guard_settings(
    layout: dict[str, Path],
    sample_path: Path,
    guard_settings: dict[str, Any] | None = None,
    allowed_tools: tuple[str, ...] | None = None,
) -> Path:
    source_guard = guard_settings if isinstance(guard_settings, dict) else CODEX_MALWARE_GUARD
    settings = {
        "codex_malware_guard": {
            "enabled": bool(source_guard.get("enabled", True)),
            "mode": str(source_guard.get("mode", "block")),
            "fail_closed": bool(source_guard.get("fail_closed", True)),
            "protected_paths": [str(sample_path.resolve())],
            "extra_protected_paths": [],
            "dangerous_tokens": source_guard.get("dangerous_tokens", []),
            "allowed_mcp_server": GHIDRA_SERVER_NAME,
            "allowed_mcp_tools": list(allowed_tools or REQUIRED_GHIDRA_TOOLS),
        }
    }
    settings_path = layout["codex"] / "guard_settings.json"
    settings_path.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
    return settings_path


# PJの絶対パスと実行IDを使い、SessionStartと実行前検査Hookを生成します。
def render_project_hooks(
    layout: dict[str, Path],
    settings_path: Path,
) -> HookVerificationContext:
    hook_script = layout["hooks"] / "malware_guard.py"
    marker_path = layout["codex"] / "hook_active.marker"
    diagnostics_path = layout["codex"] / "hook_diagnostics.jsonl"
    run_context_path = layout["codex"] / "hook_run.json"
    run_id = uuid.uuid4().hex
    command_prefix = resolve_guard_command_prefix(hook_script)
    guard_command = subprocess.list2cmdline(
        [*command_prefix, "--settings", str(settings_path)]
    )
    marker_command = subprocess.list2cmdline(
        [
            *command_prefix,
            "--mark-session",
            "--run-context",
            str(run_context_path),
        ]
    )
    hooks_template_path = HOOK_TEMPLATE_DIR / "hooks.json"
    if not hooks_template_path.is_file():
        raise RuntimeError(f"Hook template was not found: {hooks_template_path}")
    hooks_text = hooks_template_path.read_text(encoding="utf-8")
    # 正本テンプレートへ今回のPJ専用コマンドを埋め込み、他PJの設定と分離します。
    hooks = json.loads(
        hooks_text.replace('"__GUARD_COMMAND__"', json.dumps(guard_command))
        .replace('"__SESSION_COMMAND__"', json.dumps(marker_command))
    )
    hooks_path = layout["codex"] / "hooks.json"
    hooks_path.write_text(json.dumps(hooks, ensure_ascii=False, indent=2), encoding="utf-8")
    context = HookVerificationContext(marker_path, diagnostics_path, run_id, run_context_path)
    write_hook_run_context(context)
    return context


# TOMLリテラル内でWindowsパスを安全に扱えるよう引用します。
def toml_string(value: str | Path) -> str:
    return json.dumps(str(value), ensure_ascii=False)


# Ghidra MCPをrequiredにし、利用可能ツールを4種類へ限定します。
def render_project_codex_config(
    layout: dict[str, Path],
    ghidra_headless: Path,
    sample_path: Path,
    mcp_startup_timeout_seconds: int = 120,
    mcp_tool_timeout_seconds: int = 600,
) -> Path:
    if getattr(sys, "frozen", False):
        # 常駐MCPを使い捨てPJ内へ置かず、次回のPJ削除時にWindowsロックと衝突させません。
        mcp_command = APPLICATION_DIR / GHIDRA_MCP_EXECUTABLE_NAME
        if not mcp_command.is_file():
            raise RuntimeError(f"Packaged Ghidra MCP executable was not found: {mcp_command}")
        mcp_args: list[Path] = []
    else:
        if not GHIDRA_SERVER_PATH.is_file():
            raise RuntimeError(f"Ghidra MCP server was not found: {GHIDRA_SERVER_PATH}")
        mcp_command = Path(sys.executable)
        mcp_args = [GHIDRA_SERVER_PATH]
    ghidra_projects = Path(tempfile.gettempdir()) / "r_AKanaly" / "ghidra_projects"
    tools = ", ".join(toml_string(tool) for tool in REQUIRED_GHIDRA_TOOLS)
    # MCP側にも保護対象を渡し、Hookだけでなくサーバー側でも別検体を拒否させます。
    lines = [
        'web_search = "disabled"',
        "",
        f"[mcp_servers.{GHIDRA_SERVER_NAME}]",
        f"command = {toml_string(mcp_command)}",
        f"args = [{', '.join(toml_string(argument) for argument in mcp_args)}]",
        "required = true",
        f"enabled_tools = [{tools}]",
        'default_tools_approval_mode = "approve"',
        f"startup_timeout_sec = {mcp_startup_timeout_seconds}",
        f"tool_timeout_sec = {mcp_tool_timeout_seconds}",
        "",
        f"[mcp_servers.{GHIDRA_SERVER_NAME}.env]",
        f"GHIDRA_HEADLESS = {toml_string(ghidra_headless)}",
        f"GHIDRA_PROJECT_DIR = {toml_string(ghidra_projects)}",
        'GHIDRA_PROJECT_NAME = "r_AKanaly"',
        f'GHIDRA_TIMEOUT_SEC = "{mcp_tool_timeout_seconds}"',
        f"R_AKANALY_PROTECTED_SAMPLE = {toml_string(sample_path.resolve())}",
    ]
    for tool in REQUIRED_GHIDRA_TOOLS:
        lines.extend(
            ["", f"[mcp_servers.{GHIDRA_SERVER_NAME}.tools.{tool}]", 'approval_mode = "approve"']
        )
    config_path = layout["codex"] / "config.toml"
    config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return config_path


# ---------------------------------------------------------------------------
# Guest用MCPの起動情報を生成し、Host側Ghidraは設定しない。
def render_vm_codex_config(layout, session, settings):
    server = APPLICATION_DIR / 'VMWARE_GUEST_CONTROL_PACKAGE/host/analysis_mcp_server.py'
    prefix = ['--guest-mcp'] if getattr(sys, 'frozen', False) else ['-X', 'utf8', str(server)]
    args = prefix + ['--key', str(session.state / 'pipe.key'), '--pipe', session.pipe, '--session', str(session.binding)]
    text = '\n'.join([
        'web_search = "disabled"', '[mcp_servers.' + GHIDRA_SERVER_NAME + ']',
        'command = ' + toml_string(sys.executable),
        'args = ' + json.dumps(args), 'required = true',
        'enabled_tools = ["guest_analysis_request"]', 'default_tools_approval_mode = "approve"',
        'startup_timeout_sec = ' + str(settings.timeouts.mcp_startup_seconds),
        'tool_timeout_sec = ' + str(settings.timeouts.mcp_tool_seconds),
    ])
    (layout['codex'] / 'config.toml').write_text(text + '\n', encoding='utf-8')


# SDKのツール履歴とブリッジの実応答を照合し、稼働確認だけを解析成功にしない。
def verify_vm_tool_calls(items, session):
    import sqlite3
    from contextlib import closing
    evidence = []
    with closing(sqlite3.connect(session.state / 'requests.sqlite3')) as db:
        for wrapped in items:
            item = unwrap_thread_item(wrapped)
            if getattr(item, 'server', '') != GHIDRA_SERVER_NAME or getattr(item, 'tool', '') != 'guest_analysis_request':
                continue
            status = getattr(item, 'status', '')
            if str(getattr(status, 'value', status)).lower() != 'completed' or getattr(item, 'error', None):
                continue
            arguments = normalize_item_arguments(getattr(item, 'arguments', {}))
            request = arguments.get('request', {})
            if request.get('analysis_id') != session.analysis_id:
                continue
            try:
                request_id = uuid.UUID(request.get('request_id', '')).hex
            except (ValueError, TypeError):
                continue
            row = db.execute('SELECT request,response FROM requests WHERE id=?', (request_id,)).fetchone()
            if row and row[1]:
                saved_request = json.loads(row[0])
                if saved_request.get('analysis_id') != session.analysis_id or saved_request.get('action') != request.get('action'):
                    continue
                response = json.loads(row[1])
                completed = response.get('ok', False)
                if request.get('action') == 'run_tool':
                    completed = completed and response.get('result', {}).get('exit_code') == 0
                evidence.append({'request_id': request_id, 'action': request.get('action'),
                                 'ok': completed, 'error': response.get('error')})
    if not any(item['ok'] and item['action'] in ('functions', 'decompile', 'strings', 'imports', 'symbols', 'references', 'callers', 'callees', 'disassemble', 'run_tool') for item in evidence):
        raise RuntimeError('Codex did not obtain static evidence through the Guest MCP')
    return evidence


# Ghidra実行環境とWindows側の検体実行拒否を検証する処理
# ---------------------------------------------------------------------------


# 環境変数、Ghidra標準配置、ユーザー入力の順でHeadless実行ファイルを解決します。
def resolve_ghidra_headless() -> Path:
    candidates: list[Path] = []
    explicit = os.environ.get("GHIDRA_HEADLESS")
    if explicit:
        candidates.append(Path(os.path.expandvars(explicit)).expanduser())
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        candidates.append(Path(os.path.expandvars(ghidra_home)).expanduser() / "support" / "analyzeHeadless.bat")
    documents = Path.home() / "Documents"
    if documents.exists():
        # バージョン付き展開フォルダと、その一段下にあるGhidra本体の両方を探索します。
        candidates.extend(documents.glob("ghidra*/support/analyzeHeadless.bat"))
        candidates.extend(documents.glob("*/ghidra*/support/analyzeHeadless.bat"))
    for candidate in candidates:
        if candidate.is_file() and candidate.name.lower() == "analyzeheadless.bat":
            return candidate.resolve()

    while True:
        raw_path = read_user_input(
            "Ghidra analyzeHeadless.bat absolute path: "
        ).strip().strip('"')
        candidate = Path(os.path.expandvars(os.path.expanduser(raw_path)))
        if candidate.is_absolute() and candidate.is_file() and candidate.name.lower() == "analyzeheadless.bat":
            return candidate.resolve()
        print("Error: enter an absolute path to an existing analyzeHeadless.bat.")


# 現在ユーザーのSIDを取得し、ローカライズされたユーザー名依存を避けます。
def current_windows_sid() -> str:
    result = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Failed to resolve the current Windows SID.")
    row = next(csv.reader([result.stdout.strip()]), [])
    if len(row) < 2 or not row[1].startswith("S-"):
        raise RuntimeError("Failed to parse the current Windows SID.")
    return row[1]


# PJ内検体へNTFS実行拒否ACEを追加し、読取権限は変更しません。
def apply_windows_execute_deny(sample_path: Path) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("NTFS execute-deny ACL is required but this host is not Windows.")
    sid = current_windows_sid()
    result = subprocess.run(
        ["icacls", str(sample_path), "/deny", f"*{sid}:(X)"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "icacls failed.")
    return {"applied": True, "sid": sid, "output": result.stdout.strip()}


# HookをCLIテストし、危険4パターン拒否と正規MCP4種類許可を確認します。
def run_guard_self_tests(
    hook_script: Path,
    settings_path: Path,
    sample_path: Path,
    allowed_tools: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    cases: list[tuple[str, dict[str, Any], bool]] = [
        ("direct", {"tool_name": "shell_command", "tool_input": {"command": str(sample_path)}}, False),
        ("cmd", {"tool_name": "shell_command", "tool_input": {"command": f'cmd /c "{sample_path}"'}}, False),
        ("powershell", {"tool_name": "shell_command", "tool_input": {"command": f'powershell Start-Process "{sample_path}"'}}, False),
        ("fake_ghidra", {"tool_name": "shell_command", "tool_input": {"command": f'ghidra cmd /c "{sample_path}"'}}, False),
    ]
    # シェル操作とは反対に、厳密なMCP4ツールだけは許可されることを同時に確認します。
    for tool in allowed_tools or REQUIRED_GHIDRA_TOOLS:
        cases.append(
            (
                tool,
                {"tool_name": f"mcp__{GHIDRA_SERVER_NAME}__{tool}", "tool_input": {"binary_path": str(sample_path)}},
                True,
            )
        )

    results: dict[str, Any] = {}
    failures: list[str] = []
    command_prefix = resolve_guard_command_prefix(hook_script)
    for name, payload, should_allow in cases:
        result = subprocess.run(
            [*command_prefix, "--settings", str(settings_path), "--payload-json", json.dumps(payload)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        allowed = result.returncode == 0
        passed = allowed == should_allow
        results[name] = {"passed": passed, "allowed": allowed, "message": (result.stdout or result.stderr).strip()}
        if not passed:
            failures.append(name)
    if failures:
        raise RuntimeError(f"Malware guard self-tests failed: {', '.join(failures)}")
    return results


# ---------------------------------------------------------------------------
# Codex SDKの起動条件、MCP履歴、解析ターンを制御する処理
# ---------------------------------------------------------------------------


# Codex AppでPJ trustとHook承認を済ませるまで解析開始を待機します。
def wait_for_hook_trust(project_dir: Path) -> None:
    print(f"Open and trust this project in Codex App, then approve its hooks: {project_dir}")
    while not ask_yes_no("Have you trusted the project and approved the hooks?"):
        print("Analysis will not start until project hooks are approved.")


# 今回の実行IDに対応するHook診断イベントだけを読み取ります。
def read_hook_diagnostics(context: HookVerificationContext) -> list[dict[str, Any]]:
    if not context.diagnostics_path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line in context.diagnostics_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("run_id") == context.run_id:
            records.append(record)
    return records


# 固定Hookコマンドが今回の実行IDと出力先を取得するJSONを更新します。
def write_hook_run_context(context: HookVerificationContext) -> None:
    if context.run_context_path is None:
        return
    context.run_context_path.write_text(
        json.dumps(
            {
                "run_id": context.run_id,
                "marker_path": str(context.marker_path),
                "diagnostics_path": str(context.diagnostics_path),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


# マーカー本文と更新時刻が今回のSessionStart実行に一致するか判定します。
def hook_marker_matches(context: HookVerificationContext, started_at: float) -> bool:
    if not context.marker_path.is_file():
        return False
    try:
        payload = json.loads(context.marker_path.read_text(encoding="utf-8"))
        return (
            isinstance(payload, dict)
            and payload.get("active") is True
            and payload.get("run_id") == context.run_id
            and context.marker_path.stat().st_mtime >= started_at - 1.0
        )
    except (OSError, json.JSONDecodeError):
        return False


# SessionStart Hookの単体起動とマーカー書き込み可否をSDK起動前に検査します。
def run_session_hook_preflight(
    hook_script: Path,
    context: HookVerificationContext,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    try:
        command_prefix = resolve_guard_command_prefix(hook_script)
    except RuntimeError as error:
        raise HookVerificationError(
            "hook_runtime_not_found",
            str(error),
        ) from error

    probe_id = f"preflight-{context.run_id}"
    probe_marker = context.marker_path.with_name("hook_preflight.marker")
    probe_diagnostics = context.diagnostics_path.with_name("hook_preflight.jsonl")
    probe_marker.unlink(missing_ok=True)
    probe_diagnostics.unlink(missing_ok=True)
    command = [
        *command_prefix,
        "--mark-session",
        "--marker",
        str(probe_marker),
        "--run-id",
        probe_id,
        "--diagnostics",
        str(probe_diagnostics),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise HookVerificationError(
            "hook_command_timeout",
            f"SessionStart hook preflight timed out after {timeout_seconds:g} seconds.",
        ) from error

    result = {
        "passed": completed.returncode == 0 and probe_marker.is_file(),
        "exit_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }
    probe_marker.unlink(missing_ok=True)
    probe_diagnostics.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise HookVerificationError(
            "hook_command_failed",
            f"SessionStart hook preflight exited with code {completed.returncode}: "
            f"{completed.stderr.strip() or completed.stdout.strip() or 'no output'}",
            result,
        )
    if not result["passed"]:
        raise HookVerificationError(
            "marker_write_failed",
            f"SessionStart hook completed but could not write a marker under {context.marker_path.parent}.",
            result,
        )
    return result


# SessionStart Hookのマーカーを待ち、観測情報から失敗原因を分類します。
def verify_hook_marker(
    context: HookVerificationContext,
    started_at: float,
    timeout_seconds: float = 15.0,
    poll_interval_seconds: float = 0.25,
    runtime_stderr: list[str] | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if hook_marker_matches(context, started_at):
            return {
                "verified": True,
                "run_id": context.run_id,
                "events": read_hook_diagnostics(context),
            }
        if time.monotonic() >= deadline:
            break
        time.sleep(poll_interval_seconds)

    records = read_hook_diagnostics(context)
    events = {str(record.get("event")) for record in records}
    diagnostics = {
        "verified": False,
        "run_id": context.run_id,
        "events": records,
        "runtime_stderr": runtime_stderr or [],
    }
    if "marker_write_failed" in events:
        raise HookVerificationError(
            "marker_write_failed",
            "SessionStart hook ran, but writing the marker failed. Check the marker directory permissions.",
            diagnostics,
        )
    if "session_hook_started" in events:
        raise HookVerificationError(
            "hook_command_incomplete",
            "SessionStart hook started but did not complete marker generation. The hook may have failed or timed out.",
            diagnostics,
        )
    if context.marker_path.exists():
        raise HookVerificationError(
            "stale_marker",
            "A SessionStart marker exists, but it belongs to another run or predates this thread.",
            diagnostics,
        )
    stderr_text = "\n".join(runtime_stderr or []).lower()
    if "untrusted" in stderr_text or "not trusted" in stderr_text:
        code = "project_not_trusted"
        message = "Codex reported that the project is not trusted; SessionStart was not run."
    elif "approval" in stderr_text and "hook" in stderr_text:
        code = "hook_not_approved"
        message = "Codex reported that the hook is not approved or needs reapproval after its definition changed."
    elif "timed out" in stderr_text and "hook" in stderr_text:
        code = "hook_command_timeout"
        message = "Codex reported that the SessionStart hook command timed out."
    elif any(token in stderr_text for token in ("hook command failed", "hook exited", "exit code")):
        code = "hook_command_failed"
        message = "Codex reported that the SessionStart hook command exited abnormally."
    else:
        code = "session_start_not_observed"
        message = (
            "SessionStart was not observed after the initialization turn. No hook process started. "
            "Possible causes are missing project trust, missing or stale hook approval, or a runtime "
            "that did not dispatch SessionStart; inspect codex_runtime_stderr and the Codex Hooks UI."
        )
    raise HookVerificationError(code, message, diagnostics)


# SDKが起動するCodex実体パスを開発者overrideまたは同梱パッケージから解決します。
def resolve_codex_runtime_path(developer: DeveloperVariableSettings) -> tuple[Path, str]:
    if developer.dev_var and developer.codex_app_full_path:
        path = Path(developer.codex_app_full_path).expanduser().resolve(strict=False)
        if not path.is_file():
            raise RuntimeError(f"developer_variables.codex_app_full_path was not found: {path}")
        return path, "developer_override"
    try:
        from codex_cli_bin import bundled_codex_path
    except ImportError as error:
        raise RuntimeError("openai-codex-cli-bin bundled runtime is not installed.") from error
    path = Path(bundled_codex_path()).resolve(strict=False)
    if not path.is_file():
        raise RuntimeError(f"Bundled Codex runtime was not found: {path}")
    return path, "sdk_bundled"


# 外部CLIの診断出力がmetadataを肥大化させないよう上限内へ切り詰めます。
def truncate_diagnostic(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


# hooks行の有効値を追加列や空白の揺れに依存せず抽出します。
def parse_hooks_feature(stdout: str) -> tuple[str, str]:
    for raw_line in stdout.splitlines():
        columns = raw_line.split()
        if not columns or columns[0].lower() != "hooks":
            continue
        boolean_values = [
            column.lower()
            for column in columns[1:]
            if column.lower() in {"true", "false"}
        ]
        if not boolean_values:
            return "output_unrecognized", "The hooks row did not contain a true/false value."
        if boolean_values[-1] == "true":
            return "supported", "The runtime reported hooks=true."
        return "disabled", "The runtime reported hooks=false."
    return "output_unrecognized", "The features output did not contain a hooks row."


# featuresサブコマンド自体を持たない旧ランタイムの代表的なエラーを判別します。
def feature_command_is_unsupported(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(
        token in lowered
        for token in (
            "unrecognized subcommand",
            "unknown subcommand",
            "unexpected argument 'features'",
            'unexpected argument "features"',
        )
    )


# JSON引用を使い、モデル設定をCodex CLIの--config形式へ安全に変換します。
def build_model_config_overrides(
    model: str | None,
    reasoning_effort: str | None,
) -> tuple[str, ...]:
    overrides: list[str] = []
    if model:
        overrides.append(f"model={json.dumps(model)}")
    if reasoning_effort:
        overrides.append(
            f"model_reasoning_effort={json.dumps(reasoning_effort)}"
        )
    return tuple(overrides)


# Codexランタイム版とSessionStartに必要なhooks機能を起動前に確認します。
def inspect_codex_runtime(
    developer: DeveloperVariableSettings,
    timeout_seconds: float = 10.0,
    working_directory: Path | None = None,
    model: str | None = None,
    reasoning_effort: str | None = None,
) -> CodexRuntimeInfo:
    path, source = resolve_codex_runtime_path(developer)
    probe_cwd = (working_directory or APPLICATION_DIR).resolve(strict=False)
    version_command = [str(path), "--version"]
    features_command = [str(path)]
    for override in build_model_config_overrides(model, reasoning_effort):
        features_command.extend(["--config", override])
    features_command.extend(["features", "list"])
    try:
        version_result = subprocess.run(
            version_command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            cwd=probe_cwd,
            env=build_codex_environment(),
        )
    except subprocess.TimeoutExpired:
        return CodexRuntimeInfo(
            path,
            "unknown",
            source,
            "probe_failed",
            tuple(version_command),
            None,
            "",
            f"Version probe timed out after {timeout_seconds:g} seconds.",
            probe_cwd,
            "The Codex runtime version probe timed out.",
        )

    version = version_result.stdout.strip().splitlines()[0] if version_result.stdout.strip() else "unknown"
    if version_result.returncode != 0:
        return CodexRuntimeInfo(
            path,
            version,
            source,
            "probe_failed",
            tuple(version_command),
            version_result.returncode,
            truncate_diagnostic(version_result.stdout),
            truncate_diagnostic(version_result.stderr),
            probe_cwd,
            "The Codex runtime version command failed.",
        )

    try:
        features_result = subprocess.run(
            features_command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            cwd=probe_cwd,
            env=build_codex_environment(),
        )
    except subprocess.TimeoutExpired:
        return CodexRuntimeInfo(
            path,
            version,
            source,
            "probe_failed",
            tuple(features_command),
            None,
            "",
            f"Feature probe timed out after {timeout_seconds:g} seconds.",
            probe_cwd,
            "The Codex features probe timed out.",
        )

    stdout = truncate_diagnostic(features_result.stdout)
    stderr = truncate_diagnostic(features_result.stderr)
    if features_result.returncode != 0:
        status = "unsupported" if feature_command_is_unsupported(stderr) else "probe_failed"
        reason = (
            "The runtime does not recognize the features command."
            if status == "unsupported"
            else "The Codex features probe exited with a non-zero status."
        )
    else:
        status, reason = parse_hooks_feature(features_result.stdout)
    return CodexRuntimeInfo(
        path,
        version,
        source,
        status,
        tuple(features_command),
        features_result.returncode,
        stdout,
        stderr,
        probe_cwd,
        reason,
    )


# 通常解析と診断CLIで同一の作業ディレクトリ・環境条件を使ってprobeします。
def inspect_application_codex_runtime(
    developer: DeveloperVariableSettings,
    timeout_seconds: float,
    model: str | None = None,
    reasoning_effort: str | None = None,
) -> CodexRuntimeInfo:
    return inspect_codex_runtime(
        developer,
        timeout_seconds=timeout_seconds,
        working_directory=APPLICATION_DIR,
        model=model,
        reasoning_effort=reasoning_effort,
    )


# SDKランタイムのstderrからHookとrulesに関係する行だけを診断用に抽出します。
def get_codex_diagnostic_stderr(codex: Any) -> list[str]:
    client = getattr(codex, "_client", None)
    tail = getattr(client, "_stderr_tail", None)
    if not callable(tail):
        return []
    try:
        lines = tail(100)
    except Exception:
        return []
    keywords = ("hook", "sessionstart", "rule", "malware_guard")
    return [str(line)[:1000] for line in lines if any(key in str(line).lower() for key in keywords)][-30:]


# initialize応答からSDKとランタイムが申告した情報をmetadata向けに取り出します。
def get_codex_initialize_metadata(codex: Any) -> dict[str, Any]:
    metadata = getattr(codex, "metadata", None)
    if metadata is None:
        return {}
    dumper = getattr(metadata, "model_dump", None)
    if callable(dumper):
        try:
            value = dumper(mode="json", by_alias=True)
            return value if isinstance(value, dict) else {"value": str(value)}
        except Exception:
            pass
    return {"value": str(metadata)}


# ランタイムprobe結果をPathを含めてJSON保存可能な辞書へ変換します。
def runtime_info_metadata(info: CodexRuntimeInfo) -> dict[str, Any]:
    return {
        "path": str(info.path),
        "version": info.version,
        "source": info.source,
        "hooks_status": info.hooks_status,
        "check_command": list(info.check_command),
        "return_code": info.return_code,
        "stdout": info.stdout,
        "stderr": info.stderr,
        "working_directory": str(info.working_directory),
        "reason": info.reason,
    }


# 判定不能と実際の非対応を混同せず、probe診断を利用者へ返します。
def format_runtime_compatibility_error(info: CodexRuntimeInfo) -> str:
    detail = info.stderr.strip() or info.stdout.strip() or "no command output"
    return (
        "Codex runtime Hook compatibility check did not succeed. "
        f"status={info.hooks_status}; version={info.version}; path={info.path}; "
        f"return_code={info.return_code}; reason={info.reason}; detail={detail}"
    )


# SDKクライアントの設定と実際のプロセス引数から起動CLIを診断します。
def collect_sdk_runtime_metadata(codex: Any) -> dict[str, Any]:
    client = getattr(codex, "_client", None)
    config = getattr(client, "config", None)
    process = getattr(client, "_proc", None)
    process_args = getattr(process, "args", None)
    configured_raw = getattr(config, "codex_bin", None)
    launched_raw: str | None = None
    if isinstance(process_args, (list, tuple)) and process_args:
        launched_raw = str(process_args[0])
    elif isinstance(process_args, str):
        launched_raw = process_args.split(maxsplit=1)[0]

    initialize = get_codex_initialize_metadata(codex)
    server = initialize.get("serverInfo") or initialize.get("server_info") or {}
    if not isinstance(server, dict):
        server = {}
    return {
        "configured_cli_path": (
            str(Path(configured_raw).resolve(strict=False)) if configured_raw else None
        ),
        "launched_cli_path": (
            str(Path(launched_raw).resolve(strict=False)) if launched_raw else None
        ),
        "server_name": server.get("name"),
        "server_version": server.get("version"),
        "user_agent": initialize.get("userAgent") or initialize.get("user_agent"),
        "working_directory": getattr(config, "cwd", None),
    }


# バージョン表記の製品名部分を除き、SDK申告値とCLI出力を比較可能にします。
def normalize_runtime_version(value: str | None) -> str:
    raw = (value or "").strip()
    for prefix in ("codex-cli ", "codex "):
        if raw.lower().startswith(prefix):
            return raw[len(prefix) :].strip()
    return raw


# CLI出力とinitialize応答に付加情報があっても、比較対象のSemVer部分だけを取り出します。
def extract_runtime_semver(value: str | None) -> str | None:
    normalized = normalize_runtime_version(value)
    match = re.search(r"(?<![0-9A-Za-z])v?(\d+\.\d+\.\d+(?:[-._]?[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)", normalized)
    if match is None:
        return None
    return match.group(1).lower().replace("_", ".")


# probeしたCLIとSDKが起動したCLIのパス・SemVerが一致しない場合は停止します。
def verify_sdk_runtime_match(expected: CodexRuntimeInfo, actual: dict[str, Any]) -> None:
    launched = actual.get("launched_cli_path")
    if not launched:
        raise RuntimeError("Could not determine the Codex CLI path launched by the Python SDK.")
    expected_path = os.path.normcase(str(expected.path.resolve(strict=False)))
    launched_path = os.path.normcase(str(Path(str(launched)).resolve(strict=False)))
    if launched_path != expected_path:
        raise RuntimeError(
            "Codex SDK launched a different CLI than the compatibility probe: "
            f"probed={expected.path}; launched={launched}"
        )
    actual_version = extract_runtime_semver(str(actual.get("server_version") or ""))
    expected_version = extract_runtime_semver(expected.version)
    if actual_version and expected_version and actual_version != expected_version:
        raise RuntimeError(
            "Codex SDK runtime version differs from the compatibility probe: "
            f"probed={expected_version}; launched={actual_version}"
        )


# 生成したrulesをCodex CLIで構文解析し、検体名と絶対パスが拒否判定になるか確認します。
def validate_generated_rules(
    runtime_path: Path,
    rules_path: Path,
    sample_path: Path,
    timeout_seconds: float = 15.0,
) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    for label, token in (("basename", sample_path.name), ("absolute_path", str(sample_path.resolve()))):
        try:
            completed = subprocess.run(
                [str(runtime_path), "execpolicy", "check", "--pretty", "--rules", str(rules_path), token],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"Codex rules validation timed out for {label}.") from error
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
            raise RuntimeError(f"Error parsing generated rules for {label}: {detail}")
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(f"Codex rules validation returned invalid JSON for {label}.") from error
        decision = parsed.get("decision") if isinstance(parsed, dict) else None
        checks[label] = {"decision": decision, "command": token}
        if decision != "forbidden":
            raise RuntimeError(f"Generated rules did not forbid the protected sample {label}: {decision}")
    return checks


# probe済みCLIをSDKへ固定し、検査と実解析が同じ実体・PJを使うよう設定します。
# SDKの環境結合でも親アプリのCore識別が復活しないよう、独立起動を明示する。
def build_codex_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() != "CODEX_WINDOWS_REGISTERED_CORE"}
    # 省略だけではSDKが親の値を再継承する。認証・承認・sandbox設定は変更しない。
    environment["CODEX_WINDOWS_REGISTERED_CORE"] = "0"
    return environment


# 検査済みCLIと独立実行用環境を、静的・動的共通のSDKへ渡す。
def build_codex_config(
    developer: DeveloperVariableSettings,
    runtime_path: Path | None = None,
    working_directory: Path | None = None,
    model: str | None = None,
    reasoning_effort: str | None = None,
) -> Any:
    try:
        from openai_codex import CodexConfig
    except ImportError as error:
        raise RuntimeError("openai-codex Python SDK is not installed.") from error

    if runtime_path is None:
        runtime_path, _ = resolve_codex_runtime_path(developer)
    codex_bin = runtime_path.expanduser().resolve(strict=False)
    if not codex_bin.is_file():
        raise RuntimeError(f"Codex runtime selected for the SDK was not found: {codex_bin}")
    kwargs: dict[str, Any] = {
        "env": build_codex_environment(),
        "codex_bin": str(codex_bin),
        "config_overrides": build_model_config_overrides(model, reasoning_effort),
    }
    if working_directory is not None:
        kwargs["cwd"] = str(working_directory.resolve(strict=False))
    return CodexConfig(**kwargs)


# Python SDK側は一般操作を拒否し、PJ設定済み4ツールだけを承認対象に固定します。
def handle_codex_approval() -> Any:
    try:
        from openai_codex import ApprovalMode
    except ImportError as error:
        raise RuntimeError("openai-codex Python SDK is not installed.") from error
    return ApprovalMode.deny_all


# 専用Markdownテンプレートへ信頼しない入力パスと言語を埋め込みます。
def build_analysis_prompt(inputs: LlmAnalysisInputs, language: str) -> str:
    if not PROMPT_TEMPLATE_PATH.is_file():
        raise RuntimeError(f"Analysis prompt template was not found: {PROMPT_TEMPLATE_PATH}")
    template = Template(PROMPT_TEMPLATE_PATH.read_text(encoding="utf-8"))
    return template.safe_substitute(
        language=language or "English",
        sample_path=str(inputs.malware_path.resolve()),
        sysmon_path=str(inputs.sysmon_evtx_path.resolve()) if inputs.sysmon_evtx_path else "Not provided",
        dynamic_evidence_path=str(inputs.dynamic_evidence_path.resolve()),
        ghidra_server=GHIDRA_SERVER_NAME,
    )


# SDKオブジェクトからthread IDを互換的に取り出します。
def get_thread_id(thread: object) -> str | None:
    for attribute in ("id", "thread_id"):
        value = getattr(thread, attribute, None)
        if value:
            return str(value)
    return None


# SDKのunion wrapperを剥がし、実際のthread itemへ揃えます。
def unwrap_thread_item(item: Any) -> Any:
    return getattr(item, "root", item)


# MCP itemの引数を辞書へ正規化します。
def normalize_item_arguments(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


# turn履歴から必須4ツールの完了、エラー、対象検体パスを検証します。
def collect_ghidra_tool_calls(items: Iterable[Any], sample_path: Path) -> list[GhidraToolVerification]:
    expected_path = os.path.normcase(str(sample_path.resolve()))
    verifications: list[GhidraToolVerification] = []
    for wrapped in items:
        # SDKバージョンによるwrapper形状の違いを吸収してからMCP itemだけを扱います。
        item = unwrap_thread_item(wrapped)
        item_type = getattr(item, "type", None)
        if item_type != "mcpToolCall" and item.__class__.__name__ != "McpToolCallThreadItem":
            continue
        server = str(getattr(item, "server", ""))
        tool = str(getattr(item, "tool", ""))
        if server != GHIDRA_SERVER_NAME or tool not in REQUIRED_GHIDRA_TOOLS:
            continue
        arguments = normalize_item_arguments(getattr(item, "arguments", {}))
        status_value = getattr(item, "status", "")
        status = str(getattr(status_value, "value", status_value))
        error_value = getattr(item, "error", None)
        error = str(error_value) if error_value else None
        binary_path = arguments.get("binary_path")
        # ツール名が正しくても別ファイルを対象にしていれば成功として扱いません。
        path_matches = isinstance(binary_path, str) and os.path.normcase(str(Path(binary_path).resolve())) == expected_path
        success = status.lower() == "completed" and error is None and path_matches
        verifications.append(GhidraToolVerification(tool, status, success, error, arguments))

    return verifications


# 必須4ツールが1回以上成功したことを確認し、回復済みの再試行失敗は履歴へ残します。
def verify_ghidra_tool_calls(items: Iterable[Any], sample_path: Path) -> list[GhidraToolVerification]:
    verifications = collect_ghidra_tool_calls(items, sample_path)
    missing = [tool for tool in REQUIRED_GHIDRA_TOOLS if not any(v.tool == tool and v.success for v in verifications)]
    if missing:
        raise RuntimeError(f"Required Ghidra MCP calls did not complete successfully: {', '.join(missing)}")
    return verifications


# 最終成功前に失敗したMCP再試行を、成功判定とは分離した警告としてまとめます。
def collect_recovered_ghidra_failures(
    verifications: Iterable[GhidraToolVerification],
) -> list[dict[str, Any]]:
    items = list(verifications)
    successful_tools = {item.tool for item in items if item.success}
    return [
        {
            "tool": item.tool,
            "status": item.status,
            "error": item.error,
            "arguments": item.arguments,
        }
        for item in items
        if not item.success and item.tool in successful_tools
    ]


# 初期化ターンがツールや外部操作を行っていないことを確認します。
def verify_initialization_turn(result: Any) -> dict[str, Any]:
    item_types: list[str] = []
    forbidden: list[str] = []
    for wrapped in getattr(result, "items", []):
        item = unwrap_thread_item(wrapped)
        item_type = str(getattr(item, "type", item.__class__.__name__))
        item_types.append(item_type)
        lowered = item_type.lower()
        if any(token in lowered for token in ("toolcall", "commandexecution", "filechange", "websearch", "mcp")):
            forbidden.append(item_type)
    if forbidden:
        raise HookVerificationError(
            "initialization_turn_used_tools",
            f"The SessionStart initialization turn attempted prohibited operations: {', '.join(forbidden)}",
            {"item_types": item_types},
        )
    return {
        "completed": True,
        "item_types": item_types,
        "final_response": str(getattr(result, "final_response", "") or "")[:500],
    }


# read_onlyの安全な初期化ターンでHookを確認してからGhidra解析ターンを実行します。
def run_ghidra_analysis_turn(
    codex: Any,
    project_dir: Path,
    prompt: str,
    hook_context: HookVerificationContext,
    hook_marker_timeout_seconds: float = 15.0,
    hook_poll_interval_seconds: float = 0.25,
    model: str | None = None,
    progress_path: Path | None = None,
) -> tuple[Any, Any, dict[str, Any]]:
    from openai_codex import Sandbox

    # 古い成果物を消し、実行IDも照合することで過去のHook成功を誤認しません。
    hook_context.marker_path.unlink(missing_ok=True)
    hook_context.diagnostics_path.unlink(missing_ok=True)
    write_hook_run_context(hook_context)
    started_at = time.time()
    thread = codex.thread_start(
        cwd=str(project_dir),
        sandbox=Sandbox.read_only,
        approval_mode=handle_codex_approval(),
        model=model,
    )

    initialization: dict[str, Any] = {"required": False, "completed": False, "item_types": []}
    if not hook_marker_matches(hook_context, started_at):
        # 一部ランタイムはthread_startではなく最初のturn/startでSessionStartを発火させます。
        initialization["required"] = True
        from session_progress import run_turn
        initial_result = run_turn(
            thread,
            HOOK_INITIALIZATION_PROMPT,
            '静的解析 / Codex 準備',
            sandbox=Sandbox.read_only,
            approval_mode=handle_codex_approval(),
        )
        initialization.update(verify_initialization_turn(initial_result))
    hook_result = verify_hook_marker(
        hook_context,
        started_at,
        timeout_seconds=hook_marker_timeout_seconds,
        poll_interval_seconds=hook_poll_interval_seconds,
        runtime_stderr=get_codex_diagnostic_stderr(codex),
    )
    hook_result["initialization_turn"] = initialization

    # Hook確認が完了するまで検体パスを含む本解析プロンプトは一切送信しません。
    from session_progress import run_turn
    result = run_turn(
        thread, prompt, '静的解析 / Codex', progress_path,
        sandbox=Sandbox.read_only,
        approval_mode=handle_codex_approval(),
    )
    return thread, result, hook_result


# 選択形式の完成済みテンプレートを読み、レポート言語だけを埋め込みます。
def build_report_prompt(language: str, report_format: str) -> str:
    template_path = REPORT_PROMPT_PATHS.get(report_format)
    if template_path is None:
        raise RuntimeError(f"Unsupported report format: {report_format}")
    if not template_path.is_file():
        raise RuntimeError(f"Report prompt template was not found: {template_path}")
    return Template(template_path.read_text(encoding="utf-8")).safe_substitute(
        language=language or "English"
    )


# 同一threadをworkspace_writeへ切り替え、選択形式の検証後レポートだけを書かせます。
def run_report_turn(
    thread: Any,
    language: str,
    report_format: str,
    progress_path: Path | None = None,
) -> Any:
    from openai_codex import Sandbox

    prompt = build_report_prompt(language, report_format)
    from session_progress import run_turn
    return run_turn(
        thread, prompt, 'レポート生成 / Codex', progress_path,
        sandbox=Sandbox.workspace_write,
        approval_mode=handle_codex_approval(),
    )


# ---------------------------------------------------------------------------
# 解析レポートと実行metadataを保存する処理
# ---------------------------------------------------------------------------


# SDKパッケージ版をmetadataへ記録できる形で取得します。
def get_sdk_version() -> str:
    try:
        return importlib.metadata.version("openai-codex")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


# Codex SDKが現在のPythonまたはexeへ同梱されていることを明確なエラー付きで確認します。
def load_codex_class() -> Any:
    try:
        from openai_codex import Codex
    except ImportError as error:
        raise RuntimeError(
            "openai-codex Python SDK is unavailable in the current runtime: "
            f"{sys.executable}. Use the packaged r_AKanaly.exe or install openai-codex "
            "into the Python interpreter that starts r_AKanaly."
        ) from error
    return Codex


# 実行時刻と検体名から衝突しない結果ディレクトリを作ります。
def create_run_output_directory(output_root: Path, sample_name: str, started_at: datetime) -> Path:
    file_name = Path(sample_name).name
    base = output_root / f"{file_name}_{started_at.astimezone().strftime('%Y%m%d_%H%M%S')}"
    candidate = base
    index = 1
    while candidate.exists():
        candidate = output_root / f"{base.name}_{index}"
        index += 1
    candidate.mkdir(parents=True)
    return candidate


# 検証済みレポートとmetadataを実行別出力先へコピーします。
def save_analysis_outputs(
    output_root: Path,
    sample_name: str,
    started_at: datetime,
    report_source: Path | None,
    metadata: dict[str, Any],
    success: bool,
    partial_response: str = "",
    use_output_root_directly: bool = False,
    report_format: str = "md",
) -> tuple[Path, Path]:
    if report_format not in REPORT_PROMPT_PATHS:
        raise RuntimeError(f"Unsupported report format: {report_format}")
    if success and (report_source is None or not report_source.is_file() or report_source.stat().st_size == 0):
        raise RuntimeError(f"Codex did not generate a non-empty reports/analysis.{report_format}.")
    # テンプレート方式では既に実行単位の名前なので、さらにサブフォルダを増やしません。
    if use_output_root_directly:
        run_dir = output_root
        run_dir.mkdir(parents=True, exist_ok=True)
    else:
        run_dir = create_run_output_directory(output_root, sample_name, started_at)
    report_name = f"analysis.{report_format}" if success else f"analysis_failed.{report_format}"
    report_path = run_dir / report_name
    if success:
        assert report_source is not None
        shutil.copy2(report_source, report_path)
    else:
        failure_text = partial_response or "# Analysis failed\n"
        if report_format == "html":
            failure_text = (
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                "<title>Analysis failed</title></head><body><h1>Analysis failed</h1><pre>"
                + html.escape(failure_text)
                + "</pre></body></html>"
            )
        report_path.write_text(failure_text, encoding="utf-8")
    # ツール実行の検証と結論の正確性を混同しないよう、保存物へ必ず注記する。
    note = ('本レポートでいう検証は、必須ツール呼び出し・応答や成果物の生成など、'
            'プログラムが確認した処理条件を指します。解析結論の正確性・網羅性や、'
            'マルウェアの全挙動を確認したことを保証しません。未観測・失敗・未完了の情報は'
            '本文、dynamic_status.json、pipeline_status.jsonと併せて確認してください。')
    content = report_path.read_text(encoding='utf-8-sig')
    if report_format == 'html':
        block = '<aside aria-label="検証範囲の注記"><h2>検証範囲の注記</h2><p>' + html.escape(note) + '</p></aside>'
        import re
        end = re.search(r'</body\s*>', content, flags=re.IGNORECASE)
        content = content[:end.start()] + block + content[end.start():] if end else content + block
    else:
        content += '\n\n## 検証範囲の注記\n\n' + note + '\n'
    report_path.write_text(content, encoding='utf-8')
    metadata['verification_scope_note'] = note
    metadata_path = run_dir / "metadata.json"
    metadata["output_paths"] = {
        "run_directory": str(run_dir),
        "report": str(report_path),
        "metadata": str(metadata_path),
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return report_path, metadata_path


# dry-runでは副作用を起こさず、予定されるパスと処理だけを表示します。
def print_dry_run(settings: LlmSettings, inputs: LlmAnalysisInputs) -> None:
    project = (
        resolve_absolute_directory(settings.codex_project_dir, "Codex project directory")
        if settings.codex_project_dir is not None
        else prompt_absolute_directory("Codex project directory")
    )
    validation_error = validate_project_directory(project)
    if validation_error is not None:
        raise RuntimeError(validation_error)
    output = (
        resolve_absolute_directory(settings.analysis_output_dir, "Analysis output directory")
        if settings.analysis_output_dir is not None
        else prompt_absolute_directory("Analysis output directory")
    )
    if output == project or project in output.parents:
        raise RuntimeError("Analysis output directory must not be the project or a child of it.")
    print("Dry run: LLM analysis would perform the following operations:")
    print(f"  project: {project}")
    print(f"  output: {output}")
    print(f"  language: {settings.language or 'English'}")
    print(f"  report format: {settings.report_format}")
    print(f"  model: {settings.model or '<Codex default>'}")
    print(f"  reasoning effort: {settings.reasoning_effort or '<Codex default>'}")
    print(f"  malware source: {inputs.malware_path}")
    print(f"  Sysmon source: {inputs.sysmon_evtx_path or '<disabled>'}")
    print(f"  dynamic evidence source: {inputs.dynamic_evidence_path}")
    print("  planned: validate/clear PJ, copy inputs and guards, apply execute-deny ACL, self-test hooks")
    print("  planned: start read-only Ghidra turn, verify four MCP tools, write and export report")


# r_akanalyからだけ呼ばれるLLM解析オーケストレーターです。
def run(
    settings: LlmSettings,
    developer: DeveloperVariableSettings,
    inputs: LlmAnalysisInputs,
    dry_run: bool = False,
    guard_settings: dict[str, Any] | None = None,
    preparation: LlmRunPreparation | None = None,
    project_clear_confirmed: bool = False,
    hook_approval_confirmed: bool = False,
    vm_session: Any = None,
) -> LlmAnalysisResult | None:
    tui_runtime.set_stage("LLM立ち上げ", "解析PJ、Hook、Ghidra MCPを準備しています")
    print("Starting LLM analysis orchestration...", flush=True)
    started_at = preparation.started_at if preparation is not None else datetime.now(timezone.utc)
    # 最終確認前に準備済みなら同じパスを再利用し、日時や削除対象のずれを防ぎます。
    if preparation is not None:
        settings = preparation.settings
        template_output_selected = preparation.template_output_selected or preparation.output_is_run_directory
    else:
        settings, template_output_selected = resolve_llm_directory_settings(
            settings,
            inputs.malware_path,
            started_at,
        )
    if dry_run:
        print_dry_run(settings, inputs)
        return None

    # 解析開始前にPJ、入力、Hook、MCP、ACLを順に準備し、安全条件を自己テストします。
    if preparation is not None:
        project_dir = activate_prepared_project(preparation, project_clear_confirmed)
        output_root = preparation.output_dir
        output_root.mkdir(parents=True, exist_ok=True)
    else:
        project_dir = resolve_project_directory(settings.codex_project_dir)
        output_root = resolve_output_directory(settings.analysis_output_dir, project_dir)
    language = settings.language.strip() if settings.language.strip() else "English"
    layout = create_project_layout(project_dir)
    if vm_session is None:
        staged_inputs, hashes = stage_analysis_inputs(inputs, layout)
    else:
        # Guest解析では検体を解析PJへコピーせず、動的証拠だけを配置する。
        staged_inputs, hashes = stage_dynamic_inputs(inputs, layout)
        hashes['malware'] = vm_session.sha256
    if inputs.dynamic_status_path is not None:
        # 動的実行のタイムアウトと証拠不足を、挙動なしと区別してLLMへ渡す。
        from dataclasses import replace
        status_target = layout['logs'] / 'dynamic_status.json'
        hashes['dynamic_status'] = copy_and_verify_artifact(inputs.dynamic_status_path, status_target)
        staged_inputs = replace(staged_inputs, dynamic_status_path=status_target)
    copy_security_templates(layout, staged_inputs.malware_path, guard_settings)
    vm_tools = ('guest_analysis_request',) if vm_session is not None else None
    guard_settings_path = render_guard_settings(layout, staged_inputs.malware_path, guard_settings, vm_tools)
    hook_context = render_project_hooks(layout, guard_settings_path)
    ghidra_headless = None
    if vm_session is None:
        ghidra_headless = resolve_ghidra_headless()
        render_project_codex_config(layout, ghidra_headless, staged_inputs.malware_path,
            settings.timeouts.mcp_startup_seconds, settings.timeouts.mcp_tool_seconds)
        acl_result = apply_windows_execute_deny(staged_inputs.malware_path)
    else:
        from VMWARE_GUEST_CONTROL_PACKAGE.host.host_evidence import register_evidence
        register_evidence(vm_session.binding, layout['logs'], hashes)
        render_vm_codex_config(layout, vm_session, settings)
        acl_result = {'applied': False, 'reason': 'No additional Host sample staged; Guest static MCP binding is enforced'}
    self_tests = run_guard_self_tests(
        layout["hooks"] / "malware_guard.py",
        guard_settings_path,
        staged_inputs.malware_path,
        vm_tools,
    )
    # 失敗時にも途中経過を保存できるよう、SDK起動前にmetadataの初期値を揃えます。
    thread_id: str | None = None
    verifications: list[GhidraToolVerification] = []
    partial_response = ""
    error_message: str | None = None
    metadata: dict[str, Any] = {
        "success": False,
        "thread_id": None,
        "language": language,
        "report_format": settings.report_format,
        "model": settings.model,
        "reasoning_effort": settings.reasoning_effort,
        "timeouts": asdict(settings.timeouts),
        "sdk_version": get_sdk_version(),
        "codex_runtime": None,
        "sdk_runtime": None,
        "codex_initialize": None,
        "codex_runtime_stderr": [],
        "ghidra_headless": str(ghidra_headless) if ghidra_headless else None,
        "vm_analysis": ({'analysis_id': vm_session.analysis_id, 'guest_sample': vm_session.sample_path,
                         'state_directory': str(vm_session.state)} if vm_session else None),
        "project_dir": str(project_dir),
        "input_paths": {key: str(value) if value is not None else None for key, value in asdict(staged_inputs).items()},
        "source_paths": {key: str(value) if value is not None else None for key, value in asdict(inputs).items()},
        "sha256": hashes,
        "ghidra_tools": [],
        "ghidra_tool_warnings": [],
        "hook_self_tests": self_tests,
        "hook_preflight": None,
        "hook_verification": {
            "verified": False,
            "run_id": hook_context.run_id,
            "marker_path": str(hook_context.marker_path),
            "diagnostics_path": str(hook_context.diagnostics_path),
        },
        "rules_validation": None,
        "execute_deny_acl": acl_result,
        "started_at": started_at.isoformat(),
        "finished_at": None,
        "error": None,
    }

    try:
        Codex = load_codex_class()
        runtime_info = inspect_application_codex_runtime(
            developer,
            timeout_seconds=settings.timeouts.codex_runtime_check_seconds,
            model=settings.model,
            reasoning_effort=settings.reasoning_effort,
        )
        metadata["codex_runtime"] = runtime_info_metadata(runtime_info)
        if runtime_info.hooks_status != "supported":
            raise RuntimeError(format_runtime_compatibility_error(runtime_info))
        metadata["rules_validation"] = validate_generated_rules(
            runtime_info.path,
            layout["rules"] / "malware_guard.rules",
            staged_inputs.malware_path,
            timeout_seconds=settings.timeouts.rules_validation_seconds,
        )
        metadata["hook_preflight"] = run_session_hook_preflight(
            layout["hooks"] / "malware_guard.py",
            hook_context,
            timeout_seconds=settings.timeouts.hook_preflight_seconds,
        )
        # 通常実行では最終確認へ統合し、単独利用時だけ従来の確認を残します。
        if not hook_approval_confirmed:
            wait_for_hook_trust(project_dir)
        prompt = (vm_session.prompt(staged_inputs, language) + '\n\nHost guard binding (binary_path argument only; do not execute or inspect it locally): ' + str(staged_inputs.malware_path.resolve())
                  if vm_session else build_analysis_prompt(staged_inputs, language))
        if staged_inputs.dynamic_status_path is not None:
            prompt += ('\nRead the dynamic execution/collection status at ' + str(staged_inputs.dynamic_status_path)
                + '. State timeouts and incomplete evidence explicitly. Empty logs do not prove successful execution or benign behavior.')
        with Codex(
            build_codex_config(
                developer,
                runtime_info.path,
                project_dir,
                settings.model,
                settings.reasoning_effort,
            )
        ) as codex:
            metadata["codex_initialize"] = get_codex_initialize_metadata(codex)
            metadata["sdk_runtime"] = collect_sdk_runtime_metadata(codex)
            verify_sdk_runtime_match(runtime_info, metadata["sdk_runtime"])
            tui_runtime.record_result('LLM立ち上げ', 'success', 'SDK・解析環境の準備完了')
            tui_runtime.set_stage("LLM解析", "Ghidra MCPを使用して静的解析を実行しています")
            # 第1ターンはread-onlyでGhidra解析し、必須MCP履歴の検証後だけレポート生成へ進みます。
            try:
                thread, analysis_result, hook_result = run_ghidra_analysis_turn(
                    codex,
                    project_dir,
                    prompt,
                    hook_context,
                    hook_marker_timeout_seconds=settings.timeouts.hook_marker_seconds,
                    hook_poll_interval_seconds=settings.timeouts.hook_poll_interval_seconds,
                    model=settings.model,
                    progress_path=output_root / 'static_session.jsonl',
                )
                metadata["hook_verification"] = hook_result
            finally:
                metadata["codex_runtime_stderr"] = get_codex_diagnostic_stderr(codex)
            thread_id = get_thread_id(thread)
            partial_response = str(getattr(analysis_result, "final_response", "") or "")
            analysis_items = getattr(analysis_result, "items", [])
            if vm_session is None:
                verifications = collect_ghidra_tool_calls(analysis_items, staged_inputs.malware_path)
                verify_ghidra_tool_calls(analysis_items, staged_inputs.malware_path)
            else:
                metadata['vm_tools'] = verify_vm_tool_calls(analysis_items, vm_session)
                # 実際に読めたファイルと範囲を残し、ツール公開だけを読取り成功と混同しない。
                audit_path = vm_session.state / 'host_evidence_reads.jsonl'
                metadata['host_evidence_reads'] = ([json.loads(line) for line in
                    audit_path.read_text(encoding='utf-8').splitlines()] if audit_path.exists() else [])
            # Ghidra解析完了後の成果物生成を独立したロードマップ段階として表示します。
            tui_runtime.record_result('LLM解析', 'success', '解析ターン・必須ツール呼出しの確認完了（結論の正確性保証ではありません）')
            tui_runtime.set_stage("レポート化", "必須ツールの実行確認を終え、最終レポートを生成しています")
            report_result = run_report_turn(thread, language, settings.report_format,
                                            output_root / 'static_session.jsonl')
            report_response = str(getattr(report_result, "final_response", "") or "")
            if report_response:
                partial_response = report_response

        # 必須ツールとレポート生成が完了した時点だけ成功metadataとして確定します。
        metadata["success"] = True
        metadata["thread_id"] = thread_id
        metadata["ghidra_tools"] = [asdict(item) for item in verifications]
        metadata["ghidra_tool_warnings"] = collect_recovered_ghidra_failures(verifications)
        metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
        report_path, metadata_path = save_analysis_outputs(
            output_root,
            staged_inputs.malware_path.name,
            started_at,
            layout["reports"] / f"analysis.{settings.report_format}",
            metadata,
            True,
            use_output_root_directly=template_output_selected,
            report_format=settings.report_format,
        )
        tui_runtime.record_result('レポート化', 'success', 'レポート・metadata保存完了')
        return LlmAnalysisResult(True, project_dir, thread_id, report_path, metadata_path)
    except Exception as error:
        # SDK・Ghidra・レポートのどこで失敗しても、部分応答と検証状態を失敗レポートへ残します。
        error_message = str(error)
        if isinstance(error, HookVerificationError):
            metadata["hook_verification"] = {
                **metadata["hook_verification"],
                "verified": False,
                "error_code": error.code,
                "error": str(error),
                "diagnostics": error.diagnostics,
            }
        metadata["thread_id"] = thread_id
        metadata["ghidra_tools"] = [asdict(item) for item in verifications]
        metadata["ghidra_tool_warnings"] = collect_recovered_ghidra_failures(verifications)
        metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
        metadata["error"] = error_message
        failure_text = "# Analysis failed\n\n" + error_message
        if partial_response:
            failure_text += "\n\n## Partial Codex response\n\n" + partial_response
        report_path, metadata_path = save_analysis_outputs(
            output_root,
            staged_inputs.malware_path.name,
            started_at,
            None,
            metadata,
            False,
            failure_text,
            use_output_root_directly=template_output_selected,
            report_format=settings.report_format,
        )
        raise RuntimeError(
            f"{error_message} Failure details: {report_path}; metadata: {metadata_path}"
        ) from error
