#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import traceback
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPT_DIR = ROOT / "ghidra_scripts"


# Bridges Codex MCP tool calls to Ghidra's analyzeHeadless command.
class GhidraHeadlessServer:
    def __init__(self):
        self.ghidra_headless = self._resolve_headless_path()
        self.project_dir = Path(os.environ.get("GHIDRA_PROJECT_DIR", str(ROOT / "ghidra_projects")))
        self.project_name = os.environ.get("GHIDRA_PROJECT_NAME", "CodexGhidraMcp")
        self.default_timeout = int(os.environ.get("GHIDRA_TIMEOUT_SEC", "300"))
        protected_sample = os.environ.get("R_AKANALY_PROTECTED_SAMPLE")
        self.protected_sample = Path(protected_sample).resolve() if protected_sample else None

    # Finds analyzeHeadless from explicit env vars first, then common local installs.
    def _resolve_headless_path(self):
        explicit = os.environ.get("GHIDRA_HEADLESS")
        if explicit:
            return Path(explicit)

        ghidra_home = os.environ.get("GHIDRA_HOME")
        if ghidra_home:
            return Path(ghidra_home) / "support" / "analyzeHeadless.bat"

        documents = Path.home() / "Documents"
        candidates = sorted(documents.glob("ghidra*_PUBLIC*/ghidra*_PUBLIC/support/analyzeHeadless.bat"))
        if candidates:
            return candidates[-1]
        return Path("analyzeHeadless.bat")

    # Returns the MCP tool definitions exposed to Codex.
    def tools(self):
        return [
            {
                "name": "ghidra_analyze",
                "description": "Run Ghidra headless analysis for a binary and return command output.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string"},
                        "timeout_sec": {"type": "integer", "minimum": 1},
                    },
                    "required": ["binary_path"],
                },
            },
            {
                "name": "ghidra_list_functions",
                "description": "Analyze a binary with Ghidra and return discovered functions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string"},
                        "timeout_sec": {"type": "integer", "minimum": 1},
                    },
                    "required": ["binary_path"],
                },
            },
            {
                "name": "ghidra_decompile_function",
                "description": "Analyze a binary with Ghidra and decompile one function by name or address.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string"},
                        "function": {"type": "string"},
                        "timeout_sec": {"type": "integer", "minimum": 1},
                    },
                    "required": ["binary_path", "function"],
                },
            },
            {
                "name": "ghidra_get_strings",
                "description": "Analyze a binary with Ghidra and return defined strings.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {"type": "string"},
                        "min_length": {"type": "integer", "minimum": 1, "default": 4},
                        "timeout_sec": {"type": "integer", "minimum": 1},
                    },
                    "required": ["binary_path"],
                },
            },
        ]

    # Dispatches a named MCP tool to the matching Ghidra headless operation.
    def call_tool(self, name, arguments):
        if name == "ghidra_analyze":
            return self._text_result(self._analyze(arguments))
        if name == "ghidra_list_functions":
            return self._json_script_result("CodexListFunctions.java", arguments, [])
        if name == "ghidra_decompile_function":
            function = arguments.get("function")
            if not function:
                raise ValueError("function is required")
            return self._json_script_result("CodexDecompileFunction.java", arguments, [function])
        if name == "ghidra_get_strings":
            min_length = str(arguments.get("min_length", 4))
            return self._json_script_result("CodexGetStrings.java", arguments, [min_length])
        raise ValueError(f"Unknown tool: {name}")

    # 通常のGhidra解析結果をMCPのテキスト形式へ変換します。
    def _analyze(self, arguments):
        completed = self._run_headless(arguments, None, [])
        return json.dumps(
            {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            },
            ensure_ascii=False,
            indent=2,
        )

    # Runs a Ghidra script that writes structured JSON to a temporary file.
    def _json_script_result(self, script_name, arguments, script_args):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
            output_path = tmp.name
        try:
            completed = self._run_headless(arguments, script_name, [output_path, *script_args])
            payload = {}
            if Path(output_path).exists() and Path(output_path).stat().st_size > 0:
                payload = json.loads(Path(output_path).read_text(encoding="utf-8"))
            else:
                raise RuntimeError(f"Ghidra post-script did not produce output: {script_name}")
            payload["_ghidra"] = {
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            }
            return self._text_result(json.dumps(payload, ensure_ascii=False, indent=2))
        finally:
            try:
                Path(output_path).unlink(missing_ok=True)
            except OSError:
                pass

    # 保護対象との完全一致を確認してから、隔離PJでanalyzeHeadlessを実行します。
    def _run_headless(self, arguments, script_name, script_args):
        binary_path = Path(arguments.get("binary_path", "")).expanduser().resolve()
        if not binary_path.is_file():
            raise FileNotFoundError(f"binary_path does not exist: {binary_path}")
        if self.protected_sample is None:
            raise RuntimeError("R_AKANALY_PROTECTED_SAMPLE is not configured.")
        protected_path = self.protected_sample
        if not protected_path.is_file():
            raise RuntimeError(f"R_AKANALY_PROTECTED_SAMPLE is not a file: {protected_path}")
        if binary_path != protected_path:
            raise PermissionError(f"binary_path does not match the protected sample: {binary_path}")
        if not self.ghidra_headless.exists():
            raise FileNotFoundError(f"GHIDRA_HEADLESS does not exist: {self.ghidra_headless}")

        self.project_dir.mkdir(parents=True, exist_ok=True)
        project_name = f"{self.project_name}_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        command = [
            str(self.ghidra_headless),
            str(self.project_dir),
            project_name,
            "-import",
            str(binary_path),
            "-deleteProject",
        ]
        if script_name:
            command.extend(["-scriptPath", str(SCRIPT_DIR), "-postScript", script_name, *script_args])

        timeout = min(max(int(arguments.get("timeout_sec", self.default_timeout)), 1), self.default_timeout)
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            details = completed.stderr.strip() or completed.stdout.strip() or "no command output"
            raise RuntimeError(f"Ghidra Headless failed with exit code {completed.returncode}: {details}")
        return completed

    # Formats a plain text payload as an MCP content result.
    def _text_result(self, text):
        return {"content": [{"type": "text", "text": text}]}


# Implements the small subset of MCP JSON-RPC needed by Codex.
class JsonRpcMcpServer:
    def __init__(self):
        self.ghidra = GhidraHeadlessServer()

    # Handles one JSON-RPC request and returns a response object when required.
    def handle(self, request):
        method = request.get("method")
        request_id = request.get("id")
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": request.get("params", {}).get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "ghidra-headless", "version": "0.1.0"},
                }
            elif method == "tools/list":
                result = {"tools": self.ghidra.tools()}
            elif method == "tools/call":
                params = request.get("params", {})
                result = self.ghidra.call_tool(params.get("name"), params.get("arguments") or {})
            elif method in ("notifications/initialized", "$/cancelRequest"):
                return None
            else:
                return self._error(request_id, -32601, f"Method not found: {method}")
            if request_id is None:
                return None
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as exc:
            return self._error(request_id, -32000, str(exc), traceback.format_exc())

    # Creates a JSON-RPC error response with optional diagnostic detail.
    def _error(self, request_id, code, message, detail=None):
        error = {"code": code, "message": message}
        if detail:
            error["data"] = detail
        return {"jsonrpc": "2.0", "id": request_id, "error": error}


# Keeps the server attached to stdio until Codex closes the process.
def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    server = JsonRpcMcpServer()
    for line in sys.stdin:
        if not line.strip():
            continue
        response = server.handle(json.loads(line))
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
