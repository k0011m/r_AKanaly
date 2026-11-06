"""Guestに公式配布ZIPを展開し、固定パスのCLI入口を作る。"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path


# Windows Guestの専用領域だけに配置する。
def validate_root(root):
    if os.name != "nt" or not (root / "environment.json").is_file():
        raise RuntimeError("Configured Windows analysis guest is required")
    manufacturer = subprocess.check_output(
        ["powershell.exe", "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).Manufacturer"],
        creationflags=subprocess.CREATE_NO_WINDOW, timeout=30).decode(errors="replace")
    if "VMware" not in manufacturer:
        raise RuntimeError("VMware guest is required")


# 外部由来のアーカイブ名を検査し、今回の専用フォルダ以外へ書き出さない。
def unpack(package, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(package) as archive:
        for info in archive.infolist():
            target = (destination / info.filename).resolve()
            if not target.is_relative_to(destination.resolve()) or ":" in info.filename or "\\" in info.filename:
                raise RuntimeError("Unsafe distribution archive path")
        archive.extractall(destination)


# 絶対パスを持つ小さなbatを作り、Host側にインストールせずGuestから使用可能にする。
def write_launcher(path, command, environment=None):
    lines = ["@echo off", "setlocal"]
    lines.extend(f'set "{key}={value}"' for key, value in (environment or {}).items())
    lines += [command + " %*", "exit /b %ERRORLEVEL%"]
    path.write_bytes(("\r\n".join(lines) + "\r\n").encode("utf-8"))


# バージョン別の配置と起動設定を記録し、再導入時は同じ配布物を再利用する。
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=r"C:\Users\Public\r_AKanaly")
    args = parser.parse_args()
    root = Path(args.root)
    validate_root(root)
    package_dir = root / "static-tool-packages"
    manifest = json.loads((package_dir / "manifest.json").read_text(encoding="utf-8"))
    installed = {}
    for record in manifest["packages"]:
        package = package_dir / record["file"]
        if hashlib.sha256(package.read_bytes()).hexdigest() != record["sha256"]:
            raise RuntimeError("Guest package hash mismatch: " + package.name)
        target = root / "tools" / (record["tool"] + "-" + record["version"].lstrip("v"))
        marker = target / "distribution.sha256"
        if not marker.is_file() or marker.read_text() != record["sha256"]:
            unpack(package, target)
            marker.write_text(record["sha256"], encoding="ascii")
        installed[record["tool"]] = {"root": str(target), "version": record["version"], "sha256": record["sha256"]}
    paths = {
        "diec": str(Path(installed["die"]["root"]) / "die" / "diec.exe"),
        "die_gui": str(Path(installed["die"]["root"]) / "die" / "die.exe"),
        "floss": str(Path(installed["floss"]["root"]) / "floss.exe"),
        "capa": str(Path(installed["capa"]["root"]) / "capa.exe"),
        "ilspy_gui": str(Path(installed["ilspy_gui"]["root"]) / "ILSpy.exe"),
        "dotnet": str(Path(installed["dotnet"]["root"]) / "dotnet.exe"),
        "ilspycmd_dll": str(next(Path(installed["ilspycmd"]["root"]).glob("tools/*/any/ilspycmd.dll"))),
    }
    for path in paths.values():
        if not Path(path).is_file():
            raise RuntimeError("Missing installed tool: " + path)
    bin_dir = root / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name in ("diec", "die_gui", "floss", "capa", "ilspy_gui"):
        write_launcher(bin_dir / (name + ".cmd"), '"' + paths[name] + '"')
    # DiEの標準入力待ちを防ぎ、コンソールなしでファイル指定の解析を実行する。
    bridge = bin_dir / "diec-launch.py"
    bridge.write_text(
        'import subprocess, sys\n'
        '# 解析対象のパスを変更せず、DiEの出力と終了コードを呼出元へ返す。\n'
        f'raise SystemExit(subprocess.call([{paths["diec"]!r}, *sys.argv[1:]], '
        'stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW))\n', encoding="utf-8")
    write_launcher(bin_dir / "diec.cmd", f'"{sys.executable}" "{bridge}"')
    dotnet_env = {"DOTNET_ROOT": installed["dotnet"]["root"], "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
                  "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_NOLOGO": "1"}
    write_launcher(bin_dir / "ilspycmd.cmd", f'"{paths["dotnet"]}" "{paths["ilspycmd_dll"]}" --disable-updatecheck', dotnet_env)
    (root / "static-tools-env.cmd").write_bytes(f'@echo off\r\nset "PATH={bin_dir};%PATH%"\r\n'.encode("utf-8"))
    output = {"installed_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "packages": installed, "paths": paths,
              "bin_dir": str(bin_dir), "dotnet_environment": dotnet_env}
    (root / "static-tools.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "config": str(root / "static-tools.json")}))


if __name__ == "__main__":
    main()
