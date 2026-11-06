"""固定CLIから版を選択し、更新または解析本体を実行する。"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from . import credentials, releases
from .storage import atomic_json, installation_lock, version

# 配布exeとソース実行のインストール先を決める。
def install_root():
    return Path(os.environ.get("R_AKANALY_INSTALL_ROOT", str(Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1] / "dist/installed"))).resolve()

# オフライン初回配置もオンライン更新と同じ署名検証を通す。
def install_release(root, package_dir, public_key):
    package = Path(package_dir)
    manifest = releases.verify_manifest((package / "release-manifest.json").read_bytes(), (package / "release-manifest.sig").read_bytes(), public_key)
    Path(root).mkdir(parents=True, exist_ok=True)
    releases.stage(root, package / manifest["asset"], manifest)
    return manifest

# 検証済み新版を配置し、Guest互換性を満たす場合だけ有効化する。
def update(root, check=False, ui=None):
    root = Path(root)
    report = ui.status if ui else print
    if not (root / "update.json").is_file():
        raise RuntimeError("更新元が未設定です。正式な配布元の設定後に更新できます。")
    config = json.loads((root / "update.json").read_text(encoding="utf-8"))
    current = json.loads((root / "current.json").read_text(encoding="utf-8")) if (root / "current.json").exists() else None
    with tempfile.TemporaryDirectory(prefix="update-", dir=root) as temporary:
        manifest, url = releases.latest(config, temporary)
        if current and version(manifest["version"]) <= version(current["version"]):
            report("最新版です：" + current["version"])
            return 0
        report("更新バージョン：" + manifest["version"])
        if check:
            return 0
        number = current["version"] if current else "未インストール"
        if ui:
            approved = ui.confirm(number, manifest["version"])
        else:
            print("Current: " + number)
            approved = input("この版へ更新しますか？ [y/N]: ").strip().lower() in ("y", "yes")
        if not approved:
            report("更新をキャンセルしました。")
            return 0
        report("更新ファイルをダウンロードしています…")
        archive = Path(temporary) / manifest["asset"]
        releases.fetch(url, archive, manifest["size"], os.environ.get("R_AKANALY_GITHUB_TOKEN"))
        report("ファイルを検証・展開しています…")
        releases.stage(root, archive, manifest)
        atomic_json(root / "versions" / (manifest["version"] + ".manifest.json"), manifest)
        # Guest更新後のGUIでも元署名を検証できるよう、公開メタデータだけを保存する。
        import shutil
        metadata=root/'releases'/manifest['version']
        metadata.mkdir(parents=True,exist_ok=True)
        for name in ('release-manifest.json','release-manifest.sig'):
            shutil.copy2(Path(temporary)/name,metadata/name)
        if not current:
            raise RuntimeError("Initial Guest setup is required; run Setup.exe")
        if current['guest_revision'] != manifest['guest_revision']:
            from .setup_engine import SetupEngine
            atomic_json(root/'pending-update.json',{'version':manifest['version'],'guest_revision':manifest['guest_revision']})
            stored=credentials.load(root)
            plan_file=root/'installed-setup-plan.json'
            if not plan_file.exists() or not stored.get('R_AKANALY_GUEST_OS_PASSWORD'):
                raise RuntimeError('Guest update needs setup information. Run Setup.exe; current version retained.')
            plan=json.loads(plan_file.read_text(encoding='utf-8'))
            plan['mode']='existing'
            plan['vmx']=json.loads((root/current['settings']).read_text(encoding='utf-8'))['vmware']['vmx_path']
            secret={'guest_password':stored['R_AKANALY_GUEST_OS_PASSWORD'],'vm_password':stored.get('R_AKANALY_VMWARE_PASSWORD','')}
            SetupEngine(plan,secret,manifest,report=report).apply(locked=True)
            report('Guestと本体の更新が完了しました：'+manifest['version'])
            return 0
        report("本体を検証し、新版へ切り替えています…")
        releases.activate(root, manifest, root / current["settings"], current["guest_revision"])
        report("更新が完了しました：" + manifest["version"])
    return 0

# 解析は版と設定の組を固定して起動し、認証値を子プロセスだけへ渡す。
def launch(root, args):
    root = Path(root)
    current = json.loads((root / "current.json").read_text(encoding="utf-8"))
    version(current["version"])
    executable = root / "versions" / current["version"] / "r_AKanaly_core.exe"
    settings = (root / current["settings"]).resolve()
    if not settings.is_relative_to((root / "config").resolve()):
        raise ValueError("Invalid settings pointer")
    environment = dict(os.environ)
    for key, value in credentials.load(root).items():
        if key in ("R_AKANALY_GUEST_OS_PASSWORD", "R_AKANALY_VMWARE_PASSWORD"):
            environment[key] = value
    environment["R_AKANALY_SETTINGS_PATH"] = str(settings)
    environment["R_AKANALY_INSTALL_ROOT"] = str(root)
    return subprocess.call([str(executable), *args], cwd=root, env=environment)


# 本体が更新要求で終了した後だけ更新画面を開き、終了・取消・失敗後も本体へ戻す。
def run_application(root, args):
    while True:
        result = launch(root, args)
        if result != 42:
            return result
        from .update_tui import interactive
        if interactive():
            show_update(root)
            args = []
            continue
        print("\n更新ランチャー：本体は終了しました。更新を確認しています。")
        try:
            update(root)
        except (KeyboardInterrupt, EOFError):
            print("更新をキャンセルしました。")
        except Exception as error:
            print("更新できませんでした: " + str(error))
        try:
            input("Enterで本体へ戻ります。")
        except (KeyboardInterrupt, EOFError):
            pass
        args = []


# 更新の結果もTUI内へ表示し、終了時には必ず元の端末状態に戻す。
def show_update(root, check=False):
    from .update_tui import UpdateScreen
    result = 0
    with UpdateScreen() as ui:
        try:
            result = update(root, check=check, ui=ui)
        except (KeyboardInterrupt, EOFError):
            ui.status('更新をキャンセルしました。')
        except Exception as error:
            ui.status('更新できませんでした：\n' + str(error))
            result = 1
        try:
            ui.finish()
        except (KeyboardInterrupt, EOFError):
            pass
    return result

# 解析・更新・構築をロックし、稼働中の本体や保存点を変更しない。
def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    root = install_root()
    if args and args[0] in ("-h", "--help"):
        print("r_AKanaly [analysis options]\nr_AKanaly update [--check]\nr_AKanaly rollback\nr_AKanaly setup")
        return 0
    try:
        if args == ["setup"]:
            return subprocess.call([str(root / "Setup.exe")])
        with installation_lock(root):
            if args and args[0] == "update":
                parser = argparse.ArgumentParser(prog="r_AKanaly update")
                parser.add_argument("--check", action="store_true")
                from .update_tui import interactive
                check = parser.parse_args(args[1:]).check
                return show_update(root, check) if interactive() else update(root, check)
            if args == ["rollback"]:
                previous = json.loads((root / "current.json").read_text()).get("previous")
                if not previous:
                    raise RuntimeError("No previous installation")
                version(previous["version"])
                settings = (root / previous["settings"]).resolve()
                if not settings.is_relative_to((root / "config").resolve()) or not settings.is_file() or not (root / "versions" / previous["version"] / "r_AKanaly_core.exe").is_file():
                    raise RuntimeError("Previous version or settings missing")
                atomic_json(root / "current.json", previous)
                print("Rolled back to " + previous["version"])
                return 0
            return run_application(root, args)
    except Exception as error:
        print("Launcher: " + (str(error) if isinstance(error, (ValueError, RuntimeError, FileNotFoundError)) else type(error).__name__), file=sys.stderr)
        return 1
