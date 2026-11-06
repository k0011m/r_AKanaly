"""GitHub Releaseの署名付き配布を検証し、版別に配置する。"""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .storage import atomic_json, digest, extract_zip, version, safe_member


# トークンを別ホストへのリダイレクトに渡さず、HTTPSを維持する。
class ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    # GitHubの一時配布URLには認証ヘッダーを引き継がない。
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ValueError("HTTPS redirect required")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(req.full_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


# GitHub以外へ秘密値を送らず、サイズと時間を制限して取得する。
def fetch(url, destination, limit, token=None, accept="application/octet-stream"):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("HTTPS URL required")
    headers = {"User-Agent": "r-AKanaly-Updater", "Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if token and parsed.hostname == "api.github.com":
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    size = 0
    with urllib.request.build_opener(ReleaseRedirect()).open(request, timeout=60) as response, Path(destination).open("wb") as stream:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError("Download exceeds size limit")
            stream.write(chunk)


# 固定公開鍵で元のJSONバイト列を検証してから、内容を解釈する。
def verify_manifest(raw, signature, public_key):
    Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True)).verify(signature, raw)
    data = json.loads(raw)
    required = {"schema", "version", "platform", "asset", "sha256", "size", "files", "guest_revision"}
    if not isinstance(data, dict) or set(data) != required or data["schema"] != 1 or data["platform"] != "windows-x64":
        raise ValueError("Unsupported release manifest")
    version(data["version"])
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.zip", data["asset"]) or not re.fullmatch(r"[0-9a-f]{64}", data["sha256"]):
        raise ValueError("Invalid asset or digest")
    if type(data["size"]) is not int or not 0 < data["size"] <= 16 * 1024**3:
        raise ValueError("Invalid release size")
    if not isinstance(data["guest_revision"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", data["guest_revision"]):
        raise ValueError("Invalid guest revision")
    if not isinstance(data["files"], dict) or "r_AKanaly_core.exe" not in data["files"]:
        raise ValueError("Core executable missing from manifest")
    for name, sha in data["files"].items():
        safe_member(name)
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError("Invalid file digest")
    return data


# ReleaseのAPIを使い、private repoでもブラウザー用URLへ依存しない。
def latest(config, cache):
    repository = config["repository"]
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository):
        raise ValueError("Invalid GitHub repository")
    if not config.get("public_key"):
        raise ValueError("Release signing public key is not configured")
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    token = os.environ.get("R_AKANALY_GITHUB_TOKEN")
    index = cache / "release.json"
    try:
        fetch(f"https://api.github.com/repos/{repository}/releases/latest", index, 4 * 1024**2, token, accept="application/vnd.github+json")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise RuntimeError('No accessible stable release: '+repository+' (HTTP 404)') from None
        raise
    release = json.loads(index.read_bytes())
    if release.get("draft") or release.get("prerelease"):
        raise ValueError("Not a stable release")
    assets = {a["name"]: a["url"] for a in release["assets"]}
    for name in ("release-manifest.json", "release-manifest.sig"):
        url = assets[name]
        if not url.startswith(f"https://api.github.com/repos/{repository}/releases/assets/"):
            raise ValueError("Unexpected release asset URL")
        fetch(url, cache / name, 4 * 1024**2, token)
    manifest = verify_manifest((cache / "release-manifest.json").read_bytes(), (cache / "release-manifest.sig").read_bytes(), config["public_key"])
    asset_url = assets[manifest["asset"]]
    if not asset_url.startswith(f"https://api.github.com/repos/{repository}/releases/assets/"):
        raise ValueError("Unexpected package URL")
    return manifest, asset_url


# ファイル一覧まで検証した独立ディレクトリだけを新版として保存する。
def stage(root, archive, manifest):
    root = Path(root)
    if Path(archive).stat().st_size != manifest["size"] or digest(archive) != manifest["sha256"]:
        raise ValueError("Release archive hash/size mismatch")
    target = root / "versions" / manifest["version"]
    if target.exists():
        verify_files(target, manifest)
        return target
    with tempfile.TemporaryDirectory(prefix="stage-", dir=root) as temporary:
        unpacked = Path(temporary) / "package"
        extract_zip(archive, unpacked)
        verify_files(unpacked, manifest)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(unpacked, target)
    return target


# 署名一覧外のファイルも拒否し、再利用した旧配置の改変を検出する。
def verify_files(folder, manifest):
    folder = Path(folder)
    files = {p.relative_to(folder).as_posix(): p for p in folder.rglob("*") if p.is_file()}
    if set(files) != set(manifest["files"]):
        raise ValueError("Release file inventory mismatch")
    for name, path in files.items():
        if path.is_symlink() or digest(path) != manifest["files"][name]:
            raise ValueError("Release file hash mismatch: " + name)


# VMに触れない自己診断を通した版と設定の組だけを一度に選択する。
def activate(root, manifest, settings_path, guest_revision, runner=subprocess.run):
    root = Path(root)
    target = root / "versions" / manifest["version"]
    verify_files(target, manifest)
    # 正しく署名されていても、解析に必須のHookを欠く版へ切り替えない。
    from .payload import HOOK_FILES, require_files
    require_files(target, HOOK_FILES)
    if guest_revision != manifest["guest_revision"]:
        atomic_json(root / "pending-update.json", {"version": manifest["version"], "reason": "Guest setup required", "guest_revision": manifest["guest_revision"]})
        raise RuntimeError("Guest update required. Run Setup.exe before activation; current version retained.")
    pointer = root / "current.json"
    old = json.loads(pointer.read_text(encoding="utf-8")) if pointer.exists() else None
    settings = Path(settings_path).resolve()
    if not settings.is_relative_to((root / "config").resolve()) or not settings.is_file():
        raise ValueError("Settings must be inside installation config directory")
    result = runner([str(target / "r_AKanaly_core.exe"), "--deployment-self-test", "--settings", str(settings)], capture_output=True, timeout=90)
    if result.returncode or b'"deployment_api": 1' not in result.stdout:
        raise RuntimeError("New core/config self-test failed; current version retained")
    current = {"version": manifest["version"], "settings": str(settings.relative_to(root.resolve())), "guest_revision": guest_revision, "previous": old}
    # 前歴は1世代に絞るが、実ファイルや保存点は削除しない。
    if old:
        old.pop("previous", None)
    atomic_json(pointer, current)
