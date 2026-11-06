"""再配布できないSysinternalsを利用者の環境で公式配布元から取得する。"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile
from .releases import fetch
from .storage import digest


# 利用規約への明示同意と署名済みの取得情報を、ネットワーク接続より前に検査する。
def load_downloads(release, accepted):
    if accepted is not True:
        raise ValueError('Accept the Sysinternals license in Setup before downloading tools')
    data = json.loads((Path(release)/'sysinternals-downloads.json').read_text(encoding='utf-8'))
    expected = {'Procmon64.exe': 'ProcessMonitor.zip', 'Sysmon64.exe': 'Sysmon.zip'}
    if data.get('schema') != 1 or set(data.get('files', {})) != set(expected):
        raise ValueError('Invalid Sysinternals download manifest')
    for name, archive in expected.items():
        record = data['files'][name]
        if record['url'] != 'https://download.sysinternals.com/files/'+archive:
            raise ValueError('Sysinternals download must use the official Microsoft URL')
        if any(not re.fullmatch('[0-9a-f]{64}', record.get(key, '')) for key in ('sha256', 'archive_sha256')):
            raise ValueError('Invalid Sysinternals hash')
    return data['files']


# Microsoftの有効なAuthenticode署名を確認し、ハッシュだけの一致で配置しない。
def verify_publisher(path):
    literal = str(Path(path).resolve()).replace("'", "''")
    script = "$ErrorActionPreference='Stop'; Import-Module ($PSHOME+'\\Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1'); $s=Get-AuthenticodeSignature -LiteralPath '"+literal+"'; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)'){throw 'Microsoft signature invalid'}"
    powershell = Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
    # PowerShell 7から継承したモジュール探索先を5.1へ混ぜない。
    environment = dict(os.environ, PSModulePath=str(powershell.parent/'Modules'))
    result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-Command', script],
                            env=environment, capture_output=True, timeout=120, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ValueError('Microsoft Authenticode verification failed: '+Path(path).name)


# 署名対象のversionsは変更せず、ハッシュ別キャッシュへ検証済みexeだけを確定する。
def prepare(release, root, accepted, report=print):
    records = load_downloads(release, accepted)
    paths = {}
    for name, record in records.items():
        folder = Path(root)/'external-tools'/'sysinternals'/record['sha256']
        folder.mkdir(parents=True, exist_ok=True)
        target = folder/name
        if target.is_file() and digest(target) == record['sha256']:
            verify_publisher(target)
        else:
            report('Downloading from Microsoft: '+name)
            with tempfile.TemporaryDirectory(dir=folder) as temporary:
                archive = Path(temporary)/'download.zip'
                fetch(record['url'], archive, 64*1024**2)
                if digest(archive) != record['archive_sha256']:
                    raise ValueError('Microsoft package changed; updated signed release required: '+name)
                pending = Path(temporary)/name
                with zipfile.ZipFile(archive) as bundle:
                    if bundle.namelist().count(name) != 1 or bundle.getinfo(name).file_size > 64*1024**2:
                        raise ValueError('Unexpected Microsoft archive contents')
                    pending.write_bytes(bundle.read(name))
                if digest(pending) != record['sha256']:
                    raise ValueError('Microsoft executable hash mismatch: '+name)
                verify_publisher(pending)
                os.replace(pending, target)
        paths[name] = target
    return paths
