"""署名済み配布物とSetup.exeを、GUIが標準参照する配置へまとめる。"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from deployment.releases import verify_manifest
from deployment.storage import digest, installation_lock


# 検証完了したコピーだけを確定し、古い本体と新しい署名の混在を検出する。
def verified_copy(source, target):
    source, target = Path(source), Path(target)
    if source.resolve() == target.resolve():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False, suffix='.pending') as stream:
        temporary = Path(stream.name)
    try:
        shutil.copyfile(source, temporary)
        if digest(source) != digest(temporary):
            raise ValueError('Installer copy mismatch: ' + source.name)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


# 起動引数なしのSetup.exeが同梱releaseを読み、指定公開鍵で検証できる一式を作る。
def assemble(package, binaries, output, trust_path):
    package, binaries, output = Path(package), Path(binaries), Path(output)
    trust = json.loads(Path(trust_path).read_text(encoding='utf-8'))
    manifest = verify_manifest((package/'release-manifest.json').read_bytes(),
                              (package/'release-manifest.sig').read_bytes(), trust['public_key'])
    archive = package / manifest['asset']
    if archive.stat().st_size != manifest['size'] or digest(archive) != manifest['sha256']:
        raise ValueError('Installer archive differs from signed manifest')
    for name in ('Setup.exe', 'r_AKanaly.exe'):
        if not (binaries/name).is_file():
            raise ValueError('Missing installer executable: ' + name)
    output.mkdir(parents=True, exist_ok=True)
    with installation_lock(output):
        for name in ('Setup.exe', 'r_AKanaly.exe'):
            verified_copy(binaries/name, output/name)
        verified_copy(trust_path, output/'release-trust.json')
        for name in (manifest['asset'], 'release-manifest.json', 'release-manifest.sig'):
            verified_copy(package/name, output/'release'/name)
    return manifest


# 配布者が明示した署名済みパッケージだけを組み立て、署名鍵の生成や公開は行わない。
def main():
    parser = argparse.ArgumentParser()
    for option in ('package', 'binaries', 'output', 'trust'):
        parser.add_argument('--'+option, required=True)
    args = parser.parse_args()
    manifest = assemble(args.package, args.binaries, args.output, args.trust)
    print('Installer distribution assembled:', manifest['version'])


if __name__ == '__main__':
    main()
