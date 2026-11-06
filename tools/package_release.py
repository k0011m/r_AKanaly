"""配布者専用：版別配布を梱包し、Ed25519で署名する。公開処理は行わない。"""
import argparse
import base64
import json
import hashlib
from pathlib import Path
import sys
import zipfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from deployment.storage import digest,version,atomic_json,safe_member
from deployment.payload import HOOK_FILES, require_files
from deployment.releases import verify_manifest

# 検証済み候補を再圧縮せず、原本と全収録ファイルの一致を確認して正式署名する。
def sign_existing(package_dir, key_path, trust_path):
    folder = Path(package_dir)
    raw = (folder/'release-manifest.json').read_bytes()
    trust = json.loads(Path(trust_path).read_text(encoding='utf-8'))
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Ed25519 key required')
    signature = key.sign(raw)
    manifest = verify_manifest(raw, signature, trust['public_key'])
    archive = folder/manifest['asset']
    if archive.stat().st_size != manifest['size'] or digest(archive) != manifest['sha256']:
        raise ValueError('Archive hash/size mismatch')
    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
        if len(names) != len(set(names)) or set(names) != set(manifest['files']):
            raise ValueError('Archive inventory mismatch')
        for name, expected in manifest['files'].items():
            with zipped.open(name) as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            if actual != expected:
                raise ValueError('Archive member mismatch: '+name)
    # 既存署名は上書きせず、検証完了した署名だけを保存する。
    with (folder/'release-manifest.sig').open('xb') as stream:
        stream.write(signature)
    print('Signed and verified:', manifest['version'], len(manifest['files']), 'files')

# 配布者が明示した保存先だけへ秘密鍵を生成し、公開鍵だけを表示する。
def keygen(path):
    key=Ed25519PrivateKey.generate()
    with Path(path).open('xb') as stream:
        stream.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    print(base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode())

# 設定や検体を紛れ込ませない専用配布ディレクトリを署名する。
def package(source,output,number,revision,key_path):
    version(number)
    source,output=Path(source),Path(output)
    require_files(source, HOOK_FILES)
    if output.resolve().is_relative_to(source.resolve()):
        raise ValueError('Output must be outside payload directory')
    for name in ('r_AKanaly_core.exe','guest.zip','guest-manifest.json','r_AKanaly_setting.example.json','r_AKanaly_guard.exe','r_AKanaly_ghidra_mcp.exe','sysinternals-downloads.json','guest-downloads.json'):
        if not (source/name).is_file():
            raise ValueError('Missing payload: '+name)
    files={}
    for path in source.rglob('*'):
        if path.is_file():
            relative=path.relative_to(source).as_posix()
            safe_member(relative)
            if path.is_symlink() or path.name.startswith('.env') or path.name in ('r_AKanaly_setting.json','credentials.dpapi.json') or path.suffix.lower() in ('.pem','.key'):
                raise ValueError('Private data forbidden in release: '+relative)
            files[relative]=digest(path)
    output.mkdir(parents=True,exist_ok=True)
    name='r_AKanaly-'+number+'-windows-x64.zip'
    with zipfile.ZipFile(output/name,'w',zipfile.ZIP_DEFLATED,compresslevel=1) as archive:
        for file in sorted(files):
            archive.write(source/file,file)
    manifest={'schema':1,'version':number,'platform':'windows-x64','asset':name,'size':(output/name).stat().st_size,'sha256':digest(output/name),'files':files,'guest_revision':revision}
    raw=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
    key=serialization.load_pem_private_key(Path(key_path).read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey):
        raise ValueError('Ed25519 key required')
    (output/'release-manifest.json').write_bytes(raw)
    (output/'release-manifest.sig').write_bytes(key.sign(raw))

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='action',required=True)
    keys=sub.add_parser('keygen');keys.add_argument('--key',required=True)
    signing=sub.add_parser('sign-existing')
    for option in ('package', 'key', 'trust'):
        signing.add_argument('--'+option, required=True)
    pack=sub.add_parser('package')
    for option in ('source','output','version','guest-revision','key'):
        pack.add_argument('--'+option,required=True)
    args=parser.parse_args()
    if args.action=='keygen':
        keygen(args.key)
    elif args.action=='sign-existing':
        sign_existing(args.package, args.key, args.trust)
    else:
        package(args.source,args.output,args.version,args.guest_revision,args.key)
