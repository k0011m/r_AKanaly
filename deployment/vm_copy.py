"""停止した自己完結VMを、暗号化と保存点を保持したまま複製する。"""
import hashlib
from pathlib import Path, PureWindowsPath
import re
import shutil
import time
import uuid
from .storage import atomic_json, digest


# テキストの実ディスク参照だけを読む。バイナリ本文やddbの履歴値は参照として扱わない。
def references(path):
    with path.open('rb') as stream:
        raw=stream.read(1024*1024)
    if path.suffix.lower()=='.vmdk' and not raw.startswith(b'# Disk DescriptorFile'):
        return [], None, None
    if path.suffix.lower() not in ('.vmx','.vmsd','.vmdk'):
        return [], None, None
    encoding='cp932' if b'encoding="Shift_JIS"' in raw else 'utf-8'
    text=raw.decode(encoding)
    pattern=(r'(?mi)^\s*parentFileNameHint\s*=\s*"([^"]+)"' if path.suffix.lower()=='.vmdk' else r'(?mi)^\s*(?:[\w:.]*fileName|[\w.]*filename|nvram)\s*=\s*"([^"]+)"')
    names=re.findall(pattern,text)
    names+=re.findall(r'(?mi)^\s*(?:RW|RDONLY|NOACCESS)\s+\d+\s+\w+\s+"([^"]+)"',text)
    return [n for n in names if PureWindowsPath(n).suffix.lower() in ('.vmdk','.vmsn','.vmem','.nvram','.vmss')],text,encoding


# 外部参照はコピー対象として閉包を求め、リンク・欠落・稼働中のディスクを拒否する。
def inspect_vm_files(vmx):
    vmx=Path(vmx).resolve()
    config=vmx.read_text(encoding='utf-8')
    if re.search(r'(?mi)^checkpoint\.vmState\s*=\s*"[^"]+"',config):
        raise ValueError('Shut down the VM; suspended VM copies are not supported')
    pending=list(vmx.parent.rglob('*')); seen=set(); files=[]
    while pending:
        path=pending.pop(0)
        if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):
            raise ValueError('VM contains a link: '+str(path))
        path=path.resolve()
        if path in seen: continue
        seen.add(path)
        if path.name.lower().endswith('.lck'): raise ValueError('VM has a lock; shut it down before copying')
        if not path.is_file(): continue
        names,_,_=references(path)
        for name in names:
            target=path.parent/name
            if not target.is_file(): raise ValueError('VM reference is missing: '+name)
            pending.append(target)
        stat=path.stat();files.append((path,stat.st_size,stat.st_mtime_ns))
    return sorted(files)


# 別フォルダの証拠ディスク等も専用コピーへ移し、原本へ接続しない相対パスを作る。
def copy_layout(files, root):
    return {path:(path.relative_to(root) if path.is_relative_to(root) else Path('external')/hashlib.sha256(str(path.parent).encode()).hexdigest()[:16]/path.name) for path,_,_ in files}


# 作業用フォルダに照合済みコピーを作り、全件成功後だけ完成先へ確定する。
def copy_stopped_vm(vmx, destination, is_running, report=print):
    vmx, destination = Path(vmx).resolve(), Path(destination).resolve()
    if destination.name != vmx.name:
        raise ValueError('Copy destination VMX must keep the source filename: ' + vmx.name)
    if destination.parent.exists() or destination.parent.is_relative_to(vmx.parent):
        raise ValueError('Use a new VM directory outside the source')
    if is_running():
        raise RuntimeError('Source VM is running')
    files = inspect_vm_files(vmx)
    destination.parent.parent.mkdir(parents=True, exist_ok=True)
    total = sum(size for _, size, _ in files)
    if shutil.disk_usage(destination.parent.parent).free < total + 1024**3:
        raise ValueError('Insufficient free space for full VM copy')
    staging = destination.parent.with_name(destination.parent.name + '.copy-' + uuid.uuid4().hex)
    staging.mkdir()
    layout=copy_layout(files,vmx.parent)
    records, completed = {}, 0
    last_report = 0
    for source, size, modified in files:
        if is_running():
            raise RuntimeError('Source VM started during copying; incomplete copy retained: ' + str(staging))
        relative = layout[source]
        target = staging / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        expected = hashlib.sha256()
        with source.open('rb') as reader, target.open('xb') as writer:
            while block := reader.read(8 * 1024**2):
                writer.write(block)
                expected.update(block)
                completed += len(block)
                if time.monotonic() - last_report > 10:
                    report(f'VM copy: {completed}/{total} bytes')
                    last_report = time.monotonic()
        if digest(target) != expected.hexdigest():
            raise ValueError('VM copy hash mismatch: ' + str(relative))
        stat = source.stat()
        if (stat.st_size, stat.st_mtime_ns) != (size, modified):
            raise RuntimeError('Source changed during VM copy: ' + str(relative))
        records[relative.as_posix()] = expected.hexdigest()
    # ディスクリプタ内の参照を複製内へ向け、変換後のハッシュを記録する。
    import os
    for source,_,_ in files:
        names,text,encoding=references(source)
        if text is None: continue
        for name in names:
            referred=(source.parent/name).resolve()
            relative=os.path.relpath(staging/layout[referred],(staging/layout[source]).parent)
            text=text.replace(chr(34)+name+chr(34),chr(34)+relative+chr(34))
        target=staging/layout[source]
        target.write_bytes(text.encode(encoding))
        records[layout[source].as_posix()]=digest(target)
    if is_running() or inspect_vm_files(vmx) != files:
        raise RuntimeError('Source VM changed before copy completion')
    if any(not path.is_relative_to(staging) for path,_,_ in inspect_vm_files(staging/destination.name)):
        raise RuntimeError('Copied VM still references an external file')
    atomic_json(staging / 'r_AKanaly-copy-manifest.json', {'schema': 1, 'files': records})
    staging.rename(destination.parent)
    return destination
