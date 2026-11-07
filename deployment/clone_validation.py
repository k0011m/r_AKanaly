"""手動作成された完全クローンのディスク参照を検査する。"""
from pathlib import Path
import re
from .vm_copy import inspect_vm_files, references


# 元VMや外部ディスクへの参照・リンククローンを拒否してから構築に使う。
def verify_full_clone(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination == source or destination.parent.is_relative_to(source.parent) or source.parent.is_relative_to(destination.parent):
        raise ValueError('Clone must be outside the original VM directory')
    if not destination.is_file():
        raise ValueError('Clone VMX does not exist yet: ' + str(destination))
    files = inspect_vm_files(destination)
    if any(not path.is_relative_to(destination.parent) for path, _, _ in files):
        raise ValueError('Clone references files outside its directory; a full independent clone is required')
    names, config, _ = references(destination)
    disks = [destination.parent / name for name in names if Path(name).suffix.lower() == '.vmdk']
    if not disks:
        raise ValueError('Cannot verify clone disk references')
    for disk in disks:
        _, descriptor, _ = references(disk)
        if descriptor is None or not re.search(r'(?mi)^\s*parentCID\s*=\s*ffffffff\s*$', descriptor):
            raise ValueError('Clone requires a readable standalone disk descriptor: ' + disk.name)
        if re.search(r'(?mi)^\s*parentFileNameHint\s*=', descriptor):
            raise ValueError('Linked or snapshot disk cannot be accepted as a new full clone')
    return {'vmx': str(destination), 'files': len(files), 'bytes': sum(size for _, size, _ in files), 'independent': True}
