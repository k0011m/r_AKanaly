"""既存保存点を保持し、修正状態を新しい名前で分岐保存する。"""
import uuid
from .storage import atomic_json


# 元の保存点は削除・上書きせず、修正済み状態の新規保存点だけを作成する。
def clone_snapshot(vm, name, journal_path, context):
    if vm.snapshots().count(name) != 1:
        raise RuntimeError('Source snapshot must exist uniquely: ' + name)
    vm.shutdown()
    backup = 'r_AKanaly_repaired_' + uuid.uuid4().hex
    if backup in vm.snapshots():
        raise RuntimeError('New snapshot name already exists; no snapshot was changed')
    record = dict(context, source_snapshot=name, recovery_snapshot=backup, status='preparing')
    atomic_json(journal_path, record)
    vm.run('snapshot', vm.vmx, backup, timeout=600)
    if vm.snapshots().count(backup) != 1:
        raise RuntimeError('Recovery snapshot could not be verified')
    if vm.snapshots().count(name) != 1:
        raise RuntimeError('Source snapshot changed externally; new snapshot preserved: ' + backup)
    record['status'] = 'complete'
    atomic_json(journal_path, record)
    return record
