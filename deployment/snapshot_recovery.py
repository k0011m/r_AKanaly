"""Setupの保存点置換をHost側の記録と退避保存点で保護する。"""
import uuid
from .storage import atomic_json


# 元の保存点を消す前に修復済み状態を確保し、失敗時もその名前を残す。
def replace_snapshot(vm, name, journal_path, context):
    if vm.snapshots().count(name) != 1:
        raise RuntimeError('Replacement snapshot must exist uniquely: ' + name)
    vm.shutdown()
    backup = 'r_AKanaly_repaired_' + uuid.uuid4().hex
    record = dict(context, source_snapshot=name, recovery_snapshot=backup, status='preparing')
    atomic_json(journal_path, record)
    vm.run('snapshot', vm.vmx, backup, timeout=600)
    if vm.snapshots().count(backup) != 1:
        raise RuntimeError('Recovery snapshot could not be verified')
    record['status'] = 'preserved'
    atomic_json(journal_path, record)
    # 子保存点は削除しない。再派生は呼び出し側が工程をやり直して行う。
    vm.run('deleteSnapshot', vm.vmx, name, timeout=600)
    record['status'] = 'old_deleted'
    atomic_json(journal_path, record)
    vm.run('snapshot', vm.vmx, name, timeout=600)
    if vm.snapshots().count(name) != 1:
        raise RuntimeError('Replacement snapshot could not be verified; recovery: ' + backup)
    record['status'] = 'complete'
    atomic_json(journal_path, record)
    return record
