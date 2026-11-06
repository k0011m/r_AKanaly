"""解析VMだけに一時localhostコンソールを付け、停止後に元の設定へ戻す。"""
import base64
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import uuid
from datetime import datetime

KEYS = ('RemoteDisplay.vnc.enabled', 'RemoteDisplay.vnc.ip', 'RemoteDisplay.vnc.port')
MARKER = 'r_AKanaly.consoleLeaseId'


class ConsoleLease:
    # 復旧記録には変更したキーだけを含め、VM暗号化情報は複製しない。
    def __init__(self, vmx, root):
        self.vmx = Path(vmx).resolve()
        self.record = Path(root) / 'console_lease.json'
        self.port = None
        if self.record.exists():
            saved = json.loads(self.record.read_text(encoding='utf-8'))
            if saved.get('vmx') != str(self.vmx):
                raise RuntimeError('Console recovery VM mismatch')
            self.port = saved.get('port')

    # snapshotに残った自分の一時設定だけを識別し、停止中の次セッション開始前に回収する。
    @classmethod
    def recover_managed(cls, vmx):
        vmx = Path(vmx).resolve()
        lines = vmx.read_text(encoding='utf-8').splitlines()
        values = {line.split('=', 1)[0].strip(): line.split('=', 1)[1].strip().strip('"')
                  for line in lines if '=' in line}
        marker = values.get(MARKER)
        if marker is None:
            return False
        if uuid.UUID(marker).hex != marker or values.get(KEYS[0]) != 'TRUE' or values.get(KEYS[1]) != '127.0.0.1':
            raise RuntimeError('Managed console configuration has changed; recovery cannot overwrite it')
        port = int(values.get(KEYS[2], '0'))
        if not 1024 <= port <= 65535:
            raise RuntimeError('Invalid managed console port')
        # 状態フォルダを失っても、管理マーカーと追加3キーが一致する場合だけ除去する。
        instance = cls.__new__(cls)
        instance.vmx = vmx
        instance.write([line for line in lines if line.split('=', 1)[0].strip() not in (*KEYS, MARKER)])
        return True

    # 停止確認は呼出し元で行い、既存のコンソール設定を無断で置換しない。
    def prepare(self):
        if self.record.exists() and not json.loads(self.record.read_text(encoding='utf-8')).get('restored'):
            raise RuntimeError('Unrestored console lease exists')
        lines = self.vmx.read_text(encoding='utf-8').splitlines()
        if any(line.split('=', 1)[0].strip().lower().startswith('remotedisplay.vnc.') for line in lines):
            raise RuntimeError('Existing VNC configuration must be resolved before managed setup')
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            self.port = probe.getsockname()[1]
        values = ['TRUE', '127.0.0.1', str(self.port)]
        added = [f'{key} = "{value}"' for key, value in zip(KEYS, values)]
        added.append(f'{MARKER} = "{uuid.uuid4().hex}"')
        self.record.parent.mkdir(parents=True, exist_ok=True)
        self.record.write_text(json.dumps({'vmx': str(self.vmx), 'port': self.port,
            'original': [], 'added': added, 'restored': False}), encoding='utf-8')
        self.write(lines + added)

    # 同一ディレクトリの一時ファイルから置換し、途中書込みをVMwareに読ませない。
    def write(self, lines):
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.vmx.parent,
                                             prefix=self.vmx.name + '.visual.', suffix='.tmp', delete=False) as stream:
                temporary = Path(stream.name)
                stream.write('\n'.join(lines) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.vmx)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    # 実際の待受範囲と所有プロセスを調べ、設定値だけで隔離成功と判断しない。
    def verify(self):
        script = ("$ErrorActionPreference='Stop'; $rows=@(Get-NetTCPConnection -State Listen -LocalPort "
            + str(int(self.port)) + "); @($rows | ForEach-Object { $proc=Get-Process -Id $_.OwningProcess; "
            "@{address=$_.LocalAddress; name=$proc.ProcessName; pid=$proc.Id; "
            "started=$proc.StartTime.ToUniversalTime().ToString('o')} }) | ConvertTo-Json -Compress")
        result = subprocess.run([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(script.encode('utf-16le')).decode()],
            capture_output=True, timeout=15, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if result.returncode:
            raise RuntimeError('Cannot verify console listener ownership')
        rows = json.loads(result.stdout.decode('utf-8-sig'))
        rows = rows if isinstance(rows, list) else [rows]
        if not rows:
            raise RuntimeError('Console is not listening')
        # サービス側VMwareではExecutablePathが非公開になるため、対象VMの起動ログと照合する。
        with (self.vmx.parent / 'vmware.log').open('r', encoding='utf-8', errors='replace') as stream:
            prefix = stream.read(65536)
        match = re.search(r'(?m)^(\S+).*Log for VMware Workstation pid=(\d+)\b', prefix)
        if match is None:
            raise RuntimeError('VM process identity missing from VM log')
        log_time = datetime.fromisoformat(match.group(1).replace('Z', '+00:00'))
        for row in rows:
            if row.get('address') not in ('127.0.0.1', '::1'):
                raise RuntimeError('Console listener is not restricted to loopback')
            if row.get('name', '').lower() != 'vmware-vmx':
                raise RuntimeError('Console listener is not owned by VMware')
            if int(row['pid']) != int(match.group(2)):
                raise RuntimeError('Console listener belongs to another VM')
            process_time = datetime.fromisoformat(row['started'].replace('Z', '+00:00'))
            if abs((process_time - log_time).total_seconds()) > 10:
                raise RuntimeError('VM log belongs to another process lifetime')
        return {'loopback_only': True, 'vm_owner_verified': True, 'port': self.port}

    # 正常停止後のみ呼び、変更競合があれば他プロセスの設定を上書きしない。
    def restore(self):
        if not self.record.exists():
            return
        record = json.loads(self.record.read_text(encoding='utf-8'))
        if record.get('restored'):
            return
        if record['vmx'] != str(self.vmx):
            raise RuntimeError('Console recovery VM mismatch')
        lines = self.vmx.read_text(encoding='utf-8').splitlines()
        current = [line for line in lines if line.split('=', 1)[0].strip() in (*KEYS, MARKER)]
        if sorted(current) == sorted(record['original']):
            # VMX更新後・記録更新前の中断、またはsnapshot復元済みの場合は復旧済みとして扱う。
            record['restored'] = True
            self.record.write_text(json.dumps(record), encoding='utf-8')
            return
        if sorted(current) != sorted(record['added']):
            raise RuntimeError('Console settings changed outside this session')
        self.write([line for line in lines if line.split('=', 1)[0].strip() not in (*KEYS, MARKER)] + record['original'])
        record['restored'] = True
        self.record.write_text(json.dumps(record), encoding='utf-8')
