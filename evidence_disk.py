"""動的成果物をHostで展開せず、解析単位の独立VMDKで静的Guestへ渡す。"""
import json
from pathlib import Path, PureWindowsPath
import re
import subprocess
import sys
import uuid

DEFAULTS = {'enabled': False, 'size_mb': 4096, 'max_files': 256,
            'max_total_mb': 2048, 'guest_paths': []}


# 未指定時は従来動作を維持し、容量制限とGuestローカルパスを実行前に検証する。
def parse_settings(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULTS):
        raise ValueError('Invalid dynamic_analysis.evidence_disk settings')
    result = dict(DEFAULTS, **value)
    if not isinstance(result['enabled'], bool):
        raise ValueError('evidence_disk.enabled must be boolean')
    for key in ('size_mb', 'max_files', 'max_total_mb'):
        if type(result[key]) is not int or result[key] <= 0:
            raise ValueError('evidence_disk.' + key + ' must be a positive integer')
    if not 256 <= result['size_mb'] <= 65536 or result['max_total_mb'] >= result['size_mb'] - 64:
        raise ValueError('Evidence disk needs at least 64 MB of filesystem headroom')
    if not isinstance(result['guest_paths'], list) or len(result['guest_paths']) > result['max_files']:
        raise ValueError('evidence_disk.guest_paths must be a bounded file list')
    for path in result['guest_paths']:
        if not local_guest_path(path):
            raise ValueError('Evidence sources must be absolute Guest local file paths')
    result['guest_paths'] = [str(PureWindowsPath(path)) for path in result['guest_paths']]
    return result


# UNC・デバイス・代替データストリームを証拠ファイル指定として受け付けない。
def local_guest_path(value):
    return (isinstance(value, str) and bool(re.match(r'^[A-Za-z]:[\\/]', value))
            and ':' not in value[2:] and '\x00' not in value
            and '..' not in PureWindowsPath(value).parts)


# SysmonのProcessGuidで子孫を辿り、生成ファイルと子の実行イメージを候補にする。
def discover_files(log, sample, limit):
    log = Path(log)
    if not log.is_file():
        return [], ['Sysmon JSONL is unavailable; only configured files are collected']
    processes, roots = {}, set()
    with log.open(encoding='utf-8') as stream:
        for line in stream:
            event = json.loads(line)
            data = event.get('data', {})
            if str(event.get('event_id')) == '1' and data.get('ProcessGuid'):
                processes[data['ProcessGuid']] = data
                if str(PureWindowsPath(str(data.get('Image', '')))).lower() == str(PureWindowsPath(sample)).lower():
                    roots.add(data['ProcessGuid'])
    related = set(roots)
    while True:
        additions = {guid for guid, data in processes.items() if data.get('ParentProcessGuid') in related}
        if additions <= related:
            break
        related.update(additions)
    candidates = {}
    # ファイル名はGuestへ渡すデータとして扱い、Host側で開かない。
    with log.open(encoding='utf-8') as stream:
        for line in stream:
            event = json.loads(line)
            data = event.get('data', {})
            if data.get('ProcessGuid') not in related:
                continue
            kind = str(event.get('event_id'))
            path = data.get('Image') if kind == '1' else data.get('TargetFilename') if kind == '11' else None
            if not local_guest_path(path) or path.lower() == sample.lower():
                continue
            key = path.lower()
            if key not in candidates and len(candidates) >= limit:
                return list(candidates.values()), ['Candidate limit reached; collection is incomplete']
            candidates.setdefault(key, {'source': path, 'process_guid': data.get('ProcessGuid'),
                'event_id': kind, 'utc': event.get('utc'), 'reason': 'sysmon'})
    return list(candidates.values()), ([] if roots else ['Sample ProcessGuid was not found in Sysmon'])


class EvidenceDisk:
    # 製品のvmrunラッパーとGuest転送を借り、認証情報を別ファイルへ保存しない。
    def __init__(self, session, directory, settings):
        self.session = session
        self.settings = parse_settings(settings)
        self.directory = Path(directory).resolve()
        self.id = uuid.uuid4().hex
        self.path = self.directory / 'evidence.vmdk'
        self.state = {'id': self.id, 'disk': str(self.path), 'phase': 'new', 'settings': self.settings}
        self.items = []

    # 終了処理の再開でも、同じ証拠ディスクだけを識別して切り離せるようにする。
    @classmethod
    def resume(cls, session, state_path):
        state_path = Path(state_path).resolve()
        state = json.loads(state_path.read_text(encoding='utf-8'))
        instance = cls(session, state_path.parent, state['settings'])
        if Path(state['disk']).resolve() != instance.path or uuid.UUID(state['id']).hex != state['id']:
            raise ValueError('Evidence disk recovery identity mismatch')
        instance.id, instance.state = state['id'], state
        instance.items = state.get('items', [])
        return instance

    # 中断時に保存先と最後に確認できた段階を調べられるよう原子的に記録する。
    def save(self, **values):
        self.state.update(values)
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self.directory / 'state.tmp'
        temporary.write_text(json.dumps(self.state, ensure_ascii=False, indent=2), encoding='utf-8')
        temporary.replace(self.directory / 'state.json')

    # 稼働中VMの構成を編集せず、空きスロットへの接続だけを許可する。
    def attach(self):
        session = self.session
        vmx = Path(session.config['vmx_path'])
        if str(vmx).lower() in session.vmrun('list')['output'].lower():
            raise RuntimeError('Evidence disk attachment requires a stopped VM')
        raw = vmx.read_bytes()
        text = raw.decode('utf-8')
        if re.search(r'^\s*sata0:2\.', text, re.M | re.I):
            raise RuntimeError('Evidence disk SATA slot 0:2 is occupied')
        if not re.search(r'^\s*sata0.present\s*=\s*"TRUE"', text, re.M | re.I):
            raise RuntimeError('Evidence disk requires the existing SATA controller')
        slot = re.search(r'^\s*sata0.pciSlotNumber\s*=\s*"(\d+)"', text, re.M | re.I)
        if slot is None:
            raise RuntimeError('Evidence SATA controller has no identifiable PCI slot')
        if any(c in str(self.path) for c in '"\r\n') or not self.path.is_file():
            raise RuntimeError('Invalid evidence disk path')
        self.save(phase='attaching', pci_slot=int(slot[1]))
        addition = ('\nsata0:2.present = "TRUE"\nsata0:2.deviceType = "disk"\n'
                    'sata0:2.mode = "independent-persistent"\nsata0:2.fileName = "'
                    + str(self.path) + '"\n')
        vmx.write_bytes(raw + addition.encode('utf-8'))
        self.save(phase='attached', attached=True)

    # 各解析に空ディスクを作り、前回の検体データを次の解析へ混ぜない。
    def create(self):
        self.directory.mkdir(parents=True, exist_ok=False)
        manager = Path(self.session.config['vmrun_path']).with_name('vmware-vdiskmanager.exe')
        result = subprocess.run([str(manager), '-c', '-s', str(self.settings['size_mb']) + 'MB',
            '-a', 'lsilogic', '-t', '0', str(self.path)], capture_output=True, timeout=120,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if result.returncode:
            raise RuntimeError('Evidence disk creation failed: ' + str(result.returncode))
        self.save(phase='created')
        self.attach()

    # 固定管理スクリプトをGuestで動かし、要求ID付きJSONだけをHostへ回収する。
    def guest_phase(self, phase, **values):
        token = uuid.uuid4().hex
        remote = r'C:\Users\Public\r_AKanaly_evidence_' + token
        request = dict(values, phase=phase, id=self.id, request_id=token,
                       settings=self.settings, unique_id=self.state.get('unique_id'), pci_slot=self.state['pci_slot'])
        local = self.directory / (phase + '-request.json')
        local.write_text(json.dumps(request), encoding='utf-8')
        script = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent)) / 'VMWARE_GUEST_CONTROL_PACKAGE/guest/evidence_disk.ps1'
        self.session.guest('copyFileFromHostToGuest', str(script), remote + '.ps1')
        self.session.guest('copyFileFromHostToGuest', str(local), remote + '.json')
        previous_timeout = self.session.config.get('vmrun_timeout_seconds', 120)
        try:
            # 複数ファイルの照合時間を通常の短いvmrunタイムアウトと分ける。
            self.session.config['vmrun_timeout_seconds'] = 900
            self.session.program(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', remote + '.ps1',
                 '-RequestPath', remote + '.json', '-ResponsePath', remote + '-result.json'])
        finally:
            self.session.config['vmrun_timeout_seconds'] = previous_timeout
        target = self.directory / (phase + '-result.json')
        self.session.guest('copyFileFromGuestToHost', remote + '-result.json', str(target))
        result = json.loads(target.read_text(encoding='utf-8-sig'))
        if result.get('request_id') != token or result.get('id') != self.id or not result.get('success'):
            raise RuntimeError('Evidence disk Guest operation failed: ' + str(result))
        return result

    # 初回のみRAWの専用ディスクを初期化し、以後は取得したUniqueIdで照合する。
    def initialize(self):
        result = self.guest_phase('initialize')
        if result.get('protected') is not True:
            raise RuntimeError('Evidence disk is not protected before sample execution')
        self.save(phase='initialized', unique_id=result['unique_id'])

    # 生ログのHost変換後に候補だけ送り、ファイル本体のコピーはGuest内で完結する。
    def collect(self, log, sample):
        try:
            self._collect(log, sample)
            return True
        except Exception as error:
            # 原本ログは既に回収済み。成果物の欠損を明示し、静的解析へ引き継ぐ。
            self.items = []
            self.save(phase='collection_failed', collection_failed=True, items=[], complete=False,
                      warnings=['Dynamic artifact collection failed: ' + str(error)],
                      error=str(error))
            return False

    # 候補抽出とGuest回収を行い、失敗の扱いはcollectに集約する。
    def _collect(self, log, sample):
        configured = [{'source': path, 'reason': 'configured'} for path in self.settings['guest_paths']]
        discovered, warnings = discover_files(log, sample, self.settings['max_files'])
        sources = {item['source'].lower(): item for item in configured + discovered}
        if len(sources) > self.settings['max_files']:
            warnings.append('Combined candidate limit reached')
        sources = list(sources.values())[:self.settings['max_files']]
        result = self.guest_phase('collect', sources=sources)
        self.items = result['items']
        self.save(phase='collected', items=self.items, warnings=warnings,
                  complete=not warnings and all(item.get('status') == 'saved' for item in self.items))

    # 復元後は読み取り専用化して照合し、Ghidra用コピーだけを静的OSディスクへ作る。
    def import_static(self, root):
        if self.state.get('collection_failed'):
            return []
        result = self.guest_phase('import', items=self.items, destination=root + '\\evidence\\' + self.id)
        self.items = result['items']
        self.save(phase='imported', items=self.items, disk_read_only=True)
        return self.items

    # 所有している接続だけを外す。証拠VMDK本体は解析フォルダへ残す。
    def detach(self):
        vmx = Path(self.session.config['vmx_path'])
        if str(vmx).lower() in self.session.vmrun('list')['output'].lower():
            raise RuntimeError('Evidence disk detachment requires a stopped VM')
        text = vmx.read_text(encoding='utf-8')
        match = re.search(r'^\s*sata0:2.fileName\s*=\s*"([^"\r\n]+)"', text, re.M | re.I)
        if match is None:
            return
        if Path(match[1]).resolve() != self.path:
            raise RuntimeError('Evidence disk slot belongs to another disk')
        text = re.sub(r'^\s*sata0:2\.[^\r\n]*(?:\r?\n|$)', '', text, flags=re.M | re.I)
        vmx.write_text(text, encoding='utf-8')
        self.save(attached=False)
