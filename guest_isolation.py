"""動的解析の検体投入前と、管理用セットアップの独自LAN確認を共用する。"""
import base64
import json
import re
from pathlib import Path
import uuid


# ethernet0だけでなく、追加されたアダプターも含めて接続先を検査する。
def check_vmx(path):
    values = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'\s*([\w.]+)\s*=\s*"([^"\r\n]*)"\s*', line)
        if match:
            values[match[1].lower()] = match[2]
    adapters = []
    for key, value in values.items():
        if re.fullmatch(r'ethernet\d+\.present', key) and value.lower() == 'true':
            prefix = key.rsplit('.', 1)[0]
            mode = values.get(prefix + '.connectiontype', '').lower()
            if mode != 'pvn' or not values.get(prefix + '.pvnid'):
                raise RuntimeError('Guest isolation failed: ' + prefix + ' is not a private LAN segment')
            adapters.append({'adapter': prefix, 'connection_type': mode,
                             'segment_id': values[prefix + '.pvnid']})
    return {'adapters': adapters, 'all_adapters_private': True}


# Guest内でルート・NIC・外部到達性を読み取り、応答の使い回しをnonceで排除する。
def check_guest(vmx, guest, program, guest_directory, output):
    host = check_vmx(vmx)
    nonce = uuid.uuid4().hex
    remote = guest_directory + '\\isolation-' + nonce + '.json'
    quoted = remote.replace("'", "''")
    script = """$ErrorActionPreference='Stop'
$r=@{nonce='__NONCE__';success=$false;utc=[DateTime]::UtcNow.ToString('o')}
try {
 $r.adapters=@(Get-NetAdapter | Select-Object Name,Status,InterfaceDescription)
 $r.addresses=@(Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,AddressFamily)
 $r.default_routes=@(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') | Select-Object InterfaceAlias,DestinationPrefix,NextHop)
 $r.external_tcp_connected=$false
 $client=New-Object Net.Sockets.TcpClient
 try { $pending=$client.BeginConnect('1.1.1.1',443,$null,$null); if($pending.AsyncWaitHandle.WaitOne(1500)) { $client.EndConnect($pending); $r.external_tcp_connected=$client.Connected } }
 catch { $r.tcp_error=$_.Exception.GetType().FullName }
 finally { $client.Close() }
 $r.success=($r.default_routes.Count -eq 0 -and -not $r.external_tcp_connected)
} catch { $r.error=$_.Exception.Message }
$r | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath '__REMOTE__' -Encoding UTF8
""".replace('__NONCE__', nonce).replace('__REMOTE__', quoted)
    program(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            '-NoProfile', '-NonInteractive', '-EncodedCommand',
            base64.b64encode(script.encode('utf-16le')).decode())
    target = Path(output)
    guest('copyFileFromGuestToHost', remote, str(target))
    value = json.loads(target.read_text(encoding='utf-8-sig'))
    value['host'] = host
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    if value.get('nonce') != nonce or value.get('success') is not True:
        raise RuntimeError('Guest network isolation check failed; see ' + str(target))
    return value
