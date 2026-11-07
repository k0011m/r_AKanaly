"""製品に同梱するAgentとHookの正本一覧。実験ツールをglobで取り込まない。"""
from pathlib import Path

HOOK_FILES = ('hookrules/hooks.json', 'hookrules/hooks/malware_guard.py',
              'hookrules/rules/malware_guard.rules')
GUEST_FILES = (
    'analysis_agent.py', 'analysis_archive.py', 'analysis_runtime.py', 'archive_ops.py',
    'desktop_monitor.py', 'dynamic_operations.py', 'ghidra_operations.py', 'guest_agent.py',
    'guest_agent.ps1', 'resident_agent.py', 'lifecycle_agent_launcher.py', 'production_operations.py',
    'uia_operations.py', 'uia_worker.ps1', 'login_status.ps1', 'lifecycle_monitor.ps1',
    'setup_lifecycle.ps1', 'setup_dynamic.ps1', 'dynamic_capture.ps1', 'stop_dynamic_capture.ps1',
    'sample_runner.ps1', 'defender_gate.ps1', 'defender_gate_runner.ps1', 'prepare_analysis_security.ps1',
    'finalize_dynamic_defender.ps1', 'request_dynamic_uac.ps1', 'compress_dynamic_logs.ps1',
    'evidence_disk.ps1', 'sysmon.xml', 'dynamic.wprp', 'start_analysis_agents.cmd',
    'requirements-zip.txt',
)
HOST_FILES = ('analysis_mcp_server.py', 'host_evidence.py', 'bridge_service.py', 'bridge_client.py',
              'console_input.py', 'console_lifecycle.py', 'desktop_state.py',
              'login_readiness.py', 'security_readiness.py', 'visual_controller.py')
AGENT_FILES = ('guest_protection.py',) + tuple('VMWARE_GUEST_CONTROL_PACKAGE/' + folder + '/' + name
                   for folder, names in (('guest', GUEST_FILES), ('host', HOST_FILES),
                                         ('tools', ('vm_guest_control.py',)))
                   for name in names)

# 梱包開始前に必須ファイルを照合し、欠落した配布物の作成を止める。
def require_files(root, names):
    missing = [name for name in names if not (Path(root) / name).is_file()]
    if missing:
        raise ValueError('Required product files missing: ' + ', '.join(missing))

# PyInstallerでもReleaseでも、同じ正本一覧と相対配置を使う。
def product_datas(root):
    names = AGENT_FILES + HOOK_FILES
    require_files(root, names)
    return [(str(Path(root) / name), str(Path(name).parent)) for name in names]
