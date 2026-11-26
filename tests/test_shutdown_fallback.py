"""解析VMの正常停止失敗時の電源断と停止確認を検証する。"""
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
from deployment.vm import VMware
import r_akanaly

class ShutdownFallbackTests(unittest.TestCase):
    # 正常停止できる場合には強制停止を送らない。
    def test_static_soft_success(self):
        vm=VMware('vmrun','vm.vmx','user','password')
        vm.running=Mock(side_effect=[True,False]); vm.run=Mock()
        vm.shutdown(force_on_failure=True)
        vm.run.assert_called_once_with('stop','vm.vmx','soft')

    # タイムアウト後だけ電源断し、停止確認できれば成功する。
    def test_static_hard_success(self):
        vm=VMware('vmrun','vm.vmx','user','password')
        vm.running=Mock(side_effect=[True,True,False]); vm.run=Mock()
        with patch('deployment.vm.time.monotonic',side_effect=[0,181]):
            vm.shutdown(force_on_failure=True)
        self.assertEqual(vm.run.call_args_list[-1].args,('stop','vm.vmx','hard'))

    # Setupでは従来通り強制停止せずに失敗を返す。
    def test_setup_no_hard(self):
        vm=VMware('vmrun','vm.vmx','user','password')
        vm.running=Mock(return_value=True); vm.run=Mock()
        with patch('deployment.vm.time.monotonic',side_effect=[0,181]):
            with self.assertRaisesRegex(RuntimeError,'timed out'): vm.shutdown()
        vm.run.assert_called_once_with('stop','vm.vmx','soft')

    # 動的解析の停止は正常待機後にhardへ切り替え、停止確認を必須にする。
    def test_dynamic_hard_success(self):
        settings=SimpleNamespace(vmx_path='vm.vmx',vmrun_type='ws')
        commands=[]
        def run(command,**kwargs):
            commands.append(list(command)); return SimpleNamespace(returncode=0)
        with patch.object(r_akanaly,'get_vmrun_command',return_value='vmrun'), patch.object(r_akanaly,'validate_vmx_path',return_value='vm.vmx'), patch.object(r_akanaly,'run_command_capture_text',side_effect=run), patch.object(r_akanaly,'is_virtual_machine_running',side_effect=[True]*61+[False]), patch.object(r_akanaly.time,'sleep'):
            r_akanaly.shutdown_virtual_machine(settings,None,False)
        self.assertEqual([c[-1] for c in commands],['soft','hard'])

    # hard成功応答でもVMが残っていれば後続へ進めない。
    def test_static_hard_still_running(self):
        vm=VMware('vmrun','vm.vmx','user','password')
        vm.running=Mock(return_value=True); vm.run=Mock()
        with patch('deployment.vm.time.monotonic',side_effect=[0,181]), patch('deployment.vm.time.sleep'):
            with self.assertRaisesRegex(RuntimeError,'could not be confirmed'): vm.shutdown(force_on_failure=True)
