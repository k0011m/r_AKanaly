# r_AKanaly 0.1.12

解析VMの正常シャットダウンが完了しない場合、強制パワーオフへ切り替え、停止を確認してから後続処理へ進みます。Setupの既定動作は強制停止しません。未保存のGuestデータは失われる可能性があります。

対象：r_akanaly.shutdown_virtual_machine、deployment.vm.VMware.shutdown、vm_analysis.VmAnalysisSession.finish。
ログ回収失敗時の別経路は今回変更していません。実VMの強制停止試験は未実施です。

## English
Analysis shutdown now falls back to hard power-off when graceful shutdown does not complete, and verifies the VM is stopped before continuing. Setup retains its graceful-only default. Unsaved Guest data may be lost. The separate log-collection failure path is unchanged. Real-VM forced shutdown was not tested.
