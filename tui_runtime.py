from __future__ import annotations

from typing import Protocol


STAGES = (
    "表層解析",
    "VMセッティング",
    "動的解析",
    "ログ回収",
    "LLM立ち上げ",
    "LLM解析",
    "レポート化",
    "終了",
)


class TuiBridge(Protocol):
    def set_stage(self, stage: str, message: str) -> None: ...

    def set_status(self, message: str) -> None: ...

    # 工程説明を残して同じパネルへ公開セッション進捗を表示する。
    def set_session_progress(self, phase: str, message: str) -> None: ...

    def set_sample_progress(self, index: int, total: int, filename: str) -> None: ...

    def read_input(self, prompt: str, secret: bool = False) -> str: ...

    def show_error(self, message: str) -> None: ...

    def set_confirmation(self, items: list[tuple[str, str]]) -> None: ...

    def set_outputs(self, items: list[tuple[str, str]]) -> None: ...


_ACTIVE_BRIDGE: TuiBridge | None = None
STAGE_RESULTS: dict[str, dict[str, str]] = {}
RESULT_LABELS = {'pending': '未実行', 'running': '処理中', 'success': '成功',
                 'partial': '一部未完了', 'failed': '失敗', 'cancelled': '中断'}


# 前回実行の結果を次回へ持ち越さず、実際の完了通知だけで成功を記録する。
def reset_results() -> None:
    import token_usage
    token_usage.reset()
    STAGE_RESULTS.clear()
    STAGE_RESULTS.update({name: {'state': 'pending', 'detail': ''} for name in STAGES})


# 各処理が確認した結果を保存し、画面と最終JSONで共用する。
def record_result(stage: str, state: str, detail: str = '', error_details=None) -> None:
    if not STAGE_RESULTS:
        reset_results()
    STAGE_RESULTS[stage] = {'state': state, 'detail': detail}
    if error_details is not None:
        STAGE_RESULTS[stage]['error_details'] = error_details


# エラーや取消時は実行中の項目だけ閉じ、未実行を成功へ変えない。
def close_running(state: str, detail: str, error_details=None) -> None:
    for name, result in STAGE_RESULTS.items():
        if result['state'] == 'running':
            record_result(name, state, detail, error_details)


# 実行中は工程のみ返し、終了表示の呼出しだけ合計使用量を含める。
def result_items(*, include_usage: bool = False) -> list[tuple[str, str]]:
    import token_usage
    return [(name, RESULT_LABELS[value['state']] + (': ' + value['detail'] if value['detail'] else ''))
            for name, value in STAGE_RESULTS.items()] + (token_usage.current.items() if include_usage else [])


# 実行中だけTUIブリッジを登録し、通常CLIでは既存動作へフォールバックさせます。
def set_active_bridge(bridge: TuiBridge | None) -> None:
    global _ACTIVE_BRIDGE
    _ACTIVE_BRIDGE = bridge


# 現在の解析段階と置換表示する状態メッセージをTUIへ通知します。
def set_stage(stage: str, message: str) -> None:
    if not STAGE_RESULTS:
        reset_results()
    if stage in STAGE_RESULTS and STAGE_RESULTS[stage]['state'] == 'pending':
        record_result(stage, 'running', message)
    if _ACTIVE_BRIDGE is not None:
        _ACTIVE_BRIDGE.set_stage(stage, message)


# 詳細処理の最新メッセージだけをTUIへ通知します。
def set_status(message: str) -> None:
    if _ACTIVE_BRIDGE is not None:
        _ACTIVE_BRIDGE.set_status(message)


# 工程の説明と独立したセッション進捗を、同じ現在処理パネルへ渡す。
def set_session_progress(phase: str, message: str) -> None:
    if _ACTIVE_BRIDGE is not None:
        setter = getattr(_ACTIVE_BRIDGE, 'set_session_progress', None)
        if setter:
            setter(phase, message)
        else:
            _ACTIVE_BRIDGE.set_status(phase + '\n' + message)


# 工程メッセージとは別に、現在の検体と一括処理の位置を通知する。
def set_sample_progress(index: int, total: int, filename: str) -> None:
    if _ACTIVE_BRIDGE is not None:
        _ACTIVE_BRIDGE.set_sample_progress(index, total, filename)
    elif total:
        print(f'検体進捗: {index}/{total}件目 | {filename}', flush=True)


# TUI実行中だけ入力をUIへ委譲し、通常CLIではNoneを返します。
def read_input(prompt: str, secret: bool = False) -> str | None:
    if _ACTIVE_BRIDGE is None:
        return None
    return _ACTIVE_BRIDGE.read_input(prompt, secret=secret)


# 典型エラーの説明を含むエラー画面へ切り替えます。
def show_error(message: str) -> None:
    if _ACTIVE_BRIDGE is not None:
        _ACTIVE_BRIDGE.show_error(message)


# 最終確認に必要な検体・PJ・Hook情報をTUIへまとめて渡します。
def set_confirmation(items: list[tuple[str, str]]) -> None:
    if _ACTIVE_BRIDGE is not None:
        _ACTIVE_BRIDGE.set_confirmation(items)


# 完了時に生成物と保存先の一覧をTUIへまとめて渡します。
def set_outputs(items: list[tuple[str, str]]) -> None:
    if _ACTIVE_BRIDGE is not None:
        _ACTIVE_BRIDGE.set_outputs(items)


# 呼び出し側が通常CLI表示とTUI表示を切り替えるための状態を返します。
def is_active() -> bool:
    return _ACTIVE_BRIDGE is not None
