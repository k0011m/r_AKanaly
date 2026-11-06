"""製品のHook・MCP設定を再利用し、動的調査ターンを時間制限付きで実行する。"""
from vmrun_errors import error_details
import json
from pathlib import Path
import queue
import threading
import time
import llm_operate as llm
import tui_runtime


# SDKの待機とHost監視を分離し、応答停止時も観測終了・原本回収へ進める。
def bounded_turn(codex, thread, prompt, seconds, session=None):
    from openai_codex import Sandbox
    outcome = queue.Queue(maxsize=1)
    handles = []

    # turn作成自体の待機にもHostの制限時間を適用する。
    def consume():
        try:
            turn = thread.turn(prompt, sandbox=Sandbox.read_only, approval_mode=llm.handle_codex_approval())
            handles.append(turn)
            if session is None:
                from session_progress import consume_turn
                result = consume_turn(turn, '動的解析 / Codex 準備')
            else:
                from session_progress import consume_turn
                result = consume_turn(turn, '動的解析 / Codex', session.dynamic.output / 'dynamic_session.jsonl')
            outcome.put((True, result))
        except Exception as error:
            outcome.put((False, error))

    worker = threading.Thread(target=consume, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + max(0.1, seconds)
        notified = set()
        while True:
            try:
                ok, value = outcome.get(timeout=min(1, max(0.01, deadline - time.monotonic())))
                break
            except queue.Empty:
                recovery = getattr(getattr(session, 'dynamic', None), 'recovery', None)
                if recovery and recovery.settings['ai_review_enabled']:
                    events = recovery.status(getattr(session, 'recovery_seen_sequence', 0))['events']
                    actionable = [e for e in events if e['kind'] in ('observation_restored', 'restart_limit', 'guest_timeout', 'restore_timeout', 'total_limit', 'power_on_failed', 'power_on_timeout', 'shutdown_not_completed')]
                    if actionable and actionable[-1]['sequence'] not in notified and handles:
                        notified.add(actionable[-1]['sequence'])
                        session.recovery_seen_sequence = actionable[-1]['sequence']
                        # 同じthreadへ並行turnを作らず、現在turnを中断して根拠付きの次turnへ渡す。
                        session.lifecycle_interrupted = True
                        threading.Thread(target=handles[0].interrupt, daemon=True).start()
                if time.monotonic() >= deadline:
                    raise
    except queue.Empty:
        if session is not None:
            session.closed = True
        if handles:
            threading.Thread(target=handles[0].interrupt, daemon=True).start()
        codex.close()
        worker.join(timeout=5)
        raise TimeoutError('Dynamic Codex turn exceeded its time budget') from None
    if not ok:
        if session is not None and getattr(session, 'lifecycle_interrupted', False):
            from types import SimpleNamespace
            return SimpleNamespace(final_response='Host lifecycle notification interrupted this turn; action outcomes may be unknown.')
        raise value
    return value


# 同じ承認済みPJを使い、Host保護を維持したままGuest専用の動的ツールだけを許可する。
def investigate(session, settings, developer, preparation, guard_settings):
    metadata = {'success': False, 'thread_id': None, 'hook_verified': False, 'error': None}
    target = session.dynamic.output
    try:
        project = llm.activate_prepared_project(preparation, True)
        layout = llm.create_project_layout(project)
        source = session.source.resolve()
        llm.copy_security_templates(layout, source, guard_settings)
        tools = ('guest_analysis_request',)
        guard = llm.render_guard_settings(layout, source, guard_settings, tools)
        hook = llm.render_project_hooks(layout, guard)
        llm.render_vm_codex_config(layout, session, settings)
        llm.run_guard_self_tests(layout['hooks'] / 'malware_guard.py', guard, source, tools)
        Codex = llm.load_codex_class()
        runtime = llm.inspect_application_codex_runtime(developer,
            timeout_seconds=settings.timeouts.codex_runtime_check_seconds, model=settings.model,
            reasoning_effort=settings.reasoning_effort)
        if runtime.hooks_status != 'supported':
            raise RuntimeError(llm.format_runtime_compatibility_error(runtime))
        llm.validate_generated_rules(runtime.path, layout['rules'] / 'malware_guard.rules', source,
                                     timeout_seconds=settings.timeouts.rules_validation_seconds)
        llm.run_session_hook_preflight(layout['hooks'] / 'malware_guard.py', hook,
                                      timeout_seconds=settings.timeouts.hook_preflight_seconds)
        from openai_codex import Sandbox
        with Codex(llm.build_codex_config(developer, runtime.path, project, settings.model, settings.reasoning_effort)) as codex:
            llm.verify_sdk_runtime_match(runtime, llm.collect_sdk_runtime_metadata(codex))
            hook.marker_path.unlink(missing_ok=True)
            hook.diagnostics_path.unlink(missing_ok=True)
            llm.write_hook_run_context(hook)
            start = time.time()
            thread = codex.thread_start(cwd=str(project), sandbox=Sandbox.read_only,
                                        approval_mode=llm.handle_codex_approval(), model=settings.model)
            metadata['thread_id'] = llm.get_thread_id(thread)
            if not llm.hook_marker_matches(hook, start):
                initial = bounded_turn(codex, thread, llm.HOOK_INITIALIZATION_PROMPT,
                                       settings.timeouts.mcp_startup_seconds)
                llm.verify_initialization_turn(initial)
            metadata['hook_verification'] = llm.verify_hook_marker(hook, start,
                timeout_seconds=settings.timeouts.hook_marker_seconds,
                poll_interval_seconds=settings.timeouts.hook_poll_interval_seconds,
                runtime_stderr=llm.get_codex_diagnostic_stderr(codex))
            metadata['hook_verified'] = True
            from dynamic_prompt import default_instructions, review_prompt, select_reviewed
            selection = {'source': 'default', 'reason': '標準指示を使用'}
            if session.instructions != default_instructions():
                tui_runtime.set_status('動的解析の指示を理解できるか確認しています')
                session.reviewing_instructions = True
                try:
                    reviewed = bounded_turn(codex, thread, review_prompt(session.instructions),
                                            settings.timeouts.mcp_startup_seconds)
                    llm.verify_initialization_turn(reviewed)
                    session.instructions, selection = select_reviewed(session.instructions,
                        str(getattr(reviewed, 'final_response', '') or ''))
                finally:
                    session.reviewing_instructions = False
            metadata['instruction_selection'] = selection
            (target / 'dynamic_instruction_selection.json').write_text(
                json.dumps(selection, ensure_ascii=False, indent=2), encoding='utf-8')
            prompt = session.prompt(settings.language)
            (target / 'dynamic_prompt.md').write_text(prompt, encoding='utf-8')
            session.begin()
            tui_runtime.set_stage('動的解析', 'CodexがGuest画面・プロセスを確認しながら調査しています')
            result = bounded_turn(codex, thread, prompt, session.deadline - time.monotonic(), session)
            from dynamic_followup import review_prompt
            recovery = getattr(session.dynamic, 'recovery', None)
            reviewed = 0
            last_sequence = 0
            while recovery and recovery.settings['ai_review_enabled'] and reviewed < recovery.settings['max_reviews']:
                # Codexの終了が先でも、Hostの復帰中に終了回収へ突入しない。
                while recovery.state not in ('ready', 'diagnosis') and time.monotonic() < recovery.deadline:
                    time.sleep(0.5)
                state = recovery.status(last_sequence)
                followup = session.review_request
                if followup and followup['mode'] not in ('continue', 'extend'):
                    break
                if not state['events'] and followup is None:
                    break
                reviewed += 1
                last_sequence = state['sequence']
                session.recovery_seen_sequence = last_sequence
                remaining = recovery.deadline - time.monotonic()
                if remaining <= 0:
                    break
                if followup and followup['mode'] in ('continue', 'extend'):
                    recovery.resume_observation()
                session.completion = None
                session.lifecycle_interrupted = False
                session.review_request = None
                duration = min(remaining, followup['seconds'] if followup else 300)
                session.deadline = time.monotonic() + duration
                result = bounded_turn(codex, thread, review_prompt(state), duration, session)
            metadata['recovery_reviews'] = reviewed
            metadata['followup'] = session.review_request
            if session.review_request:
                (target / 'followup_request.json').write_text(json.dumps(session.review_request, ensure_ascii=False, indent=2), encoding='utf-8')
            (target / 'dynamic_summary.md').write_text(str(getattr(result, 'final_response', '') or ''), encoding='utf-8')
            if session.completion is None:
                raise RuntimeError('Codex returned without finish_investigation; evidence retained as partial')
            metadata['success'] = True
    except Exception as error:
        metadata['error'] = str(error)
        metadata['error_details'] = error_details(error)
        # LLM障害を動的挙動なしと解釈せず、後続解析へ欠損として渡す。
        summary_path = target / 'dynamic_summary.md'
        partial = summary_path.read_text(encoding='utf-8') if summary_path.exists() else ''
        summary_path.write_text('動的LLM調査は未完了です。\n\n' + str(error) + '\n\n' + partial, encoding='utf-8')
    finally:
        (target / 'dynamic_llm.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding='utf-8')
        session.finalize(metadata['error'], failure_details=metadata.get('error_details'))
    try:
        result = session.dynamic.collect()
    except Exception as error:
        if getattr(session.dynamic, 'recovery', None) is None:
            raise
        return session.dynamic.partial_result(error)
    if session.review_request and session.review_request['mode'] in ('safe_mode', 'offline'):
        session.dynamic.preserve_for_followup(session.review_request)
    return result
