"""Guestの観測対象IDを管理し、UIA処理の停止を別ワーカー内に閉じ込める。"""
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

OBSERVATIONS = {}


# UIA providerが応答しなくても常駐受付を復旧できるよう、時間制限付き子プロセスで呼ぶ。
def worker(payload):
    with tempfile.TemporaryDirectory(prefix='r_AKanaly_uia_') as directory:
        request, response = Path(directory) / 'request.json', Path(directory) / 'response.json'
        request.write_text(json.dumps(payload), encoding='utf-8')
        completed = subprocess.run([r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(Path(__file__).with_name('uia_worker.ps1')),
            '-RequestPath', str(request), '-ResponsePath', str(response)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=12,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
        if completed.returncode:
            detail = completed.stderr.decode('utf-8', errors='replace')[:2000]
            raise RuntimeError('UIA worker startup failed (exit ' + str(completed.returncode) + '): ' + detail)
        return json.loads(response.read_text(encoding='utf-8-sig'))


# RuntimeIdをLLMへ操作権として渡さず、現在の観測・解析に束縛した不透明IDを発行する。
def operate(request):
    try:
        analysis_id = request['analysis_id']
        action = request['action']
        if action == 'ui_observe':
            handle = request.get('window_handle')
            if handle is not None and (type(handle) is not int or handle <= 0):
                raise ValueError('window_handle must be a positive integer')
            result = worker({'mode': 'observe', 'window_handle': handle})
            if result.get('status') != 'observed':
                return result
            observation = uuid.uuid4().hex
            elements, public = {}, []
            for element in result.get('elements', []):
                target_id = uuid.uuid4().hex
                elements[target_id] = element
                public.append(dict(element, target_id=target_id))
            OBSERVATIONS[observation] = {'analysis_id': analysis_id, 'generation': request.get('generation'),
                'deadline': time.monotonic() + 60, 'elements': elements}
            while len(OBSERVATIONS) > 16:
                OBSERVATIONS.pop(next(iter(OBSERVATIONS)))
            return dict(result, observation_id=observation, elements=public,
                        recovery='image_fallback' if not public else None)
        if action != 'ui_action':
            raise ValueError('Unknown UIA action')
        observation = OBSERVATIONS.get(request.get('observation_id'))
        if not observation or observation['analysis_id'] != analysis_id or observation['generation'] != request.get('generation'):
            raise ValueError('Unknown observation or generation; observe again')
        if time.monotonic() > observation['deadline']:
            raise ValueError('Observation expired; observe again')
        target = observation['elements'].get(request.get('target_id'))
        if target is None:
            raise ValueError('Unknown target ID')
        operation = request.get('operation', 'invoke')
        if operation not in ('point', 'click', 'invoke', 'set_value', 'select'):
            raise ValueError('Unsupported UIA operation')
        value = request.get('value', '')
        if not isinstance(value, str) or len(value) > 10000:
            raise ValueError('Invalid UIA value')
        if operation != 'point':
            OBSERVATIONS.clear()
        result = worker({'mode': 'action', 'target': target, 'operation': 'point' if operation == 'click' else operation, 'value': value,
                         'window_handle': target['window_handle']})
        result['requested_operation'] = operation
        result['observation_id'] = request['observation_id']
        return result
    except Exception as error:
        return {'status': 'image_fallback', 'error': type(error).__name__, 'message': str(error),
                'analysis_halt_required': False, 'recovery': 'observe_again_or_use_screen_observe'}
