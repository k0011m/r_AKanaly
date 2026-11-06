"""同じワーカー上でPyGhidraのプロジェクトを保持する実験用操作。"""
import os
from contextlib import ExitStack
from pathlib import Path


class GhidraOperations:
    # JVMは最初の解析要求時に起動し、health受付をブロックしない。
    def __init__(self, environment, projects):
        self.environment, self.projects = environment, Path(projects)
        self.stack = None
        self.program = None
        self.project = None

    # 公開操作は静的照会と保存に限定し、任意スクリプトを受け付けない。
    def __call__(self, request):
        action = request['action']
        if action == 'open':
            return self.open(request)
        if self.program is not None and request['analysis_id'] != self.analysis_id:
            raise ValueError('Analysis ID does not own this project')
        if action == 'save_close':
            return self.close()
        # 子成果物へ切り替えた照会を、前に開いた検体の結果として返さない。
        if self.program is not None and request.get('project', self.project) != self.project:
            self.open(request)
        if self.program is None:
            raise RuntimeError('No program is open')
        if action in ('symbols', 'imports', 'strings', 'references', 'callers', 'callees', 'disassemble', 'memory'):
            return self.query(request)
        if action == 'functions':
            offset = max(0, int(request.get('offset', 0)))
            limit = min(500, max(1, int(request.get('limit', 50))))
            values = []
            for index, function in enumerate(self.program.getFunctionManager().getFunctions(True)):
                if index < offset:
                    continue
                if len(values) == limit:
                    break
                values.append({'name': str(function.getName()), 'address': str(function.getEntryPoint()),
                               'external': bool(function.isExternal()), 'thunk': bool(function.isThunk())})
            return {'items': values, 'offset': offset, 'total': self.program.getFunctionManager().getFunctionCount()}
        if action == 'decompile':
            from ghidra.app.decompiler import DecompInterface
            address = self.program.getAddressFactory().getAddress(request['address'])
            function = self.program.getFunctionManager().getFunctionAt(address)
            if function is None:
                raise ValueError('Function not found')
            decompiler = DecompInterface()
            try:
                if not decompiler.openProgram(self.program):
                    raise RuntimeError('Cannot open decompiler')
                result = decompiler.decompileFunction(function, 30, self.pyghidra.task_monitor(35))
                if not result.decompileCompleted():
                    raise RuntimeError(str(result.getErrorMessage()))
                return {'address': str(address), 'text': str(result.getDecompiledFunction().getC())}
            finally:
                decompiler.dispose()
        raise ValueError('Unsupported static operation: ' + action)

    # Ghidraの読取APIをページ化し、大きな結果を一度にHostへ送らない。
    def query(self, request):
        action = request['action']
        offset = max(0, int(request.get('offset', 0)))
        limit = min(500, max(1, int(request.get('limit', 100))))
        query = str(request.get('query', '')).casefold()
        p = self.program
        address = p.getAddressFactory().getAddress(request.get('address', ''))
        if action in ('references', 'callers', 'callees', 'disassemble') and address is None:
            raise ValueError('Valid address required')
        rows = []
        if action == 'memory':
            rows = [{'name': str(b.getName()), 'start': str(b.getStart()), 'end': str(b.getEnd()),
                     'size': int(b.getSize()), 'read': bool(b.isRead()), 'write': bool(b.isWrite()),
                     'execute': bool(b.isExecute())} for b in p.getMemory().getBlocks()]
        elif action in ('symbols', 'imports'):
            for s in p.getSymbolTable().getAllSymbols(True):
                if action == 'imports' and not s.isExternal():
                    continue
                if query and query not in str(s.getName()).casefold():
                    continue
                rows.append({'name': str(s.getName(True)), 'address': str(s.getAddress()), 'type': str(s.getSymbolType())})
        elif action == 'strings':
            from ghidra.program.model.data import StringDataInstance
            for data in p.getListing().getDefinedData(True):
                instance = StringDataInstance.getStringDataInstance(data)
                if instance is None or instance.getStringValue() is None:
                    continue
                value = str(instance.getStringValue())
                if not query or query in value.casefold():
                    rows.append({'address': str(data.getAddress()), 'text': value})
        elif action == 'references':
            refs = (p.getReferenceManager().getReferencesFrom(address) if request.get('direction') == 'from'
                    else p.getReferenceManager().getReferencesTo(address))
            rows = [{'from': str(r.getFromAddress()), 'to': str(r.getToAddress()), 'type': str(r.getReferenceType())} for r in refs]
        elif action in ('callers', 'callees'):
            f = p.getFunctionManager().getFunctionContaining(address)
            if f is None:
                raise ValueError('Function not found')
            monitor = self.pyghidra.task_monitor(30)
            functions = f.getCallingFunctions(monitor) if action == 'callers' else f.getCalledFunctions(monitor)
            rows = sorted([{'name': str(x.getName()), 'address': str(x.getEntryPoint())} for x in functions], key=lambda x: x['address'])
        else:
            # 逆アセンブルは指定開始位置から必要なページだけを走査する。
            for index, instruction in enumerate(p.getListing().getInstructions(address, True)):
                if index >= offset + limit + 1:
                    break
                rows.append({'address': str(instruction.getAddress()), 'text': str(instruction)})
        return {'items': rows[offset:offset + limit], 'offset': offset,
                'has_more': len(rows) > offset + limit, 'total': None if action == 'disassemble' else len(rows)}

    # 新規importと既存プロジェクトの再オープンを明示的に分ける。
    def open(self, request):
        if self.stack is not None:
            if request['analysis_id'] != self.analysis_id:
                raise ValueError('Analysis ID does not own this project')
            if request['project'] == self.project:
                return {'project': self.project, 'reopened': True,
                        'function_count': self.program.getFunctionManager().getFunctionCount()}
            self.close()
        name = request['project']
        if not name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in name):
            raise ValueError('Invalid project name')
        os.environ['JAVA_HOME'] = self.environment['java_home']
        os.environ['GHIDRA_INSTALL_DIR'] = self.environment['ghidra_home']
        import pyghidra
        self.pyghidra = pyghidra
        pyghidra.start()
        from java.io import File
        self.projects.mkdir(parents=True, exist_ok=True)
        stack = ExitStack()
        try:
            create = not request.get('reopen', False) and not (self.projects / (name + '.gpr')).exists()
            project = stack.enter_context(pyghidra.open_project(self.projects, name, create=create))
            target = Path(request['sample_path'])
            if create:
                loader = pyghidra.program_loader().project(project).source(File(str(target)))
                with loader.load() as loaded:
                    loaded.save(pyghidra.task_monitor())
            program = stack.enter_context(pyghidra.program_context(project, '/' + target.name))
            if create:
                pyghidra.analyze(program, pyghidra.task_monitor(300))
            self.stack, self.program, self.project = stack, program, name
            self.analysis_id = request['analysis_id']
            return {'project': name, 'function_count': program.getFunctionManager().getFunctionCount(), 'reopened': not create}
        except Exception:
            stack.close()
            raise

    # 保存成功後にProgramとProjectのコンテキストを閉じる。
    def close(self):
        if self.stack is None:
            if self.project is not None:
                return {'project': self.project, 'saved': True, 'closed': True}
            raise RuntimeError('No project to save')
        self.program.save('r_AKanaly resident analysis', self.pyghidra.task_monitor())
        self.stack.close()
        self.stack, self.program = None, None
        return {'project': self.project, 'saved': True, 'closed': True}
