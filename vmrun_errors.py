"""vmrunの終了情報を認証引数なしの共通形式で保持する。"""
import locale


# 生バイトを置換前に復号し、日本語出力を壊さない。
def decode_output(raw):
    if raw is None:
        return ''
    if isinstance(raw, str):
        return raw
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16', errors='replace')
    for encoding in ('utf-8-sig', locale.getpreferredencoding(False), 'cp932'):
        try:
            return raw.decode(encoding)
        except (UnicodeError, LookupError):
            continue
    return raw.decode('utf-8', errors='replace')


# 実行引数そのものを保存せず、資格情報に一致する出力だけを伏せる。
def redact(text, command):
    values = [str(command[i + 1]) for i, arg in enumerate(command[:-1]) if arg in ('-vp', '-gp', '-gu')]
    for value in sorted(set(values), key=len, reverse=True):
        if value:
            text = text.replace(value, '[REDACTED]')
    return text


# オプション値を飛ばして操作名だけを抽出し、未知の引数は記録しない。
def operation_name(command):
    known = {'list', 'start', 'stop', 'reset', 'suspend', 'pause', 'unpause', 'revertToSnapshot',
        'snapshot', 'deleteSnapshot', 'listSnapshots', 'runProgramInGuest', 'runScriptInGuest',
        'listProcessesInGuest', 'killProcessInGuest', 'copyFileFromHostToGuest', 'copyFileFromGuestToHost',
        'fileExistsInGuest', 'directoryExistsInGuest', 'deleteFileInGuest', 'createDirectoryInGuest',
        'deleteDirectoryInGuest', 'checkToolsState', 'listDirectoryInGuest'}
    index = 1
    while index < len(command):
        if command[index] in ('-T', '-vp', '-gu', '-gp', '-h', '-P', '-u', '-p'):
            index += 2
            continue
        return command[index] if command[index] in known else 'unknown'
    return 'unknown'


class VmrunError(RuntimeError):
    # 終了コードはプロセス終了値として保持し、VIXの詳細コードとは混同しない。
    def __init__(self, returncode, output='', *, operation='unknown', stderr='', timed_out=False):
        self.returncode, self.output = returncode, output
        self.operation, self.stderr, self.timed_out = operation, stderr, timed_out
        super().__init__(f'vmrun {operation} failed ({returncode}): ' +
                         ('timed out' if timed_out else (stderr.strip() or output.strip())))

    # ログ・MCP共通の、JSONへ直接保存できる失敗情報を返す。
    def as_dict(self):
        return {'operation': self.operation, 'returncode': self.returncode,
                'stdout': self.output, 'stderr': self.stderr, 'timed_out': self.timed_out}


# 呼出し側の出力復号状態にかかわらず、例外に秘密を含めない。
def from_result(command, result):
    return VmrunError(result.returncode, redact(decode_output(result.stdout), command),
        operation=operation_name(command), stderr=redact(decode_output(result.stderr), command))


class ErrorContext(RuntimeError):
    # 複数工程の失敗や遠隔応答を文字列に潰さず、上位へ引き継ぐ。
    def __init__(self, message, *causes, details=None):
        super().__init__(message)
        self.causes = causes
        self.error_details = details


# 既存の表示文を維持しながら、原因チェーンのvmrun情報を独立項目へ集約する。
def error_details(error):
    entries, seen = [], set()
    # 同一例外を二重計上せず、秘密付き標準例外の抑制されたcontextも辿らない。
    def visit(item):
        if item is None or id(item) in seen:
            return
        seen.add(id(item))
        if isinstance(item, VmrunError):
            entries.append(item.as_dict())
        saved = getattr(item, 'error_details', None)
        if isinstance(saved, dict):
            entries.extend(saved.get('vmrun_errors', []))
        for cause in getattr(item, 'causes', ()):
            visit(cause)
        visit(item.__cause__)
        if not item.__suppress_context__:
            visit(item.__context__)
    visit(error)
    return {'type': type(error).__name__, 'message': str(error), 'vmrun_errors': entries}
