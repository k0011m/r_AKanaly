"""Guestの読取り専用確認が返した証拠をHostで検証する。"""

FIELDS = ('RealTimeProtectionEnabled', 'BehaviorMonitorEnabled',
          'IoavProtectionEnabled', 'IsTamperProtected')


# 設定値や成功フラグだけに依存せず、型・対象OS・連続観測を照合する。
def valid_group_policy_evidence(result):
    if not isinstance(result, dict):
        return False
    platform = result.get('platform')
    checks = result.get('checks')
    if (result.get('strategy') != 'group_policy_v1'
            or result.get('policy_version') != 3
            or result.get('success') is not True
            or result.get('apply_requested') is not False
            or result.get('bypass') is not False
            or type(result.get('stable_checks')) is not int
            or result['stable_checks'] < 2
            or not isinstance(platform, dict)
            or not str(platform.get('edition', '')).startswith('Professional')
            or platform.get('gpedit_available') is not True
            or not isinstance(checks, list) or len(checks) < 2):
        return False
    return all(isinstance(entry, dict)
               and entry.get('AMRunningMode') in ('Normal', 'Not running')
               and all(entry.get(field) is False for field in FIELDS)
               for entry in checks[-2:])
