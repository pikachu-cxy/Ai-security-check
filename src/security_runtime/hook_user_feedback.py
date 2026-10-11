"""Closed user-facing Hook copy; source and scanner prose never enter messages.

These descriptions are presentation only. They cannot authorize a repair,
create a confirmation capability, or establish scanner resolution.
"""
from __future__ import annotations

import re


_TLS_HOSTNAME = (
    'HTTPS 连接没有核对服务器身份',
    '这行代码关闭了 HTTPS 主机名校验，服务器证书的域名与目标地址不匹配也会被接受。',
    '如果网络连接被劫持，攻击者可能冒充目标服务器，窃取或篡改通信内容；实际部署中的使用情况尚未确认。',
    '建议修复：删除这行绕过校验的代码，恢复默认检查，再重新检查。恢复后，证书域名不匹配的连接会被拒绝。',
)

_COPY = {
    'command-injection': (
        '外部输入可能被当成系统命令',
        '检查发现外部输入可能进入系统命令执行操作，需要核查输入是否能改变命令。',
        '如果攻击者能够控制这段输入并到达执行位置，可能在应用权限范围内执行额外命令、读取或修改数据；实际可利用性尚未确认。',
        '建议修复：先核查输入来源和命令构造方式，优先使用固定命令与独立参数，并限制允许的输入；修改后重新检查。',
    ),
    'sql-injection': (
        '外部输入可能改变数据库查询',
        '检查发现外部输入可能被拼进数据库查询，需要核查是否使用了参数绑定。',
        '如果攻击者能够控制查询输入，可能绕过查询限制、读取或修改数据库中的数据；实际可利用性尚未确认。',
        '建议修复：核查查询构造方式，使用参数化查询绑定输入；修改后重新检查。',
    ),
    'ssrf': (
        '外部输入可能控制服务器访问的地址',
        '检查发现外部输入可能进入服务器发起的网络请求，需要核查目标地址的限制。',
        '如果攻击者能控制目标地址，服务器可能被用于访问内网或受限制的服务；是否存在这样的访问路径尚未确认。',
        '建议修复：核查地址来源，限制允许的协议和目标地址，并检查重定向后的目标；修改后重新检查。',
    ),
    'xss': (
        '外部输入可能被浏览器当成代码',
        '检查发现外部输入可能进入网页输出，需要核查是否按输出位置进行了转义。',
        '如果攻击者能控制这些内容且其他用户打开相关页面，可能在这些用户的浏览器中执行脚本、读取可访问的信息或冒充其操作；实际可利用性尚未确认。',
        '建议修复：核查网页输出位置，使用对应的转义方式或安全的模板输出；修改后重新检查。',
    ),
    'path-traversal': (
        '外部输入可能访问预期目录之外的文件',
        '检查发现外部输入可能参与文件路径构造，需要核查最终路径是否仍位于允许的目录内。',
        '如果攻击者能控制路径并绕过目录限制，可能在应用权限范围内读取或修改不应访问的文件；实际可利用性尚未确认。',
        '建议修复：核查输入和最终解析路径，将文件访问限制在允许的目录内；修改后重新检查。',
    ),
    'arbitrary-file-read': (
        '外部输入可能指定读取的文件',
        '检查发现外部输入可能控制文件读取路径，需要核查访问范围。',
        '如果攻击者能指定允许范围之外的文件，可能读取应用有权限访问的敏感数据；实际可利用性尚未确认。',
        '建议修复：核查最终文件路径并限制可读取的目录或文件；修改后重新检查。',
    ),
    'arbitrary-file-write': (
        '外部输入可能指定写入的文件',
        '检查发现外部输入可能控制文件写入路径，需要核查写入范围。',
        '如果攻击者能指定允许范围之外的路径，可能覆盖应用有权限写入的文件或破坏数据；实际可利用性尚未确认。',
        '建议修复：核查最终文件路径并限制可写入的目录和文件名；修改后重新检查。',
    ),
    'unsafe-deserialization': (
        '不可信数据可能被还原成可执行的对象',
        '检查发现可能对外部数据使用不安全的对象还原方式，需要核查输入是否可信。',
        '如果攻击者能提供被还原的数据，可能触发非预期行为，部分场景下可能执行代码；具体条件和实际可利用性尚未确认。',
        '建议修复：核查数据来源，使用仅解析数据的安全格式并限制允许的数据类型；修改后重新检查。',
    ),
    'xxe': (
        '外部 XML 数据可能请求额外资源',
        '检查发现 XML 解析可能允许外部实体，需要核查解析器配置。',
        '如果攻击者能提供 XML 内容且外部实体可用，可能读取本地文件或访问其他网络资源；实际可利用性尚未确认。',
        '建议修复：核查解析器配置，禁用不需要的外部实体和外部资源访问；修改后重新检查。',
    ),
    'trust-all-tls': (
        '加密连接的服务器身份检查可能被关闭',
        '检查发现 TLS 服务器身份校验可能被绕过，需要核查证书和主机名校验配置。',
        '如果身份校验被关闭且网络连接被劫持，攻击者可能冒充服务器，窃取或篡改通信内容；实际部署中的使用情况尚未确认。',
        '建议修复：核查绕过校验的配置，恢复默认的证书和主机名校验；恢复后，不符合校验要求的连接可能被拒绝，再重新检查。',
    ),
    'secret': (
        '代码中可能暴露了密钥或访问凭据',
        '检查发现疑似密钥或访问凭据；提示不会显示原值，也尚未确认它是否有效。',
        '如果该凭据真实有效且被他人获得，可能被用于访问相关服务或数据；权限范围和实际有效性尚未确认。',
        '建议处理：核查凭据是否真实，移出代码并改用安全的配置方式；如果已经泄露，由凭据所有者在对应服务中撤销或轮换，再重新检查。',
    ),
    'dependency': (
        '依赖版本匹配到已知漏洞记录',
        '检查发现依赖的包名和版本匹配到漏洞记录；版本匹配本身不能证明应用可以被攻击。',
        '如果应用使用了受影响的功能且满足漏洞条件，可能受到攻击；具体影响、可到达路径和实际可利用性尚未确认。',
        '建议处理：核查漏洞资料、受影响功能和依赖路径，确认适用的修复版本与兼容性后再升级或替换，并重新检查。',
    ),
}

_UNKNOWN = (
    '待核查的安全风险',
    '检查发现一个安全风险候选，当前没有足够的已确认信息说明具体问题。',
    '具体影响和实际可利用性尚未确认；不能据此断言已经发生攻击或认定代码安全。',
    '建议先核查受影响代码与检查依据，确认问题和修改范围后再处理，并重新检查。',
)

_INCONCLUSIVE_REASONS = frozenset({
    'INCONCLUSIVE', 'VERIFICATION_INCONCLUSIVE', 'REMEDIATION_INCONCLUSIVE',
    'VERIFICATION_REQUIRED', 'EPISODE_ALREADY_EXISTS',
})
_ATTEMPT_REASONS = frozenset({
    'EPISODE_ATTEMPT_BUDGET_EXCEEDED', 'REMEDIATION_ESCALATED',
})
_QUESTION = '回复“修复”，我会进一步处理并重新检查；回复“忽略”，本次不修复，风险记录仍保留。'


def _dependency_copy(details: dict) -> tuple:
    """Render package coordinates, never arbitrary advisory/scanner prose."""
    package = details.get('package')
    version = details.get('package_version')
    if (not isinstance(package, str) or
            not re.fullmatch(r'[A-Za-z0-9@][A-Za-z0-9_.:/@+-]{0,199}', package) or
            not isinstance(version, str) or
            not re.fullmatch(r'v?[0-9][A-Za-z0-9_.+!~-]{0,119}', version)):
        return _COPY['dependency']
    title = f'依赖 {package} {version} 有已知安全风险'
    advisory = details.get('canonical_vulnerability_id')
    if not isinstance(advisory, str) or not re.fullmatch(
            r'CVE-[0-9]{4}-[0-9]{4,10}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}', advisory):
        advisory = ''
    problem = (f'依赖清单中的 {package} {version} 匹配到已知漏洞记录'
               f'{"（" + advisory + "）" if advisory else ""}。'
               '版本匹配本身不能证明应用可以被攻击；是否已安装这个版本尚未确认。')
    impact = _COPY['dependency'][2]
    if (package.lower() == 'pyyaml' and str(details.get('ecosystem', '')).lower() in {'pip', 'pypi'}
            and advisory in {'CVE-2020-14343', 'GHSA-8q59-q68h-6hv4'}):
        impact = ('如果程序使用 FullLoader 或 full_load 读取外部提供的 YAML 数据，'
                  '攻击者可能让程序执行恶意代码；是否存在这种用法尚未确认。')
    recommendation = _COPY['dependency'][3]
    fixed = details.get('fixed_versions')
    if isinstance(fixed, (list, tuple)):
        versions = [item for item in fixed[:20] if isinstance(item, str) and
                    re.fullmatch(r'v?[0-9][A-Za-z0-9_.+!~-]{0,119}', item)][:3]
        if versions:
            recommendation += (' 漏洞记录提供的修复版本：' + '、'.join(versions) +
                               '；这些版本是否适合本项目，仍需核查。')
    return title, problem, impact, recommendation


def _location(finding: dict) -> dict:
    relative = finding.get('file_path')
    if (not isinstance(relative, str) or
            not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', relative) or
            any(part in {'', '.', '..'} for part in relative.split('/'))):
        return {'file': None, 'line': None}
    line = finding.get('line_start')
    if finding.get('category') == 'dependency':
        # Dependency providers commonly use line 1 as a manifest placeholder;
        # this is not proof of the editable version's actual source line.
        line = None
    if type(line) is not int or not 1 <= line <= 10_000_000:
        line = None
    return {'file': relative, 'line': line}


def issue_feedback(finding: dict, *, reason: str = '', action: str = 'ADVISE',
                   verification_status: str | None = None,
                   evidence_scope: str = 'CURRENT_FINDING') -> dict:
    """Describe one issue using fixed templates and bounded coordinates only.

    An explicit verification status describes a verification result supplied by
    the caller, not a scanner invocation inferred from the existence of a record.
    EPISODE_ALREADY_EXISTS can carry a synthetic INCONCLUSIVE: that combination
    must not claim a new verification was performed.
    ORIGINAL_FINDING describes the precisely bound original record only. It is
    not evidence that the finding remains in the currently edited code.
    """
    finding = finding if isinstance(finding, dict) else {}
    details = finding.get('technical_details')
    details = details if isinstance(details, dict) else {}
    rule = details.get('rule_id', finding.get('rule_id'))
    category = finding.get('category')
    copy = (_dependency_copy(details) if category == 'dependency' else
            _TLS_HOSTNAME if rule == 'ai-security.java.trust-all-hostname' else
            _COPY.get(category, _UNKNOWN) if isinstance(category, str) else _UNKNOWN)
    title, problem, impact, recommendation = copy
    original = evidence_scope == 'ORIGINAL_FINDING'
    if original:
        title = f'待复查的原安全问题：{title}'
        problem = f'原问题记录：{problem} 当前代码是否仍存在该问题，需重新确认。'
        recommendation = f'先确认当前代码是否已消除原问题；若问题仍存在，{recommendation}'
    location = _location(finding)
    where = (f"`{location['file']}` 第 {location['line']} 行" if location['line'] else
             f"`{location['file']}`" if location['file'] else '当前改动的代码')
    state = []
    if reason == 'EPISODE_ALREADY_EXISTS' and not original:
        state.append('此前已有处理记录，风险目前再次被检出，尚未确认解决。')
    if verification_status in ('SCANNER_STILL_PRESENT', 'STILL_PRESENT') and not original:
        state.append('重新检查后，这个问题仍然存在，需要继续处理。')
    elif verification_status == 'INCONCLUSIVE' and reason != 'EPISODE_ALREADY_EXISTS':
        state.append('重新检查未能确认结果；尚未确认修复成功，不代表风险已消除。')
    elif ((isinstance(reason, str) and reason in _INCONCLUSIVE_REASONS) or
          verification_status == 'INCONCLUSIVE'):
        state.append('尚未确认修复成功，不代表风险已消除。')
    choices = ['修复', '忽略']
    question = _QUESTION
    if action == 'ESCALATE' or (isinstance(reason, str) and reason in _ATTEMPT_REASONS):
        state.append('已停止重复自动修复尝试，需要先核查原因和处理范围；不会因为回复“修复”而重置尝试次数或跳过检查。')
        question = '回复“修复”，我会先核查再处理并重新检查；回复“忽略”，本次不修复，风险记录仍保留。'
    elif action == 'AUTO_FIX':
        choices = []
        question = '本次修复已获得授权，将按已批准的范围处理并重新检查。'
    heading = f'{title}。' if original else f'发现安全风险：{title}。'
    location_label = '原问题位置' if original else '位置'
    message = '\n'.join([heading, f'{location_label}：{where}',
                         problem, impact, recommendation, *state, question])
    return {'version': 'security-user-feedback-v1', 'title': title, 'location': location,
            'problem': problem, 'impact': impact, 'recommendation': recommendation,
            'choices': choices, 'message': message}


def _count(delta: dict, field: str) -> int | None:
    value = delta.get(field)
    return value if type(value) is int and 0 <= value <= 1_000_000 else None


def _base_scan_status_message(result: dict) -> str:
    """Translate known scan states without reflecting diagnostics or next_step."""
    result = result if isinstance(result, dict) else {}
    status = result.get('status')
    status = status if isinstance(status, str) else ''
    coverage = result.get('coverage')
    coverage = coverage if isinstance(coverage, str) else ''
    delta = result.get('delta')
    delta = delta if isinstance(delta, dict) else {}
    new, persisting, additional = (_count(delta, key) for key in
                                  ('new', 'persisting', 'additional_occurrences'))
    if status == 'NOT_SCANNED':
        # NOT_SCANNED can also mean an unavailable host capability. Only
        # closed read-only reasons justify describing the event as read-only.
        readonly = any(result.get(key) in ('READ_ONLY_BASH', 'READ_ONLY_ACTIVITY')
                       for key in ('reason', 'scanner_skipped_reason'))
        if readonly:
            return '本次是只读操作，没有需要检查的代码改动，无需追加安全检查。'
        if coverage == 'NOT_APPLICABLE':
            return '本次操作无需执行安全检查，没有新增检查结果。'
        return '本次未执行安全检查，不能据此判断是否存在风险。'
    if status == 'NOT_APPLICABLE':
        return '本次没有适用的安全检查项目，未执行扫描。'
    if status in {'REUSED_LAST_RESULT', 'NO_CHANGE'}:
        return '本次复用已有检查结果，未重新扫描；仍受上次检查范围限制，不能据此确认风险已经解决。'
    if status == 'SESSION_FINALIZED':
        return '本次会话已结束，未重新扫描；请结合最近一次检查结果处理风险。'
    if status == 'NO_CHANGES':
        return '没有需要检查的代码改动，本次未执行扫描；这不代表项目没有安全风险。'
    if status == 'DEBOUNCED':
        return '改动已记录，本次尚未执行扫描，仍需等待后续检查。'
    if status == 'BUSY':
        return '安全检查正在处理其他改动，本次检查尚未完成；请稍后重新检查。'
    if status == 'BASELINE_ESTABLISHED':
        if coverage in {'PARTIAL', 'UNKNOWN'}:
            return '已建立首次比较基线，但安全检查覆盖仍不完整，部分范围未检查或未确认；首次基线不能确定哪些风险由这次改动引入，也不能说明项目安全。'
        return '已建立首次比较基线；首次基线不能确定哪些风险由这次改动引入，也不能说明项目安全。'
    if status in {'FAILED', 'INCONCLUSIVE'}:
        return '本次安全检查未能给出完整结果；尚未确认修复成功，不代表风险已消除。请重新检查。'
    if status == 'PARTIAL' or (status == 'SCANNED' and coverage in {'PARTIAL', 'UNKNOWN'}):
        return '本次只完成部分安全检查，仍有范围未确认；不能据此确认没有风险或风险已经解决。请重新检查未覆盖的范围。'
    if status == 'SCANNED' and coverage == 'FULL':
        if new is not None and persisting is not None:
            if new or persisting or (additional is not None and additional > 0):
                counts = f'发现 {new} 个新增风险、{persisting} 个持续风险'
                if additional:
                    counts += f'，已有风险还新增 {additional} 处出现位置'
                return f'本次检查完成：{counts}。建议查看具体问题、影响和修复建议。'
            if additional == 0:
                return '本次检查完成，在本次检查范围内未发现新增风险；已有风险是否解决仍需对应的验证结果，不能据此认定项目安全。'
        return '本次检查完成；风险数量尚未确认，请查看具体风险与检查范围。'
    if status == 'SCANNED' and coverage == 'SCOPED':
        return '本次已完成适用范围的安全检查；未执行的检查范围仍需单独确认。'
    return '本次安全检查结果尚未确认，请重新检查；这不代表风险已消除。'


def dependency_status_message(result: dict) -> str:
    """Describe closed dependency states without reflecting diagnostic prose."""
    if not isinstance(result, dict):
        return ''
    status = result.get('status')
    if isinstance(status, str) and status in {
            'NO_CHANGE', 'REUSED_LAST_RESULT', 'NOT_SCANNED', 'NOT_APPLICABLE',
            'NO_CHANGES', 'SESSION_FINALIZED', 'DEBOUNCED', 'BUSY'}:
        return ''
    capabilities = result.get('capabilities')
    capabilities = capabilities if isinstance(capabilities, dict) else {}
    state = capabilities.get('DEPENDENCY_VULN')
    if not isinstance(state, str) or state not in {'FAILED', 'UNAVAILABLE', 'PARTIAL'}:
        return ''
    runs = result.get('scanner_runs')
    runs = runs if isinstance(runs, list) else []
    errors = {run.get('error_code') for run in runs[:50]
              if isinstance(run, dict) and isinstance(run.get('scanner'), str)
              and run.get('scanner') in {'trivy', 'trivy-vuln', 'osv-scanner'}
              and isinstance(run.get('error_code'), str)}
    reason = result.get('dependency_check_reason')
    if isinstance(reason, str):
        errors.add(reason)
    start = ('依赖检查只完成部分范围，尚未确认完整依赖范围。' if state == 'PARTIAL' else
             '依赖检查没有完成，暂时无法确认依赖是否安全。')
    if 'VULNERABILITY_DB_STALE' in errors:
        return start + ('本次使用的本地漏洞数据已经过期，可能遗漏新的漏洞；'
                        '更新漏洞数据后，需要重新检查。')
    if 'VULNERABILITY_DB_FRESHNESS_UNKNOWN' in errors:
        return start + ('本次无法确认本地漏洞数据的更新时间，可能遗漏新的漏洞；'
                        '确认或更新漏洞数据后，需要重新检查。')
    if 'VULNERABILITY_DB_UNAVAILABLE' in errors:
        return start + '本地没有可用的依赖漏洞数据；需要先准备漏洞数据，再重新检查。'
    if 'ENGINE_UNAVAILABLE' in errors:
        return start + '本地依赖检查工具尚未就绪；准备检查工具后，需要重新检查。'
    if 'OFFLINE_MODE' in errors:
        return start + '本地缺少可用的检查工具或漏洞数据；准备好本地检查条件后，需要重新检查。'
    return start + ('尚未确认全部传递依赖和已安装版本，不能据此判断全部依赖安全。'
                    if state == 'PARTIAL' else '请核查检查工具和漏洞数据后，重新检查。')


def scan_status_message(result: dict) -> str:
    message = _base_scan_status_message(result)
    dependency = dependency_status_message(result)
    return message + ('\n' + dependency if dependency else '')
