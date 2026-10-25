"""Closed user-facing Hook copy; source and scanner prose never enter messages.

These descriptions are presentation only. They cannot authorize a repair,
create a confirmation capability, or establish scanner resolution.
"""
from __future__ import annotations

import re

from .guidance.risk_decision_guidance import PRIMARY_CHOICES, SECONDARY_CHOICES


_TLS_HOSTNAME = (
    'HTTPS 连接没有核对服务器身份',
    '这行代码关闭了 HTTPS 主机名校验，服务器证书的域名与目标地址不匹配也会被接受。',
    '如果网络连接被劫持，攻击者可能冒充目标服务器，窃取或篡改通信内容；实际部署中的使用情况尚未确认。',
    '建议修复：删除这行绕过校验的代码，恢复默认检查，再重新检查。恢复后，证书域名不匹配的连接会被拒绝。',
)

_DYNAMIC_FUNCTION_RULE = 'ai-security.javascript.dynamic-function'
_DYNAMIC_FUNCTION = (
    '输入可能被当成 JavaScript 执行',
    '这行代码把动态内容传给 Function 构造器（包括 new Function），生成的函数会把这些内容当作 JavaScript 代码。',
    '如果外部输入能到达这里且生成的函数被调用，攻击者可能在应用权限范围内执行非预期代码、读取或修改数据；实际入口是否可到达、Function 是否为原生构造器尚未确认。',
    '建议修复：核查输入来源；算术计算应改用仅允许数字、括号和已约定运算符的受限解析器，不能改用 eval 或其他动态执行方式。解析器会收窄可接受的语法，不能保证保留任意 JavaScript 表达式；修改后复查原风险是否消除。',
)
_DYNAMIC_EVAL = (
    _DYNAMIC_FUNCTION[0],
    '这行代码把动态内容传给 eval，这些内容可能被直接当作 JavaScript 代码执行。',
    '如果外部输入能到达这里且 eval 为原生函数，攻击者可能在应用权限范围内执行非预期代码、读取或修改数据；实际入口是否可到达、eval 是否为原生函数尚未确认。',
    _DYNAMIC_FUNCTION[3],
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
_DYNAMIC_ONLY_NOTICE = ('本次快速检查只覆盖这些文件中的动态 Function / eval 调用；'
                        '其他代码安全规则尚未执行，需要完整扫描确认。')


def code_scope_notice(result: dict) -> str:
    """Translate the fixed Runtime scope enum; never reflect arbitrary notice text."""
    return (_DYNAMIC_ONLY_NOTICE if isinstance(result, dict) and
            result.get('code_check_scope') == 'CANONICAL_DYNAMIC_CODE_ONLY' else '')


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
            (_DYNAMIC_EVAL if details.get('dangerous_api') == 'eval' else _DYNAMIC_FUNCTION)
            if rule == _DYNAMIC_FUNCTION_RULE else
            _COPY.get(category, _UNKNOWN) if isinstance(category, str) else _UNKNOWN)
    title, problem, impact, recommendation = copy
    original = evidence_scope == 'ORIGINAL_FINDING'
    if original:
        title = f'待复查的原安全问题：{title}'
        problem = f'原问题记录：{problem} 当前代码是否仍存在该问题，需重新确认。'
        recommendation = f'先确认当前代码是否已消除原问题；若问题仍存在，{recommendation}'
    location = _location(finding)
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
    choices = list(PRIMARY_CHOICES)
    investigate_first = False
    if action == 'ESCALATE' or (isinstance(reason, str) and reason in _ATTEMPT_REASONS):
        state.append('已停止重复自动修复尝试，需要先核查原因和处理范围；不会因为回复“修复”而重置尝试次数或跳过检查。')
        investigate_first = True
    elif action == 'AUTO_FIX':
        choices = []
    feedback = {'version': 'security-user-feedback-v2', 'title': title, 'location': location,
            'problem': problem, 'impact': impact, 'recommendation': recommendation,
            'choices': choices, 'secondary_choices': list(SECONDARY_CHOICES) if choices else [],
            'legacy_choice_aliases': {'暂不处理': '稍后处理', '忽略': '稍后处理'},
            'finding_id': finding.get('id', ''),
            'display_facts': dict(notes=state, authorized=action == 'AUTO_FIX',
                                  investigate_first=investigate_first, original=original)}
    return render_feedback(feedback)


def render_feedback(feedback, notices=()):
    """Compatibility envelope; all visible messages use the shared reply plan."""
    from .reply_adapters import issue_facts
    from .reply_plan import Notice, ReplyFacts, plan_reply
    from .reply_render import render_reply
    items = feedback.get('items') or [feedback]
    risks = []
    for item in items:
        display = item.get('display_facts') or {}
        risks.extend(issue_facts(item, notes=display.get('notes', ()),
            authorized=display.get('authorized') is True,
            investigate_first=display.get('investigate_first') is True,
            original=display.get('original') is True).risks)
    existing = tuple(Notice(n['kind'], n['text']) for n in
                     feedback.get('reply_plan', {}).get('notices', []))
    plan = plan_reply(ReplyFacts('ISSUE' if len(items) == 1 else 'ISSUE_GROUP',
        risks=tuple(risks), notices=existing+tuple(notices),
        total_risk_count=feedback.get('finding_count')))
    feedback.update(reply_plan=plan.to_dict(), message=render_reply(plan))
    return feedback


def combine_feedback(items, *, total_count=None):
    return render_feedback(dict(version='security-user-feedback-v2', items=items,
        finding_count=total_count if type(total_count) is int else len(items),
        choices=[], selection_required=True))


def check_gap_feedback(message, *, state='INCOMPLETE'):
    from .reply_plan import CheckFact, Notice, ReplyFacts, plan_reply
    from .reply_render import render_reply
    plan = plan_reply(ReplyFacts('CHECK_STATUS', CheckFact(state), notices=(Notice('CHECK_GAP', message),)))
    return dict(message=render_reply(plan), reply_plan=plan.to_dict())


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
        return '本次只完成部分安全检查，仍有范围未确认；具体问题的复查结果单独列示，不能据此确认没有风险或认定整个项目安全。请重新检查未覆盖的范围。'
    if status == 'SCANNED' and coverage == 'FULL':
        if new is not None and persisting is not None:
            if new or persisting or (additional is not None and additional > 0):
                counts = f'发现 {new} 个新增检查提示、{persisting} 个仍存在的检查提示'
                if additional:
                    counts += f'，已有提示还新增 {additional} 处出现位置'
                return f'本次检查完成：{counts}；实际影响需结合代码核实。'
            if additional == 0:
                return '本次检查完成，在本次检查范围内未发现新增检查提示；已有风险是否解决仍需对应的验证结果，不能据此认定项目安全。'
        return '本次检查完成；提示数量尚未确认，请查看具体提示与检查范围。'
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
    direct_runs = [r for r in runs if isinstance(r, dict) and r.get('scanner') == 'trivy-maven-direct']
    if direct_runs:
        start += ('Maven 仓库返回 HTTP 429，已停止远程解析间接依赖；'
                  '当前仅返回能够本地确定版本的 POM 直接依赖结果，间接依赖扫描不完整。'
                  if any(r.get('status') == 'SUCCESS' for r in direct_runs) else
                  'Maven 仓库返回 HTTP 429，已停止远程解析；直接依赖降级检查也未完成，间接依赖未完整检查。')
    inventories = result.get('dependency_inventory', [])
    inventories = inventories if isinstance(inventories, list) else []
    missing, observed = set(), set()
    unresolved = False
    confirmed = False
    for inventory in inventories[:10]:
        if not isinstance(inventory, dict):
            continue
        names = inventory.get('unconfirmed_manifests', [])
        for name in names[:20] if isinstance(names, list) else []:
            if (isinstance(name, str) and len(name) <= 200
                    and re.fullmatch(r'[\w./ -]+', name) and '..' not in name.split('/')
                    and not name.startswith('/')):
                missing.add(name)
        confirmed |= type(inventory.get('confirmed_manifests')) is int and inventory['confirmed_manifests'] > 0
        per_manifest = inventory.get('per_manifest', {})
        if isinstance(per_manifest, dict):
            observed.update(name for name, count in per_manifest.items()
                            if isinstance(name, str) and type(count) is int and count > 0)
        declarations = inventory.get('python_declarations', {})
        if isinstance(declarations, dict):
            unresolved |= any(isinstance(report, dict) and type(report.get('unresolved_entries')) is int
                              and report['unresolved_entries'] > 0 for report in declarations.values())
    missing -= observed
    if missing:
        start += '以下清单尚未取得依赖包列表：' + '、'.join(f'`{name}`' for name in sorted(missing)[:5]) + '；没有告警不代表已检查其中的依赖。'
    if unresolved:
        start += '部分 Python 依赖使用版本范围、动态声明或尚未支持的格式，未推断其安装版本；请提供受支持的锁文件以补齐检查。'
    if confirmed and not missing and state == 'PARTIAL':
        start += '已检查能够确认的声明版本；全部传递依赖和实际安装版本仍未确认。'
    if 'VULNERABILITY_DB_STALE' in errors:
        return start + ('本次使用的本地漏洞数据已经过期，可能遗漏新的漏洞；'
                        '更新漏洞数据后，需要重新检查。')
    if 'VULNERABILITY_DB_FRESHNESS_UNKNOWN' in errors:
        return start + ('本次无法确认本地漏洞数据的更新时间，可能遗漏新的漏洞；'
                        '确认或更新漏洞数据后，需要重新检查。')
    if 'VULNERABILITY_DB_UNAVAILABLE' in errors:
        return start + '本地没有可用的依赖漏洞数据；需要先准备漏洞数据，再重新检查。'
    if 'ENGINE_MISSING_OFFLINE' in errors:
        return start + '本地依赖检查工具尚未安装，本次仅使用本地组件；安装该工具后再检查。'
    if 'OSV_DATABASE_MISSING' in errors:
        return start + '备用依赖检查工具已就绪，但缺少所需的本地漏洞数据；补齐数据后再检查。'
    if errors & {'COMPONENT_EXECUTION_IDENTITY_UNAVAILABLE', 'SCAN_EXECUTION_IDENTITY_UNAVAILABLE'}:
        return start + '无法确认依赖检查工具的运行环境；核对工具安装入口后再检查。'
    if 'ENGINE_UNAVAILABLE' in errors:
        return start + '本地依赖检查工具尚未就绪；准备检查工具后，需要重新检查。'
    if 'OFFLINE_MODE' in errors:
        return start + '本地缺少可用的检查工具或漏洞数据；准备好本地检查条件后，需要重新检查。'
    return start + ('尚未确认全部传递依赖和已安装版本，不能据此判断全部依赖安全。'
                    if state == 'PARTIAL' else '请核查检查工具和漏洞数据后，重新检查。')


def scan_status_message(result: dict) -> str:
    return scan_status_feedback(result)['message']


def scan_status_feedback(result: dict) -> dict:
    from .reply_plan import CheckFact, Notice, ReplyFacts, plan_reply
    from .reply_render import render_reply
    result = result if isinstance(result, dict) else {}
    if result.get('handling_unavailable'):
        from .guidance.risk_decision_guidance import HANDLING_UNAVAILABLE_MESSAGE
        scope = code_scope_notice(result)
        dependency = dependency_status_message(result)
        notices = tuple(Notice(kind, text) for kind, text in (
            ('HANDLING_UNAVAILABLE', HANDLING_UNAVAILABLE_MESSAGE), ('SCOPE', scope),
            ('CHECK_GAP', dependency)) if text)
        plan = plan_reply(ReplyFacts('SCAN_STATUS', notices=notices, handling_available=False))
        return dict(message=render_reply(plan), reply_plan=plan.to_dict())
    message = _base_scan_status_message(result)
    projection = result.get('finding_feedback_projection', {}) if isinstance(result, dict) else {}
    folded = projection.get('folded_count') if isinstance(projection, dict) else None
    remaining = projection.get('alert_finding_count') if isinstance(projection, dict) else None
    if (result.get('status') == 'SCANNED' and result.get('coverage') == 'FULL'
            and type(folded) is int and 0 < folded <= 1_000_000
            and type(remaining) is int and 0 <= remaining <= 1_000_000):
        # Raw delta still counts scanner observations. Do not present the exact
        # already-reviewed candidates as new pending repair choices again.
        message = (f'本次检查有 {remaining} 条告警仍需核查；'
                   f'另有 {folded} 条已排除或已暂缓，原始记录保留。'
                   if remaining else '')
    scope_notice = code_scope_notice(result)
    dependency = dependency_status_message(result)
    verification = rule_delta_message(result)
    notices = tuple(Notice(kind, text) for kind, text in (
        ('SCOPE', scope_notice), ('PRIOR_VERIFICATION', verification), ('CHECK_GAP', dependency)) if text)
    state = result.get('status')
    known = {'NOT_SCANNED', 'NOT_APPLICABLE', 'REUSED_LAST_RESULT', 'NO_CHANGE',
             'SESSION_FINALIZED', 'NO_CHANGES', 'DEBOUNCED', 'BUSY', 'BASELINE_ESTABLISHED',
             'SCANNED', 'FAILED', 'PARTIAL', 'INCONCLUSIVE'}
    state = state if isinstance(state, str) and state in known else 'UNKNOWN'
    plan = plan_reply(ReplyFacts('SCAN_STATUS', CheckFact(state, message=message),
                                notices=notices))
    return dict(message=render_reply(plan), reply_plan=plan.to_dict())


def rule_delta_message(result: dict) -> str:
    """Distinguish confirmed absence from missing proof, even in a partial scan."""
    delta = result.get('delta', {}) if isinstance(result, dict) else {}
    families = delta.get('families', []) if isinstance(delta, dict) else []
    lines = []
    groups = {}
    for family in families if isinstance(families, list) else []:
        if not isinstance(family, dict):
            continue
        location = _location(family)
        if not location['file']:
            continue
        key = (location['file'], family.get('status'), family.get('count_certainty'))
        groups[key] = groups.get(key, 0) + 1
    for (file, status, _), count in list(groups.items())[:20]:
        where = f'`{file}`'
        if status == 'RESOLVED_FAMILY':
            lines.append(f'复查结果：{where} 的 {count} 条原规则提示已确认关闭，已从持续风险记录中关闭；结论仅覆盖对应规则与当前文件版本。')
        elif status == 'UNCONFIRMED_ABSENCE':
            lines.append(f'复查结果：{where} 当前未再检出 {count} 条原提示，但缺少与原记录一致的规则或文件覆盖证明，关闭确认尚未完成，仍保留待确认记录。')
    return '\n'.join(lines)


def secret_verification_feedback(results: list[dict]) -> dict:
    lines = []
    groups = {}
    for result in results[:20]:
        location = _location(result.get('original_evidence', {}))
        where = f"`{location['file']}`" if location['file'] else '选定文件'
        state = result.get('verification_status')
        if state == 'SCANNER_VERIFIED_RESOLVED':
            text = f'复查完成：{where} 已按原凭据检测规则重新检查，未再检出原提示，对应规则提示已确认关闭。'
        elif state == 'STILL_PRESENT':
            text = f'复查完成：{where} 仍检出原凭据提示；请继续检查并移除代码中的凭据格式文本，然后再次复查。'
        elif result.get('scanner_runs') and all(r.get('status') == 'SUCCESS' for r in result['scanner_runs']) and not result.get('current_evidence'):
            text = f'复查已执行：{where} 当前未再检出原提示，但缺少与原记录一致的规则或文件覆盖证明，暂未确认关闭，风险记录仍保留待确认。'
        else:
            text = f'检查未完成：{where} 尚不能确认原提示是否消除；请核查检查能力和原文件范围后再次复查，风险记录仍保留。'
        # Group by outcome and reason, preserving mixed outcomes separately.
        key = (text, result.get('reason', ''))
        groups[key] = groups.get(key, 0) + 1
    for (text, _), count in groups.items():
        lines.append(text + (f'（{count} 条原规则提示）' if count > 1 else ''))
    if results:
        lines.append('复查只确认本次代码提示；密钥是否有效、是否已撤销及历史泄露是否处理，需要另行确认，不能据此认定项目安全。')
    return {'version': 'security-user-feedback-v1', 'message': '\n'.join(dict.fromkeys(lines)),
        'choices': [], 'scope': 'ORIGINAL_PROVIDER_RULE_FILE_ONLY',
        'functional_verification': 'NOT_PROVEN_BY_SCANNER'}
