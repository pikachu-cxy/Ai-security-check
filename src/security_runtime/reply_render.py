"""Chinese fallback rendering of a reply plan. No domain state is modified."""
from .reply_plan import ReplyPlan
from .risk_decision_guidance import PRIMARY_CHOICES


def choice_prompt(total, *, issue=False, investigate_first=False):
    if issue and total == 1:
        return ('回复“修复”，我会先核查再处理并重新检查；回复“稍后处理”，保留记录，本次不再追问。'
                if investigate_first else
                '回复“修复”，我会按说明的范围处理并重新检查；回复“稍后处理”，风险记录仍保留，本次不再追问。')
    question = ('**回复「修复」或「稍后处理」即可。**' if total == 1 else
                '**请选择具体风险，再回复「修复」或「稍后处理」。**')
    return question+'\n\n暂不处理仅表示本次不修复，风险记录保留，本次不再追问。选择前不会修改代码。'


def risk_details(risk, *, issue=False, number=None):
    parts = [f'**{number}. {risk.title}**'] if number is not None else []
    if issue:
        where = (f'`{risk.file}` 第 {risk.line} 行' if risk.file and risk.line else
                 f'`{risk.file}`' if risk.file else '当前改动的代码')
        parts.append(('原问题位置' if risk.original else '位置')+'：'+where)
    else:
        source = '上下文核查线索' if risk.source == 'HOST_REVIEW' else '静态检查提示'
        where = f'{risk.file}:{risk.line}' if risk.file and risk.line else risk.file or '当前改动的代码'
        parts.append(f'📍 `{where}` · {source}')
    if risk.deleted:
        parts.append('位置对应删除前的代码。')
    parts.extend(['**问题**\n'+risk.problem, '**可能影响**\n'+risk.impact])
    if risk.source == 'HOST_REVIEW':
        parts.append('风险范围：'+('关联代码中的现有条件性风险，不等于新增入口仍有漏洞。'
                                   if risk.related else '本次改动相关路径。'))
        if risk.evidence:
            parts.append('代码依据：'+' → '.join(risk.evidence))
        parts.append('触发条件：'+('；'.join(risk.preconditions) or '实际可达性未确认'))
        parts.append('当前防护：'+('；'.join(risk.protections) or '未观察到相关防护；不代表不存在'))
        parts.append('反证：'+('；'.join(risk.counterevidence) or '未观察到足以排除风险的反证'))
    parts.append('**建议修复**\n'+risk.recommendation)
    parts.append('**尚未确认**\n'+('；'.join(risk.unknowns) or '该风险的实际触发条件尚未确认。'))
    parts.extend(risk.notes)
    if risk.authorized:
        parts.append('本次修复已获得授权，将按已批准的范围处理并重新检查。')
    return '\n\n'.join(parts)


def repair_impact_details(impact):
    """Render business effects without declaring compatibility or edit authority."""
    parts = ['**修复影响**']
    if impact.summary:
        parts.append('方案：'+impact.summary)
    if impact.security_goal:
        parts.append('安全目标：'+impact.security_goal)
    for label, values in (
            ('预期限制的危险行为', impact.expected_restrictions),
            ('正常业务变化', impact.behavior_changes),
            ('拟保留的正常行为', impact.preserved_behaviors),
            ('已核对范围', impact.no_additional_changes),
            ('替代方案', impact.alternatives),
            ('关键未知', impact.critical_unknowns),
            ('尚未确认', impact.unknowns)):
        if values:
            parts.append(label+'：'+'；'.join(values))
    if impact.current is not True:
        parts.append('这份分析的依据尚未核对为当前有效，不能作为继续编辑的依据。')
    elif impact.gate == 'CRITICAL_CONTEXT_MISSING':
        parts.append('决定该方案是否保留正常行为的依据不足，该方案尚不能实施。')
    if impact.read_only:
        parts.append('本次仅查看影响分析，不产生修复授权。')
    return '\n\n'.join(parts)


def _check_message(plan):
    check = plan.check
    if check.message:
        return check.message
    if plan.intent == 'HISTORY':
        if check.raw_findings:
            return f'检查记录共 {check.raw_findings} 项，风险详情按页返回；本次查询未重新执行检查。'
        if check.state == 'NO_CHANGES':
            return '本次记录没有可检查的文件改动。'
        if check.state not in {'COMPLETE'}:
            return '当前没有已记录的风险提示；检查尚未完成或覆盖受限。'
        return '本次已保存的检查记录没有发现安全线索。'
    if plan.intent == 'QUERY':
        return ('已保存的安全检查只完成部分范围。' if check.state == 'PARTIAL' else
                '本次查询读取已保存的安全检查结果，未重新检查。')
    if plan.intent not in {'TASK', 'TASK_DELIVERY'}:
        return ''
    if check.state == 'NO_CHANGES':
        return '本次没有观察到可检查的文件改动。'
    if check.state == 'CAPACITY_REQUIRED':
        return '代码复核尚未开始，已有检查记录保留。'
    if check.state not in {'COMPLETE', 'PARTIAL', 'INCOMPLETE'}:
        return ''
    message = f'安全核查：本任务有 {check.changed_files} 个改动文件，提交静态检查 {check.scope_files} 个文件。'
    if check.state == 'INCOMPLETE':
        message += '本次任务安全核查未完成。'
    elif check.state == 'PARTIAL':
        message += '本次只完成部分安全检查。'
    elif not check.raw_findings:
        message += '本次未发现安全线索。'
    elif not plan.risks:
        message += '已登记提示的处置状态另列，原始记录保留。'
    return message


def render_reply(plan: ReplyPlan, *, include_risks=True):
    parts = []
    risks = plan.risks if include_risks else ()
    total = plan.total_risk_count if include_risks else 0
    if total:
        if plan.intent == 'ISSUE':
            parts.append((risks[0].title+'。') if risks[0].original else '发现安全风险：'+risks[0].title+'。')
        else:
            related = sum(r.related for r in risks)
            label = '关联风险' if related == total else '安全风险'
            detail = f'（其中 {related} 项关联风险）' if 0 < related < total else ''
            title = '：'+risks[0].title if total == 1 else ''
            parts.append(f'**发现 {total} 项{label}{detail}{title}**')
        parts.extend(risk_details(r, issue=plan.intent == 'ISSUE', number=i if total > 1 else None)
                     for i, r in enumerate(risks[:3], 1))
        if total > 3:
            parts.append(f'另有 {total-3} 项已保留在本次核查记录中。')
    parts.extend(repair_impact_details(item) for item in plan.repair_impacts[:3])
    if len(plan.repair_impacts) > 3:
        parts.append(f'另有 {len(plan.repair_impacts)-3} 份修复影响分析已保留。')
    check = _check_message(plan)
    if check:
        parts.append(('**检查范围**\n' if total else '')+check)
    capability_labels = {'CODE_SAST': '代码安全检查', 'SECRET_SCAN': '密钥检查',
                         'DEPENDENCY_VULN': '依赖检查', 'IAC_MISCONFIG': '配置安全检查'}
    unavailable = [capability_labels[key]+'未完成' for key, state in plan.check.capabilities
                   if key in capability_labels and state in {'UNAVAILABLE', 'FAILED', 'PARTIAL', 'NOT_COVERED'}]
    labels = {'CHECK_GAP': '检查未完成', 'PRIOR_VERIFICATION': '原问题复查',
              'HANDLING_RECEIPT': '处置结果', 'HANDLING_UNAVAILABLE': '处置记录',
              'APPLICABILITY': '结果适用范围', 'CHECK_RESULT': '处置状态', 'SCOPE': '检查范围'}
    groups = {}
    if unavailable:
        groups['CHECK_GAP'] = ['；'.join(unavailable)+'，这些范围的风险尚未确认。']
    for notice in plan.notices:
        groups.setdefault(notice.kind, []).append(notice.text)
    for kind, notes in groups.items():
        parts.append(f"**{labels.get(kind, '检查说明')}**\n"+'\n'.join(notes))
    if include_risks and plan.action_ids:
        parts.append(choice_prompt(len(plan.action_ids), issue=plan.intent == 'ISSUE',
                                   investigate_first=any(r.investigate_first for r in risks)))
    if plan.business_choice_refs:
        parts.append('请明确要保留的业务行为或采用的方案；这项选择不会扩大已有修复授权。')
    return '\n\n'.join(parts)


def choice_labels():
    return list(PRIMARY_CHOICES)
