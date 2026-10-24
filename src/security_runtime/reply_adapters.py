"""Read-only adapters from existing results to security reply facts.

No store, scanner, host transport or test runner is invoked here. Callers keep
ownership, version checks, redaction and persisted handling authoritative.
"""
from __future__ import annotations

from .reply_plan import CheckFact, Notice, RepairImpactFact, ReplyFacts, RiskFact


def finding_fact(finding, *, source='SCANNER', feedback=None, choice_required=True):
    feedback = feedback or {}
    context = source == 'HOST_REVIEW'
    title = finding.get('plain_title') or finding.get('title') or '待核查的安全问题'
    return RiskFact(identifier=finding.get('id', ''), title=title,
        file=finding.get('file_path'), line=finding.get('line_start'), problem=title,
        impact=finding.get('impact', '实际影响尚未确认。'),
        recommendation=finding.get('fix_advice', '先核查代码依据和处理范围。'),
        unknowns=tuple(finding.get('unknowns') or ()) if context else (),
        preconditions=tuple(finding.get('preconditions') or ()),
        protections=tuple(finding.get('current_protections', finding.get('counterevidence')) or ()),
        counterevidence=tuple(finding.get('counterevidence') or ()),
        evidence=tuple(f"{v['path']}:{v['start_line']}-{v['end_line']}"
                       for v in finding.get('evidence_locations', [])),
        source=source, severity=finding.get('severity', 'UNKNOWN'),
        related=finding.get('risk_scope') == 'RELATED_EXISTING',
        deleted=finding.get('location_version') == 'BEFORE_DELETION',
        suppressed=bool(feedback.get('reminder_suppressed', feedback.get('folded', False))),
        choice_required=choice_required,
        reviewed=context or (feedback.get('state') == 'STILL_RISK'
                             and feedback.get('agent_review_current') is True
                             and feedback.get('technical_assessment_current') is True))


_GAPS = {
    'INVENTORY_READ_BUDGET': '部分文件未能保存修改前的对照信息，无法完整确认本次改动范围。',
    'TASK_CHANGE_COMPARISON_UNAVAILABLE': '部分文件的修改前后内容无法完成比较。',
    'TASK_HOOK_CURRENT_SOURCE_UNAVAILABLE': '部分文件未能取得本次检查所需的当前内容。',
}
from .tasks.coverage import CAPTURE_GAP
from .tasks.coverage import CAPTURE_LABEL
from .tasks.coverage import capture_gap_note
from .tasks.coverage import display_limitations
_GAPS[CAPTURE_GAP] = CAPTURE_LABEL

_ATTRIBUTION_REASON = 'CONCURRENT_TASK_ATTRIBUTION_UNAVAILABLE'
_ATTRIBUTION_LABEL = '同一工作区的任务时间窗重叠，改动归属未能独立确认'

# Closed diagnostic codes only: scanner prose may contain sensitive or
# untrusted text and must not become instructions or a vulnerability finding.
_CAPABILITY_GAPS = {'UNAVAILABLE', 'FAILED', 'PARTIAL', 'NOT_COVERED'}
_CHECK_REASONS = {
    'SCAN_EXECUTION_IDENTITY_UNAVAILABLE': '无法确认检查工具的运行环境；需核对工具安装入口后重试。',
    'COMPONENT_EXECUTION_IDENTITY_UNAVAILABLE': '无法确认检查工具的运行环境；需核对工具安装入口后重试。',
    'ENGINE_MISSING_OFFLINE': '本地检查工具尚未安装，本次仅使用本地组件；安装该工具后重试。',
    'OSV_DATABASE_MISSING': '备用依赖检查工具缺少本地漏洞数据；补齐所需数据后重试。',
    'VULNERABILITY_DB_UNAVAILABLE': '本地没有可用的依赖漏洞数据；准备数据后重试。',
    'VULNERABILITY_DB_FRESHNESS_UNKNOWN': '本地漏洞数据的更新时间无法确认；核对或更新数据后重试。',
    'VULNERABILITY_DB_STALE': '本地漏洞数据已经过期，可能遗漏新的漏洞；更新数据后重试。',
}


def _capability_notices(static):
    providers = {'CODE_SAST': {'semgrep'},
                 'DEPENDENCY_VULN': {'trivy', 'trivy-vuln', 'osv-scanner'}}
    labels = {'CODE_SAST': '代码安全检查', 'DEPENDENCY_VULN': '依赖检查'}
    runs = static.get('scanner_runs') or []
    runs = runs if isinstance(runs, list) else []
    for capability, scanners in providers.items():
        state = (static.get('capability_results') or {}).get(capability)
        if state not in _CAPABILITY_GAPS:
            continue
        reasons = tuple(dict.fromkeys(_CHECK_REASONS[run['error_code']]
            for run in runs[:50] if isinstance(run, dict)
            and isinstance(run.get('scanner'), str) and run['scanner'] in scanners
            and isinstance(run.get('error_code'), str) and run['error_code'] in _CHECK_REASONS))
        if reasons:
            status = '未启动' if capability == 'CODE_SAST' and state == 'UNAVAILABLE' else '未完成'
            yield Notice('CHECK_GAP', labels[capability]+status+'：'+' '.join(reasons), capability)


def _attribution_details(record, limitations, static_complete):
    """Display facts only; never upgrade persisted coverage or closure authority."""
    attribution = [item for item in limitations if isinstance(item, dict)
                   and item.get('reason') == _ATTRIBUTION_REASON]
    if not attribution:
        return (), set()
    completion = record.get('review_completion') or {}
    units, reviewed = completion.get('unit_count'), completion.get('reviewed_unit_count')
    source_complete = (record['phase'] == 'COMPLETE'
        and completion.get('status') == 'COMPLETE'
        and completion.get('coverage') == 'REVIEWED'
        and type(units) is int and units > 0 and type(reviewed) is int and reviewed == units
        and not completion.get('gaps') and not record.get('context_gaps')
        and not record.get('unverified_paths'))
    # Recognize only the exact notes generated for these structured reasons.
    # Unknown/historical prose remains a check gap rather than being hidden.
    notes = {_ATTRIBUTION_LABEL + (f"（{item['count']} 项）" if item.get('count') else '')
             for item in attribution}
    return (('static_check', 'COMPLETED' if static_complete else 'INCOMPLETE'),
            ('source_review', 'COMPLETED' if source_complete else 'INCOMPLETE'),
            ('change_attribution', 'UNCONFIRMED')), notes


def gap_notes(values):
    notes = []
    for value in values or []:
        if isinstance(value, str):
            note = _GAPS.get(value, value)
        elif isinstance(value, dict):
            note = (capture_gap_note(value) if value.get('reason') == CAPTURE_GAP else
                    _GAPS.get(value.get('reason'), '部分代码或检查依据尚未完成核对。'))
            paths = value.get('paths') or ([value['path']] if value.get('path') else [])
            if isinstance(paths, list) and paths:
                note += ' 涉及：'+'、'.join(str(p) for p in paths[:5])+'。'
        else:
            continue
        if note and note not in notes:
            notes.append(note)
    return tuple(notes)


def task_facts(record, host_feedback=None, static_feedback=None, *, handling_available=True):
    phase = record['phase']
    static, review = record.get('static') or {}, record.get('review') or {}
    limitations = record.get('limitations') or record.get('baseline', {}).get('limitations') or []
    raw = len(static.get('findings', []))+len(review.get('findings', []))
    state = phase
    complete = (static.get('status') in {'SUCCESS', 'COMPLETED'}
                and static.get('coverage') in {'FULL', 'SCOPED'})
    details, attribution_notes = _attribution_details(record, limitations, complete)
    if phase == 'COMPLETE' and (not complete or review.get('coverage') != 'REVIEWED'
                               or limitations or review.get('limitations')):
        state = 'PARTIAL'
    notices = []
    if phase in {'COMPLETE', 'INCOMPLETE'}:
        notices.extend(_capability_notices(static))
        capability_gaps = any(key in {'CODE_SAST', 'SECRET_SCAN', 'DEPENDENCY_VULN', 'IAC_MISCONFIG'}
                              and value in _CAPABILITY_GAPS
                              for key, value in (static.get('capability_results') or {}).items())
        if not complete and not capability_gaps:
            notices.append(Notice('CHECK_GAP', '静态检查未完成或覆盖受限，未检查范围的风险尚待核实。'))
        check_gaps = [item for item in limitations if not (
            isinstance(item, dict) and item.get('reason') == _ATTRIBUTION_REASON)]
        check_gaps.extend(note for note in review.get('limitations') or []
                          if not (isinstance(note, str) and note in attribution_notes))
        for note in gap_notes(display_limitations(record, check_gaps)):
            notices.append(Notice('CHECK_GAP', note))
        if details:
            notices.append(Notice('ATTRIBUTION',
                '同一工作区存在任务时间窗重叠，无法独立确认本次改动的归属。'))
            if dict(details)['source_review'] != 'COMPLETED':
                notices.append(Notice('CHECK_GAP', '必读代码复核尚未完成或缺少完成记录。'))
        if phase == 'INCOMPLETE':
            notices.append(Notice('CHECK_GAP', record.get('skip_reason') or '代码复核尚未完成，已有检查记录保留。'))
        if not complete and record.get('hook_final_recheck_files'):
            names = record['hook_final_recheck_files']
            notices.append(Notice('PRIOR_VERIFICATION', '文件修改检查保留范围的当前风险尚待核实：'+
                '、'.join(names[:5])+'；本次最终检查不足以证明先前提示已消除。'))
    if not handling_available:
        notices.append(Notice('HANDLING_UNAVAILABLE', '风险处置记录暂时无法读取，本次不重复要求选择；尚未确认风险已消除。'))
    if record.get('review_capacity') and phase not in {'COMPLETE', 'INCOMPLETE', 'NO_CHANGES'}:
        state = 'CAPACITY_REQUIRED'
        notices.append(Notice('CHECK_GAP', '全部必读范围需要的资源超过当前可承载容量，代码复核尚未开始；已有记录保留，未省略文件。'))
    risks = ()
    if phase in {'COMPLETE', 'INCOMPLETE'}:
        risks = tuple(finding_fact(f, feedback=(static_feedback or {}).get(f['id']))
                      for f in static.get('findings', []))
        risks += tuple(finding_fact(f, source='HOST_REVIEW', feedback=(host_feedback or {}).get(f['id']))
                       for f in review.get('findings', []))
    if phase == 'NO_CHANGES' and limitations:
        notices.extend(Notice('CHECK_GAP', note) for note in gap_notes(limitations))
    return ReplyFacts('TASK', CheckFact(state, len(record.get('changes', [])),
        len(static.get('scope_files', [])), raw,
        capabilities=tuple((static.get('capability_results') or {}).items()), details=details), risks, tuple(notices), handling_available,
        quiet=phase not in {'COMPLETE', 'INCOMPLETE'} and not notices)


def history_facts(record, selected, *, current=True, feedback=None,
                  static_feedback=None, handling_available=True, delivery=False,
                  total_risk_count=None):
    """One bounded projection, with current delivery authorized by the service.

    The default remains a history read. Neither a current file hash nor reading
    a saved report is a reason to repeat a repair choice.
    """
    facts = task_facts(record, host_feedback=feedback, static_feedback=static_feedback,
                       handling_available=handling_available)
    risks = tuple(finding_fact(item['detail'],
        source='HOST_REVIEW' if item['source'] == 'HOST_TASK_REVIEW' else 'SCANNER',
        feedback=(item['detail'].get('feedback') or {}),
        choice_required=delivery and (item['source'] == 'HOST_TASK_REVIEW'
                                     or bool((record.get('static') or {}).get('scan_id'))))
        for item in selected if item.get('details_complete') and not item['detail'].get('prior_report'))
    # Historical pages retain the complete explanations in their existing
    # fields. They never imply a fresh check or replay a repair prompt.
    return ReplyFacts('TASK_DELIVERY' if delivery else 'HISTORY', facts.check, risks,
                      facts.notices, handling_available=handling_available,
                      current=current,
                      quiet=delivery and record['phase'] == 'NO_CHANGES' and not facts.notices,
                      total_risk_count=total_risk_count)


def issue_facts(feedback, *, notes=(), authorized=False, investigate_first=False, original=False):
    location = feedback['location']
    risk = RiskFact(feedback.get('finding_id', ''), feedback['title'], location['file'],
        location['line'], feedback['problem'], feedback['impact'], feedback['recommendation'],
        notes=tuple(notes), original=original, authorized=authorized,
        investigate_first=investigate_first)
    return ReplyFacts('ISSUE', risks=(risk,))


def summary_facts(result):
    counts = result['risk_handling']
    context = result.get('scan_context', {})
    current = context.get('full_project_reusable') is True
    state = 'COMPLETE' if result['scan_coverage'] in {'FULL', 'SCOPED'} else 'PARTIAL'
    notices = [Notice('CHECK_RESULT', f"待处理 {counts['pending_finding_count']} 项，已暂缓 {counts['deferred']} 项，"
                      f"用户排除 {counts['excluded_by_user']} 项，AI 复核排除 {counts['excluded_by_agent']} 项。")]
    if not current:
        notices.append(Notice('APPLICABILITY', '这是已保存的检查结果，不能代替当前完整项目检查；已保存处置另行保留。'))
    return ReplyFacts('QUERY', CheckFact(state, raw_findings=counts['raw_finding_count'],
        capabilities=tuple(result.get('capability_results', {}).items())),
                      notices=tuple(notices), current=current)


def handling_facts(result):
    messages = {
        'AGENT_FALSE_POSITIVE': 'Agent 根据当前代码复核认为此告警是误报，已停止重复提醒；原告警和复核依据保留，可恢复提醒。',
        'FALSE_POSITIVE': 'AI 复核认为此告警不成立；提醒状态按你的处置决定保留。',
        'USER_MARKED_UNCONFIRMED': '已记录你的误报意见，尚未形成有效复核结论。',
        'REVIEW_STALE': '此前复核依据已变化或无法读取，原结论需要重新核查。',
        'STILL_RISK': 'Agent 复核后仍认为存在风险；技术判断和处理历史保留，尚未授权修复。',
        'NEEDS_CONTEXT': '现有证据不足以判断，具体缺少的信息保留在复核说明中。',
        'UNREVIEWED': '这条告警尚无当前有效的复核结论。',
    }
    message = messages.get(result['state'], messages['UNREVIEWED'])
    source = result.get('handling_source')
    if source == 'ORIGINATING_SCANNER_RECHECK' and result.get('handling_status') == 'RESOLVED':
        message = '原问题已由原扫描规则复查确认修复；原始告警、技术评估和复查记录保留。'
    elif source == 'USER_DECISION':
        message = ('已暂缓此项，本次不再重复追问；技术评估和原告警仍保留。'
                   if result['handling_status'] == 'DEFERRED' else
                   '已按你的决定排除此项，不再重复提醒；技术评估和原告警仍保留，可随时恢复。')
        if ((result.get('disposition') or {}).get('decision') or {}).get('metadata', {}).get('historical_only'):
            message += ' 当前源码不可定位，此决定仅关联这次历史告警，后续扫描需重新识别。'
    elif source == 'USER_RESTORE':
        message = '已恢复此项提醒；原告警、技术评估及处置历史仍保留。'
    elif result.get('folded') and not result.get('technical_false_positive'):
        message += ' 提醒依据未发生实质变化，仍沿用此前不重复提醒的处置；最新技术评估单独保留。'
    return ReplyFacts('HANDLING', notices=(Notice('HANDLING_RECEIPT', message),))


def repair_impact_facts(result, *, history=False, allow_business_choice=True,
                        handling_available=True, suppressed=False):
    """Project validated domain results without creating a repair choice or grant.

    Callers retain redaction, ownership, source freshness and saved handling.
    Reading an existing report may show its analysis, but never requests a choice.
    """
    proposal = result.get('proposal') or {}
    effects = result.get('impacts') or []
    unknowns = result.get('unknowns') or []
    current = result.get('lifecycle') in {'CURRENT', 'PARTIAL'}
    # PARTIAL can describe current evidence, but never supplies a ready verdict.
    if result.get('gate') == 'REASSESS_REQUIRED':
        current = False

    def summaries(kind):
        def describe(item):
            details = [label+'：'+'、'.join(item[key]) for key, label in (
                ('affected_roles', '角色'), ('affected_operations', '操作'),
                ('affected_modules', '模块'), ('interfaces', '接口')) if item.get(key)]
            return item['summary'] + ('（'+'；'.join(details)+'）' if details else '')
        return tuple(describe(item) for item in effects if item.get('kind') == kind)

    def unknown_summaries(critical):
        return tuple(item['summary'] for item in unknowns
                     if bool(item.get('critical')) is critical)

    alternatives = tuple(dict.fromkeys(text for item in effects
                                      for text in item.get('alternatives', [])))
    page_unknowns = ()
    if (result.get('impact_count', len(effects)) > len(effects)
            or result.get('unknown_count', len(unknowns)) > len(unknowns)):
        page_unknowns = ('本页尚未展示全部影响或未知项，需查看后续报告；未展示不等于不存在。',)
    impact = RepairImpactFact(result.get('assessment_ref', ''), proposal.get('summary', ''),
        security_goal=proposal.get('security_goal', ''),
        proposal_revision=result.get('proposal_revision', ''),
        expected_restrictions=summaries('EXPECTED_SECURITY_RESTRICTION'),
        behavior_changes=summaries('BUSINESS_BEHAVIOR_CHANGE'),
        preserved_behaviors=tuple(proposal.get('preserve') or ()),
        no_additional_changes=summaries('NO_ADDITIONAL_CHANGE_IDENTIFIED'),
        unknowns=unknown_summaries(False) + summaries('UNDETERMINED') + page_unknowns,
        critical_unknowns=unknown_summaries(True), alternatives=alternatives,
        gate=result.get('gate', ''), current=current, suppressed=suppressed,
        choice_required=(allow_business_choice and not history
                         and result.get('gate') == 'BUSINESS_CHOICE_REQUIRED'),
        read_only=history or not allow_business_choice)
    notices = (() if handling_available else (Notice('HANDLING_UNAVAILABLE',
        '风险处置记录暂时无法读取，本次不重复要求选择；原记录保留。'),))
    return ReplyFacts('REPAIR_IMPACT_HISTORY' if history else 'REPAIR_IMPACT',
        notices=notices, handling_available=handling_available, current=current,
        repair_impacts=(impact,))
