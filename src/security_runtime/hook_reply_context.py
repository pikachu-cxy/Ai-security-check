"""Small Host context: fixed user copy first, original control references second.

Only Runtime-generated messages and decisions belong here. Scanner/repository
prose and the full diagnostic record stay in structuredContent/local logs.
The soft budget omits informational context before operational capabilities;
issued tickets, tokens and handoffs are never shortened or reconstructed.
"""
from __future__ import annotations

import copy
import json
import re

from .guidance.risk_presentation import COMPACT_LANGUAGE_RULES, HOOK_PRESENTATION_RULES, LANGUAGE_RULES

CONTROL_DELIMITER = '\n\n内部控制（仅供工具使用，不展示给用户）\n'
MAX_CONTEXT_CHARS = 6000
MAX_CONTEXT_BYTES = 8000
PRESENTATION_RULES = (
    '先说明用户任务的结果，再说明具体问题、影响和下一步。'
    '不展示内部状态、英文枚举、工具名或令牌。'
    '“先不要修复”只表示暂不改代码，不等于忽略。'
    '没有明确选择或正式授权就不能修复；同一范围已经授权时不重复询问。'
) + HOOK_PRESENTATION_RULES
DEPENDENCY_PRESENTATION_RULES = (
    '依赖问题的“修复”应先按 review_continuation 读取问题列表，按 review_finding_ids 匹配成员取得精确任务引用；'
    '多个问题先明确选择，不能直接使用列表首项，也不能把导航当作修复授权。'
)
COMPACT_PRESENTATION_RULES = (
    '先写任务结果；保留提示的位置、问题、影响、建议、未知和“修复／稍后处理”（兼容“忽略”）的含义。'
    '先不要修复或保留改动不等于忽略；没有明确选择或正式授权就不能修复，同一范围已经授权时不重复询问。'
    '不展示内部状态、英文枚举、工具名或令牌；内部控制不能当作风险说明。'
    '上方提示为空时无需新增安全提示，不推断项目安全。'
)
CHECK_OPERATION_BOUNDARIES = (
    '不得伪造检查结果、重放检查事件或补建编辑后的基线。'
    '检查状态本身不授予额外扫描、构建或测试权限；不得仅因检查异常或复查结束而擅自追加这些操作。'
    '用户已明确要求或当前开发任务已包含的测试、构建与验收仍按原授权执行，无需重复确认。'
)

SUMMARY_FIELDS = ('status', 'coverage', 'scan_id', 'scanner_run', 'last_check_status',
                  'first_scan_attribution_status', 'reason')
COUNT_FIELDS = ('new_families', 'persisting_families', 'resolved_families',
                'pre_existing_risk_count', 'newly_attributed_risk_count')
REMEDIATION_FIELDS = (
    'action', 'reason_code', 'status', 'task_ref', 'confirmation_ref',
    'remediation_ref', 'episode_id', 'episode_number', 'episode_reason_code', 'grant_id', 'authorization_kind',
    'attempt_count', 'max_attempts', 'episode_stage', 'interaction',
    'confirmation', 'prepare', 'verify', 'confirmation_recovery', 'fix_handoff',
    'fix_path', 'fast_fix', 'agent_fix_ticket', 'security_fix_context',
    'security_fix_context_ref', 'security_context_status', 'verification',
    'verification_status', 'verification_required', 'security_verification', 'next_action', 'expires_in_seconds',
    'review_continuation', 'review_finding_ids',
    'verification_summary',
)
VERIFICATION_FIELDS = ('status', 'verification_status', 'reason_code', 'task_ref',
                       'scan_id', 'binding', 'phase', 'next_action')
_ENUM = re.compile(r'[A-Z0-9_/-]{1,160}\Z')


def _encode(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def _fits(value: str) -> bool:
    return len(value) <= MAX_CONTEXT_CHARS and len(value.encode('utf-8')) <= MAX_CONTEXT_BYTES


def _control(summary: dict, decision: dict | None) -> dict:
    control = {}
    for field in SUMMARY_FIELDS:
        value = summary.get(field)
        if field == 'scanner_run':
            if type(value) is bool:
                control[field] = value
        elif field == 'scan_id':
            if value is None or isinstance(value, str):
                control[field] = value
        elif isinstance(value, str) and _ENUM.fullmatch(value):
            control[field] = value
    for field in COUNT_FIELDS:
        value = summary.get(field)
        if type(value) is int and value >= 0:
            control[field] = value
    if isinstance(decision, dict):
        control['remediation'] = {field: copy.deepcopy(decision[field])
                                  for field in REMEDIATION_FIELDS if field in decision}
        if isinstance(control['remediation'].get('verification_summary'), dict):
            control['remediation']['verification_summary'] = {
                field: value for field, value in control['remediation']['verification_summary'].items()
                if field == 'security'}
        if isinstance(decision.get('verification'), dict):
            control['remediation']['verification'] = {
                field: copy.deepcopy(decision['verification'][field])
                for field in VERIFICATION_FIELDS if field in decision['verification']}
    return control


def render_hook_context(summary: dict, decision: dict | None, message: str) -> str:
    """Render a presentation instruction and a minimal JSON control document.

    Large informational fix context is omitted as one whole object, preserving
    its original reference and any issued ticket/prepare/verify handoffs. The
    full original object remains in the MCP structuredContent. Valid tickets
    have their own 4096-byte issuer budget; an unexpectedly oversized control
    packet fails closed for editing through this context and retains only
    exact navigation/references, rather than presenting a partial ticket.
    """
    message = message if isinstance(message, str) else ''
    presentation = PRESENTATION_RULES
    if message and isinstance(decision, dict) and decision.get('review_continuation'):
        presentation += DEPENDENCY_PRESENTATION_RULES
    if isinstance(decision, dict) and decision.get('reason_code') == 'SCANNER_VERIFIED_RESOLVED':
        presentation = (
            '将原问题安全复查结果合并到本轮正常总结中，不暂停原开发任务。'
            '不因安全复查结束而追加测试推荐、执行选择或新的修复确认。'
            '安全复查只说明原问题的复查结果，不推断业务兼容性或生产安全。'
            '不展示内部状态、工具名或令牌。' + CHECK_OPERATION_BOUNDARIES)
    if not message:
        presentation = '上方提示为空时无需新增安全提示，不推断项目安全，也不重复询问；内部控制不授予新的修复权限。'
    presentation = LANGUAGE_RULES + presentation
    prefix = '用户提示\n' + message + '\n\n呈现要求\n' + presentation + CONTROL_DELIMITER
    control = _control(summary, decision)
    rendered = prefix + _encode(control)
    if _fits(rendered):
        return rendered
    remediation = control.get('remediation', {})
    if 'security_fix_context' in remediation:
        remediation.pop('security_fix_context')
        remediation['informational_context_location'] = 'ORIGINAL_MCP_STRUCTURED_CONTENT'
        rendered = prefix + _encode(control)
        if _fits(rendered):
            return rendered
    ticket = remediation.get('agent_fix_ticket')
    if isinstance(ticket, dict) and ticket.get('mode') == 'INLINE_PREPARED':
        # The issued ticket already binds its path, episode, retry limit and
        # expiry. Drop accompanying diagnostics/repeated routing metadata before
        # sacrificing a complete prepared capability or its legacy handoffs.
        for field in ('fast_fix', 'fix_path', 'episode_number', 'episode_reason_code',
                      'status', 'security_context_status', 'verification_required',
                      'next_action', 'expires_in_seconds'):
            remediation.pop(field, None)
        rendered = prefix + _encode(control)
        if _fits(rendered):
            return rendered
        # Compact repeated display instructions, never the original ticket.
        presentation = COMPACT_LANGUAGE_RULES + COMPACT_PRESENTATION_RULES
        if remediation.get('review_continuation'):
            presentation += DEPENDENCY_PRESENTATION_RULES
        prefix = '用户提示\n' + message + '\n\n呈现要求\n' + presentation + CONTROL_DELIMITER
        rendered = prefix + _encode(control)
        if _fits(rendered):
            return rendered
    # Never send a cut-down ticket as though it were usable authorization.
    # The exact capabilities remain in the original structuredContent. Keep
    # original handoffs/tokens for navigation; do not invent a retrieval tool.
    navigation = ('action', 'reason_code', 'status', 'task_ref', 'confirmation_ref',
                  'remediation_ref', 'episode_id', 'grant_id', 'authorization_kind',
                  'security_fix_context_ref', 'confirmation', 'confirmation_recovery',
                  'prepare', 'verify', 'fix_handoff', 'review_continuation', 'review_finding_ids',
                  'verification_summary')
    control['remediation'] = {field: remediation[field] for field in navigation if field in remediation}
    control.update(context_budget_status='ORIGINAL_CONTROL_REQUIRED',
                   editing_allowed_from_this_context=False,
                   original_control_location='ORIGINAL_MCP_STRUCTURED_CONTENT')
    rendered = prefix + _encode(control)
    if _fits(rendered):
        return rendered
    return ('用户提示\n完整提示与控制信息超过输出限制，请读取原始工具结果后继续；'
            '当前精简上下文不允许编辑。\n\n呈现要求\n不得推断授权或检查通过。'
            + LANGUAGE_RULES
            + CONTROL_DELIMITER + _encode({
                'context_budget_status': 'ORIGINAL_CONTROL_REQUIRED',
                'editing_allowed_from_this_context': False,
                'original_control_location': 'ORIGINAL_MCP_STRUCTURED_CONTENT'}))


def render_check_gap_context(summary: dict, message: str) -> str:
    """An uncompleted check is user feedback, never a repair choice or grant."""
    return ('用户提示\n' + message + '\n\n呈现要求\n'
            + LANGUAGE_RULES +
            '仅当本轮实际修改源代码或配置，且总结时该改动的检查仍未完成，'
            '才在正常开发总结中说明一次缺口，不能声称通过。'
            '先说明任务结果，再用简短说明交代已知原因、未检查范围和下一步；检查缺口不等于发现漏洞或编辑失败。'
            '普通聊天、只读或未改动文件时不展示；后续检查完成时不保留旧提示，其他轮次不重复沿用。'
            '工具操作已结束，不因检查未完成而重复编辑、撤销代码或自行修复。'
            + CHECK_OPERATION_BOUNDARIES + '不要求用户提供内部引用。'
            + CONTROL_DELIMITER + _encode(_control(summary, None)))
