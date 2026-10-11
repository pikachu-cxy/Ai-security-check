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


CONTROL_DELIMITER = '\n\n内部控制（仅供工具使用，不展示给用户）\n'
MAX_CONTEXT_CHARS = 6000
MAX_CONTEXT_BYTES = 8000
PRESENTATION_RULES = (
    '回复必须保留提示中的位置、问题、可能影响、修复建议、未知条件和“修复／忽略”选择及含义；多问题按原提示选择。'
    '用直白中文，不展示内部状态、英文枚举、工具名、调用过程或令牌。'
    '“先不要修复”“观察自动检查”“保留改动”只表示暂不修改，不等于忽略，仍需说明风险并询问选择。'
    '没有明确选择或正式授权就不能修复；同一范围已经授权时不重复询问。'
    '内部控制仅用于原始交接与现有授权，不能当作风险说明。'
    '上方提示为空时无需新增安全提示，不推断项目安全，也不重复询问。'
)
DEPENDENCY_PRESENTATION_RULES = (
    '依赖问题的“修复”应先按 review_continuation 读取问题列表，按 review_finding_ids 匹配成员取得精确任务引用；'
    '多个问题先明确选择，不能直接使用列表首项，也不能把导航当作修复授权。'
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
    if isinstance(decision, dict) and decision.get('review_continuation'):
        presentation += DEPENDENCY_PRESENTATION_RULES
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
    # Never send a cut-down ticket as though it were usable authorization.
    # The exact capabilities remain in the original structuredContent. Keep
    # original handoffs/tokens for navigation; do not invent a retrieval tool.
    navigation = ('action', 'reason_code', 'status', 'task_ref', 'confirmation_ref',
                  'remediation_ref', 'episode_id', 'grant_id', 'authorization_kind',
                  'security_fix_context_ref', 'confirmation', 'confirmation_recovery',
                  'prepare', 'verify', 'fix_handoff', 'review_continuation', 'review_finding_ids')
    control['remediation'] = {field: remediation[field] for field in navigation if field in remediation}
    control.update(context_budget_status='ORIGINAL_CONTROL_REQUIRED',
                   editing_allowed_from_this_context=False,
                   original_control_location='ORIGINAL_MCP_STRUCTURED_CONTENT')
    return prefix + _encode(control)
