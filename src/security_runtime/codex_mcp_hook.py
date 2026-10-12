"""PostToolUse transport POC: host claims in, existing Hook advisory out."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .hook_adapters import CodexHookAdapter
from .hook_runtime import HookCoordinator
from .hook_state import no_links
from .integration_state import WorkspaceBinding
from .hook_timing import timings, elapsed, core_context


def codex_mcp_hook_config() -> dict:
    """Generate only a POC document; never install, merge or trust hooks."""
    return {'hooks': {'PostToolUse': [{
        'matcher': '^(Bash|apply_patch|Edit|Write)$',
        'hooks': [{
            'type': 'mcp_tool', 'server': 'ai_security_runtime',
            'tool': 'handle_hook_event',
            'input': {'event': '${hook_event_name}', 'workspace_path': '${cwd}',
                      'session_id': '${session_id}', 'tool_name': '${tool_name}',
                      'turn_id': '${turn_id}', 'tool_use_id': '${tool_use_id}',
                      'permission_mode': '${permission_mode}',
                      'tool_input': '${tool_input}'},
            'timeout': 120, 'statusMessage': 'AI Security Runtime [mcp-hook-poc]',
        }],
    }]}}


# Public compatibility aliases; raw parsing now lives in the Codex adapter.
from .host_event_runtime import inconclusive as _inconclusive
from .codex_event_adapter import classify_bash_command, CodexEventAdapter


def _bash_no_scan(result, classification, reason):
    result.update(status='NOT_SCANNED', coverage='NOT_APPLICABLE', scanner_run=False,
                  tool_classification=classification, workspace_mutation_observed=False,
                  changed_file_count=0, scanner_trigger_reason=None,
                  scanner_skipped_reason=reason)
    return result


def handle_codex_hook(event: str, workspace_path: str, session_id: str, tool_name: str,
                      tool_input=None,
                      *, binding: WorkspaceBinding | None,
                      coordinator: HookCoordinator | None = None, remediation=None,
                      turn_id=None, tool_use_id=None, permission_mode=None, claim_guard=None) -> dict:
    started = time.perf_counter()
    decision = None
    validated_root = None
    claim_diag = None
    normalized = None
    adapter = CodexEventAdapter()
    args = dict(event=event, workspace_path=workspace_path, session_id=session_id,
                tool_name=tool_name, turn_id=turn_id, tool_use_id=tool_use_id,
                permission_mode=permission_mode, tool_input=tool_input)
    claims = (event, workspace_path, session_id, tool_name)
    limits = (32, 4096, 500, 64)
    if any(not isinstance(value, str) or not value.strip() or len(value) > limit
           or '${' in value or any(ord(char) < 32 for char in value)
           for value, limit in zip(claims, limits)) or event != 'PostToolUse':
        result = _inconclusive('INVALID_HOST_CLAIMS')
        if claim_guard is not None:
            claim_diag = adapter.validate_claims(args, 'PostToolUse')
    elif tool_name not in {'Bash', 'apply_patch', 'Edit', 'Write'}:
        result = _inconclusive('INVALID_HOST_CLAIMS' if claim_guard else 'UNSUPPORTED_TOOL')
        if claim_guard is not None:
            claim_diag = adapter.validate_claims(args, 'PostToolUse')
    else:
        normalized, claim_diag, reason = adapter.bind_project(args, binding=binding,
            guard=claim_guard, expected='PostToolUse', legacy=claim_guard is None)
        if reason:
            result = _inconclusive(reason)
        else:
            validated_root = normalized.context.workspace
            classification = adapter.legacy_classification(normalized)
            from .recent_hooks import observe
            observe('CLAIMS_VALID', tool_classification=classification, **(claim_diag or {}))
            try:
                from .host_event_runtime import handle_normalized_event
                if classification != 'READ_ONLY':
                    active_coordinator = coordinator or HookCoordinator()
                    active_coordinator.store.pending_activity(validated_root, 'codex', session_id, mark=True)
                    from .closeout_state import CloseoutStateStore
                    from .hook_state import identity
                    jobs = CloseoutStateStore(active_coordinator.store.workspace_directory(validated_root) / 'closeout.db',
                                             lambda: active_coordinator.store.key(validated_root))
                    previous_job = jobs.latest(identity(os.path.normcase(str(validated_root))), identity('codex\0' + session_id))
                    if previous_job and previous_job['status'] != 'COMPLETED':
                        jobs.mark_pending(previous_job['closeout_ref'], previous_job['workspace_id'])
                result, decision = handle_normalized_event(normalized,
                    coordinator=coordinator or HookCoordinator(), remediation=remediation,
                    started=started)
                result['tool_classification'] = classification
                # Existing Codex ABI, not a Core operation or mutation proof.
                result['scanner_trigger_reason'] = ('POST_TOOL_USE_MUTATION'
                    if result.get('workspace_mutation_observed') is True else None)
                if classification == 'READ_ONLY':
                    result['reason'] = result['scanner_skipped_reason'] = 'READ_ONLY_BASH'
            except Exception:
                observe('HANDLER_ERROR', handler_reason='HOOK_CHECK_INCONCLUSIVE')
                result = _inconclusive('HOOK_CHECK_INCONCLUSIVE')

    delta = result['delta']
    summary = {key: result[key] for key in ('status', 'coverage', 'scan_id', 'execution',
                                           'baseline_available', 'duration_ms')}
    for key in ('tool_classification', 'workspace_mutation_observed', 'changed_file_count',
                'scanner_trigger_reason', 'scanner_skipped_reason', 'snapshot_file_count', 'snapshot_available',
                'snapshot_source', 'snapshot_generation', 'pre_snapshot_match', 'content_delta_detected', 'reconciliation_reason',
                'normalized_scanner_trigger_reason', 'first_scan_attribution_attempted',
                'pre_edit_targeted_scan_run', 'pre_edit_targeted_scan_count', 'first_scan_attribution_status',
                'pre_existing_risk_count', 'newly_attributed_risk_count', 'attribution_scanner_equivalent',
                'first_scan_attribution_reason', 'first_scan_attribution_ms'):
        if key in result:
            summary[key] = result[key]
    summary.update(transport='codex-mcp-hook-poc', scanner_run=result['execution']['scanner_run'],
                   new_families=delta['new'], persisting_families=delta['persisting'],
                   resolved_families=delta['resolved'],
                   additional_occurrences=delta['additional_occurrences'],
                   removed_occurrences=delta['removed_occurrences'],
                   reused=result['status'] in {'NO_CHANGE', 'REUSED_LAST_RESULT'},
                     debounced=result['status'] == 'DEBOUNCED')
    summary['check_source'] = 'SYNCHRONOUS_HOOK_CHECK'
    if normalized is not None:
        summary.update(normalized.diagnostics())
    if claim_diag is not None:
        summary.update(claim_diag)
        if claim_diag['host_claim_status'] != 'VALID':
            summary['scanner_skipped_reason'] = result['reason']
    measured = timings()
    measured.update(result.get('timing_ms', {}))
    if decision is not None:
        measured.update({k: v for k, v in decision.get('timing_ms', {}).items() if v is not None})
    measured['hook_total'] = elapsed(started)
    summary.update(timing_ms=measured, execution_context=core_context())
    from .scanner_cache import lifetime
    summary.update(lifetime())
    summary['remediation_cycle_wall_ms'] = decision.get('remediation_cycle_wall_ms') if decision else None
    summary['remediation_cycle_measurement'] = decision.get('remediation_cycle_measurement') if decision else {
        'status': 'NOT_APPLICABLE', 'reason_code': 'NO_REMEDIATION_EPISODE'}
    for key in ('remediation_cycle_timepoints_ms', 'remediation_cycle_breakdown_ms',
                'remediation_cycle_boundary', 'remediation_cycle_detail_ms',
                'remediation_cycle_breakdown_measurement'):
        summary[key] = decision.get(key) if decision else None
    summary['duration_ms'] = round(measured['hook_total'])
    if 'scanner_diagnostics' in result:
        summary['scanner_diagnostics'] = result['scanner_diagnostics']
    for key in ('current_dependency_finding_ids', 'dependency_user_feedback', 'capabilities', 'dependency_check_reason', 'target_selection', 'unattributed_code_risk_count',
                'code_check_scope', 'scan_scope_notice', 'deferred_code_providers'):
        if key in result:
            summary[key] = result[key]
    if 'reason' in result:
        summary['reason'] = result['reason']
    if 'last_check_status' in result:
        summary['last_check_status'] = result['last_check_status']
    for key in ('baseline_source', 'baseline_seed_status'):
        if key in result:
            summary[key] = result[key]
    output = CodexHookAdapter().output({'hook_event_name': 'PostToolUse'}, result)
    if decision is None and result['execution']['scanner_run'] is True and result.get('dependency_user_feedback'):
        # Non-Git workspaces use the advisory-only Hook. Actual dependency
        # findings still need a readable choice, with navigation but no grant.
        feedback = result['dependency_user_feedback']
        message = feedback['message']
        decision = {'action': 'ADVISE', 'reason_code': 'DEPENDENCY_RISK_REVIEW_REQUIRED',
                    'feedback_required': False, 'user_feedback': feedback,
                    'review_finding_ids': result.get('dependency_review_finding_ids', []),
                    'review_continuation': {'tool': 'get_security_summary', 'arguments': {
                        'workspace_path': str(validated_root), 'scan_id': result['scan_id'], 'details': True}}}
        output.update({'continue': False, 'stopReason': message, 'systemMessage': message})
    if decision is not None:
        summary['remediation'] = decision
        if decision.get('review_continuation') and decision.get('user_feedback'):
            # Review navigation identifies only the displayed candidates. A
            # recommended first task must never replace the user's selection.
            decision.setdefault('review_finding_ids', result.get('dependency_review_finding_ids', []))
        if decision.get('feedback_required') is True and decision['action'] == 'AUTO_FIX':
            # PostToolUse cannot undo the edit. A blocking decision rejects the
            # nested Code Mode promise after it ran; use non-reject feedback.
            # The returned grant and structured guidance still control repair;
            # these presentation fields never issue or broaden authorization.
            message = '已收到修复确认，正在修复这个问题；完成后会重新检查。'
            output.update({'continue': False, 'stopReason': message, 'systemMessage': message})
        elif decision.get('feedback_required') is True and decision['action'] == 'CONFIRM_REQUIRED':
            # PostToolUse side effects already happened. Unlike block, this
            # documented feedback path does not reject the Code mode promise.
            # Asking/waiting is host guidance, not an automatic model halt.
            message = decision.get('user_feedback', {}).get('message') or (
                '自动检查发现一个安全风险。请查看本次检查的受影响位置、可能影响和修复建议。'
                '回复“修复”，我会修复并重新检查；回复“忽略”，本次不修复，风险记录仍保留。')
            # User-visible Hook fields carry plain copy; the control protocol
            # remains in additionalContext, never an implicit repair grant.
            output.update({'continue': False, 'stopReason': message, 'systemMessage': message})
        elif decision['action'] in {'ADVISE', 'MANUAL_ONLY', 'ESCALATE'}:
            # Advisory and failed-recheck feedback must be understandable too.
            # User presentation and repair authorization are separate effects.
            output['systemMessage'] = (decision.get('user_feedback', {}).get('message') or
                                       decision.get('user_message') or
                                       '安全检查或修复流程尚未完成。请先核查问题详情；'
                                       '当前结果不能证明风险已消除。')
        elif decision['action'] == 'NONE':
            output['systemMessage'] = ('这个问题已修复，并通过了原规则的重新检查。'
                                       if decision['reason_code'] == 'SCANNER_VERIFIED_RESOLVED' else
                                       decision.get('user_feedback', {}).get('message') or
                                       '检查发现一个安全风险，但缺少改动前的检查记录，'
                                       '暂时无法确认是否由本次改动引入。请查看问题详情后选择是否修复。'
                                       if result.get('reason') == 'FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT' else
                                       output['systemMessage'] if result.get('coverage') not in {'FULL', 'NOT_APPLICABLE'} else '')
        feedback = decision.get('user_feedback') or {}
        if (result['execution']['scanner_run'] is True and
                (feedback.get('choices') or feedback.get('selection_required') is True) and
                decision['action'] in {'ADVISE', 'MANUAL_ONLY', 'ESCALATE', 'NONE'}):
            # A repeated episode still needs a user-facing risk choice. This is
            # the documented non-reject PostToolUse feedback route, not a grant
            # or a request to undo/retry the edit. Cached/read-only events do not
            # create another interruption or refresh evidence/consent.
            output.update({'continue': False, 'stopReason': output['systemMessage']})
    # Bounded metadata only; no families, findings, file contents or scanner errors.
    if (remediation is not None and validated_root is not None and decision is not None and
            decision.get('action') in {'AUTO_FIX', 'CONFIRM_REQUIRED'}):
        observation = remediation.mark_initial_hook_response_ready(
            validated_root, decision.get('episode_id'), time.perf_counter())
        decision.update(observation)
        summary.update(observation)
    # The text channel is the Host's actual developer context. Put the fixed
    # user-facing explanation first and keep operational refs separate; the
    # complete diagnostic record remains in SDK structuredContent/local logs.
    from .hook_reply_context import render_hook_context
    output['hookSpecificOutput']['additionalContext'] = render_hook_context(
        summary, decision, output.get('systemMessage', ''))
    return {**summary, **output}


def codex_hook_output(result: dict) -> dict:
    """The documented Hook output shape for the MCP text content channel."""
    return {key: result[key] for key in ('systemMessage', 'hookSpecificOutput', 'decision', 'reason',
                                        'continue', 'stopReason') if key in result}
