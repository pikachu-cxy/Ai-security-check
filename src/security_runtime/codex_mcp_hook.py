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


MAX_TASK_HOOK_CHECKS = 256


def _bounded_task_paths(paths, *, count=1000, bytes_limit=128_000):
    from .hook_runtime import safe_path
    ordered = sorted({safe_path(name) for name in paths})
    selected, size = [], 0
    for name in ordered:
        cost = len(name.encode('utf-8'))
        if len(selected) >= count or size + cost > bytes_limit:
            break
        selected.append(name)
        size += cost
    return selected, len(ordered)-len(selected)


def _record_task_hook(hooks, root, result, decision):
    """Link edit checks to the signed task, without source or repair tokens.

    Scanner records remain in their existing store. This bounded ledger makes
    deferred/failed checks visible at task closeout and is diagnostic only;
    it never turns a historical finding into a current risk or grants repair.
    """
    from .task_security_state import TaskSecurityStore
    import sqlite3
    store = TaskSecurityStore(hooks, root)
    try:
        task = store.get(active=True)
    except (ValueError, OSError, sqlite3.DatabaseError):
        return None, 'UNAVAILABLE'
    if not task:
        return None, 'NOT_APPLICABLE'
    if result.get('tool_classification') == 'READ_ONLY' or result.get('workspace_mutation_observed') is False:
        return task, 'NO_MUTATION'
    row = {key: result[key] for key in ('status', 'last_check_status', 'coverage', 'scan_id',
        'change_digest', 'workspace_mutation_observed', 'changed_file_count', 'capabilities',
        'deferred_code_providers', 'dependency_check_reason') if key in result}
    row.update(scanner_run=result['execution']['scanner_run'],
        delta={key: result['delta'].get(key, 0) for key in (
            'new', 'persisting', 'resolved', 'additional_occurrences', 'removed_occurrences')})
    scope = result.get('hook_scope_files', [])
    row['scope_files'], row['scope_files_omitted'] = _bounded_task_paths(scope, count=20, bytes_limit=2048)
    row['scope_file_count'] = len(scope)
    if decision:
        row['remediation'] = {key: decision[key] for key in (
            'action', 'reason_code', 'episode_id', 'episode_number') if key in decision}
    for attempt in range(2):
        try:
            complete = (result['status'] == 'SCANNED' and result.get('last_check_status') == 'SCANNED'
                and result.get('coverage') in {'FULL', 'SCOPED'} and bool(result.get('capabilities'))
                and all(isinstance(state, str) and state in {'EXECUTED', 'NOT_APPLICABLE'}
                        for state in result['capabilities'].values())
                and not result.get('deferred_code_providers') and not result.get('dependency_check_reason')
                and result['execution']['scanner_run'])
            retained = set(task.get('hook_recheck_files', ()))
            pending = set(task.get('hook_pending_scope_files', ()))
            if complete:
                retained.difference_update(scope)
                pending.difference_update(scope)
            else:
                pending.update(scope)
            retained.update(result.get('hook_recheck_files', ()))
            task['hook_recheck_files'], omitted = _bounded_task_paths(retained)
            task['hook_recheck_paths_omitted'] = task.get('hook_recheck_paths_omitted', 0) + omitted
            task['hook_pending_scope_files'], omitted = _bounded_task_paths(pending)
            task['hook_pending_paths_omitted'] = task.get('hook_pending_paths_omitted', 0) + omitted
            rows = [*task.get('hook_checks', []), row]
            task.update(hook_checks=rows[-MAX_TASK_HOOK_CHECKS:],
                hook_checks_omitted=task.get('hook_checks_omitted', 0) + max(0, len(rows)-MAX_TASK_HOOK_CHECKS))
            return store.save(task), 'RECORDED'
        except (ValueError, OSError, sqlite3.DatabaseError):
            if attempt == 0:
                try:
                    refreshed = store.get(active=True)
                    if refreshed and refreshed['task_ref'] == task['task_ref']:
                        task = refreshed
                        continue
                except (ValueError, OSError, sqlite3.DatabaseError):
                    pass
            try:
                store.record_hook_failure(task['task_ref'], task_created_at=task['created_at'],
                    scope_files=set(scope) | set(result.get('hook_recheck_files', ())) |
                        set(task.get('hook_recheck_files', ())) | set(task.get('hook_pending_scope_files', ())),
                    scan_id=result.get('scan_id'))
                return task, 'FAILURE_MARKER_RECORDED'
            except (ValueError, OSError, sqlite3.DatabaseError):
                return task, 'UNAVAILABLE'


def _deferred_task_context(summary):
    """No per-edit user prompt or pending repair instruction in Host text."""
    from .hook_reply_context import CONTROL_DELIMITER
    control = {key: summary[key] for key in ('security_task_ref', 'status', 'last_check_status',
        'coverage', 'scan_id', 'scanner_run', 'new_families', 'persisting_families', 'resolved_families',
        'additional_occurrences', 'removed_occurrences', 'capabilities', 'deferred_code_providers',
        'dependency_check_reason', 'hook_check_recording', 'unpersisted_hook_scope_files',
        'unpersisted_hook_scope_files_omitted') if key in summary}
    control.update(feedback_delivery='TASK_FINAL_SUMMARY', user_feedback_suppressed=True,
                   repair_authorized=False)
    failure = ('本次文件修改检查的任务记录保存失败；已保留独立失败记录，任务结束必须复查其中的范围并披露历史记录缺口。'
               if summary.get('hook_check_recording') == 'FAILURE_MARKER_RECORDED' else
               '本次文件修改检查的任务记录与独立失败记录均未能保存；最终总结必须明确记录保存失败及可能遗漏的检查范围，'
               '不得声称这些结果已持久保留，也不得将未复查范围认定为安全。'
               if summary.get('hook_check_recording') == 'UNAVAILABLE' else '')
    return ('任务内检查记录（仅供工具使用，不展示给用户）\n'
        '当前是已登记的开发任务。继续用户已授权的开发工作；本次逐次静态检查与风险记录以实际工具记录为准，'
        '不要立即呈现钩子反馈、暂停开发或要求用户作出安全处理选择。'
        '任务结束时完成整次任务安全核查，把当前风险、检查范围和未完成项一次合并进开发总结；'
        '仍存在的问题由用户选择处理，已经验证消除的历史问题不能作为当前待处理风险。'
        '检查失败、缺失组件或延期检查不代表安全。'
        '本次检查没有授予修复权限，未经明确批准不得修复安全风险。'
        + failure
        + CONTROL_DELIMITER + json.dumps(control, ensure_ascii=False, separators=(',', ':')))


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
    active_coordinator = coordinator
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
                active_coordinator = coordinator or HookCoordinator()
                if classification != 'READ_ONLY':
                    active_coordinator.store.pending_activity(validated_root, 'codex', session_id, mark=True)
                    from .closeout_state import CloseoutStateStore
                    from .hook_state import identity
                    jobs = CloseoutStateStore(active_coordinator.store.workspace_directory(validated_root) / 'closeout.db',
                                             lambda: active_coordinator.store.key(validated_root))
                    previous_job = jobs.latest(identity(os.path.normcase(str(validated_root))), identity('codex\0' + session_id))
                    if previous_job and previous_job['status'] != 'COMPLETED':
                        jobs.mark_pending(previous_job['closeout_ref'], previous_job['workspace_id'])
                result, decision = handle_normalized_event(normalized,
                    coordinator=active_coordinator, remediation=remediation,
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
                'first_scan_attribution_reason', 'first_scan_attribution_ms',
                'security_task_ref', 'task_edit_check_policy'):
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
                'code_check_scope', 'scan_scope_notice', 'deferred_code_providers', 'background_preparation'):
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
    if result.get('background_preparation'):
        note = result['background_preparation']['message'] + ' 可用组件按本次实际结果说明；缺失项保留待检，不代表安全。'
        output['systemMessage'] = (output.get('systemMessage', '') + '\n' + note).strip()
        output['hookSpecificOutput']['additionalContext'] += '\n' + note
    # Already selected repair continuation/verification retains its exact
    # handoff. Task-level deferral neither changes nor broadens that authority.
    repair_flow = bool(decision and (decision.get('action') == 'AUTO_FIX' or
        decision.get('episode_id') and decision.get('verification') and decision.get('attempt_count', 0) > 0))
    if validated_root is not None and active_coordinator is not None:
        task, recording = _record_task_hook(active_coordinator.store, validated_root, result, decision)
        if task:
            summary.update(security_task_ref=task['task_ref'], hook_check_recording=recording)
            if recording == 'UNAVAILABLE':
                scope = set(result.get('hook_scope_files', ())) | set(result.get('hook_recheck_files', ()))
                summary['unpersisted_hook_scope_files'], summary['unpersisted_hook_scope_files_omitted'] = (
                    _bounded_task_paths(scope, count=20, bytes_limit=2048))
            if not repair_flow and recording != 'NO_MUTATION':
                summary['feedback_delivery'] = 'TASK_FINAL_SUMMARY'
                output.pop('systemMessage', None)
                output.pop('stopReason', None)
                output['continue'] = True
                # Rebuild instead of appending to the immediate alert's
                # presentation rules and unapproved confirmation handoffs.
                output['hookSpecificOutput']['additionalContext'] = _deferred_task_context(summary)
    # Read-only/cached checks are useful diagnostics, not chat messages. Keep
    # actual risk feedback and an explicitly approved fix handoff intact.
    authorized = repair_flow
    unpersisted_gap = bool(summary.get('security_task_ref') and summary.get('hook_check_recording') == 'UNAVAILABLE')
    if not result['execution']['scanner_run'] and not authorized and not unpersisted_gap:
        output = {}
    elif not output.get('systemMessage') and not authorized and not summary.get('security_task_ref'):
        output = {}
    elif not unpersisted_gap and not decision and not result.get('dependency_user_feedback') and result.get('coverage') in {'FULL', 'NOT_APPLICABLE'} and not delta['new'] and not delta['additional_occurrences']:
        output = {}
    return {**summary, **output}


def codex_hook_output(result: dict) -> dict:
    """The documented Hook output shape for the MCP text content channel."""
    output = {key: result[key] for key in ('systemMessage', 'hookSpecificOutput', 'decision',
                                         'continue', 'stopReason') if key in result and result[key] != ''}
    # Diagnostic reason enums belong in structuredContent only. A reason is a
    # wire field exclusively for an actual continuation decision.
    if result.get('decision') == 'block' and 'reason' in result:
        output['reason'] = result['reason']
    return output
