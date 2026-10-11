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
    if 'reason' in result:
        summary['reason'] = result['reason']
    if 'last_check_status' in result:
        summary['last_check_status'] = result['last_check_status']
    for key in ('baseline_source', 'baseline_seed_status'):
        if key in result:
            summary[key] = result[key]
    output = CodexHookAdapter().output({'hook_event_name': 'PostToolUse'}, result)
    if decision is not None:
        summary['remediation'] = decision
        if decision.get('feedback_required') is True and decision['action'] == 'AUTO_FIX':
            # PostToolUse cannot undo the edit. A blocking decision rejects the
            # nested Code Mode promise after it ran; use non-reject feedback.
            fast = decision.get('fix_path') == 'DETERMINISTIC_FAST_FIX'
            compact = decision.get('security_context_status') == 'READY' and not fast
            inline = decision.get('agent_fix_ticket', {}).get('mode') == 'INLINE_PREPARED'
            output.update({'continue': False, 'stopReason': (
                'SECURITY_AUTO_REMEDIATION_AUTHORIZED. SECURITY_FIX_REQUIRED. '
                'Read the structured agent_fix_ticket target, apply its minimal edit, and let Hook verify. '
                'Do not call prepare_task_fix or recover references from prose.' if inline else
                'SECURITY_AUTO_REMEDIATION_AUTHORIZED. SECURITY_FIX_REQUIRED. '
                'The preceding edit is complete. Follow remediation.prepare and security_fix_context; '
                'do not repeat the edit or ask for approval.' if compact else
                'The preceding edit already executed successfully. Do not retry or repeat it. '
                'Runtime has authorized remediation, not the original insecure edit. '
                + ('Execute the authorized plan through the registered atomic Host bridge. ' if fast else
                 'Immediately call prepare_task_fix. ') + decision['guidance'])})
            output['systemMessage'] = ('Security Runtime: AUTO_FIX already prepared. Use agent_fix_ticket and context.' if inline else
                'Security Runtime: SECURITY_FIX_REQUIRED; AUTO_FIX authorized. '
                'Use the compact context and prepare handoff.' if compact else
                'Security Runtime: AUTO_FIX is already authorized. '
                                       'Do not ask the user for confirmation. Immediately continue with '
                                       + ('the Runtime-issued Fast Fix Plan.' if fast else
                                          'the Runtime-issued prepare_task_fix handoff.'))
        elif decision.get('feedback_required') is True and decision['action'] == 'CONFIRM_REQUIRED':
            # PostToolUse side effects already happened. Unlike block, this
            # documented feedback path does not reject the Code mode promise.
            # Asking/waiting is host guidance, not an automatic model halt.
            output.update({'continue': False, 'stopReason': decision['guidance']})
            output['systemMessage'] = ('Security Runtime: the file edit already executed. Do not repeat it. '
                                       'Explain the risk and ask whether to remediate it, then wait.')
        elif decision['action'] == 'NONE':
            output['systemMessage'] = ('Security Runtime verified the local repair.'
                                       if decision['reason_code'] == 'SCANNER_VERIFIED_RESOLVED' else
                                       'FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT: high-confidence risk is present; '
                                       'review existing candidates. No earlier baseline proves edit attribution; '
                                       'automatic remediation is not authorized.'
                                       if result.get('reason') == 'FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT' else '')
    # Bounded metadata only; no families, findings, file contents or scanner errors.
    if (remediation is not None and validated_root is not None and decision is not None and
            decision.get('action') in {'AUTO_FIX', 'CONFIRM_REQUIRED'}):
        observation = remediation.mark_initial_hook_response_ready(
            validated_root, decision.get('episode_id'), time.perf_counter())
        decision.update(observation)
        summary.update(observation)
    model_context = summary
    if decision is not None and decision.get('agent_fix_ticket'):
        # Same formal ticket, not a ref reconstructed from a report. Keep the
        # documented text channel small; SDK structuredContent remains complete.
        model_context = {k: summary[k] for k in ('status', 'coverage', 'scanner_run')}
        model_context['remediation'] = {k: decision[k] for k in (
            'action', 'reason_code', 'episode_id', 'grant_id', 'agent_fix_ticket',
            'security_fix_context', 'security_fix_context_ref', 'agent_fix_ticket_diagnostics',
            'next_action', 'guidance')}
    output['hookSpecificOutput']['additionalContext'] = json.dumps(model_context, ensure_ascii=True,
                                                                 separators=(',', ':'))
    return {**summary, **output}


def codex_hook_output(result: dict) -> dict:
    """The documented Hook output shape for the MCP text content channel."""
    return {key: result[key] for key in ('systemMessage', 'hookSpecificOutput', 'decision', 'reason',
                                        'continue', 'stopReason') if key in result}
