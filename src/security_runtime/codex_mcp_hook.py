"""PostToolUse transport POC: host claims in, existing Hook advisory out."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .hook_adapters import CodexHookAdapter
from .hook_runtime import HookCoordinator
from .hook_state import no_links
from .integration_state import WorkspaceBinding


def codex_mcp_hook_config() -> dict:
    """Generate only a POC document; never install, merge or trust hooks."""
    return {'hooks': {'PostToolUse': [{
        'matcher': '^(apply_patch|Edit|Write)$',
        'hooks': [{
            'type': 'mcp_tool', 'server': 'ai_security_runtime',
            'tool': 'handle_hook_event',
            'input': {'event': '${hook_event_name}', 'workspace_path': '${cwd}',
                      'session_id': '${session_id}', 'tool_name': '${tool_name}'},
            'timeout': 120, 'statusMessage': 'AI Security Runtime [mcp-hook-poc]',
        }],
    }]}}


def _inconclusive(reason: str) -> dict:
    # Do not echo host claims, paths, exception messages or rejected input.
    return {'status': 'INCONCLUSIVE', 'coverage': 'UNKNOWN', 'scan_id': None,
            'delta': dict(new=0, persisting=0, resolved=0,
                          additional_occurrences=0, removed_occurrences=0),
            'execution': dict(scanner_run=False, ai_called=False,
                              network_required=False, source_modified=False, target_build=False),
            'baseline_available': False, 'duration_ms': 0,
            'reason': reason,
            'next_step': 'Hook check was not completed. Verify the connected server workspace binding and refresh host claims.'}


def handle_codex_hook(event: str, workspace_path: str, session_id: str, tool_name: str,
                      *, binding: WorkspaceBinding | None,
                      coordinator: HookCoordinator | None = None, remediation=None) -> dict:
    decision = None
    claims = (event, workspace_path, session_id, tool_name)
    limits = (32, 4096, 500, 64)
    if any(not isinstance(value, str) or not value.strip() or len(value) > limit
           or '${' in value or any(ord(char) < 32 for char in value)
           for value, limit in zip(claims, limits)) or event != 'PostToolUse':
        result = _inconclusive('INVALID_HOST_CLAIMS')
    elif binding is None:
        result = _inconclusive('WORKSPACE_BINDING_REQUIRED')
    else:
        payload = dict(hook_event_name=event, cwd=workspace_path,
                       session_id=session_id, tool_name=tool_name)
        try:
            if not Path(workspace_path).is_absolute():
                raise ValueError('Absolute host cwd required')
            root = Path(binding.root)
            # Reject foreign/UNC paths lexically before probing the filesystem
            # or Git; a host claim must not cause access outside this binding.
            candidate = Path(os.path.abspath(workspace_path))
            if not candidate.is_relative_to(root):
                raise ValueError('Host cwd outside bound workspace')
            no_links(candidate)
            hook_event, session = CodexHookAdapter().translate(payload, root)
        except Exception:
            result = _inconclusive('HOST_CLAIMS_REJECTED')
        else:
            try:
                result = (coordinator or HookCoordinator()).handle(hook_event, root, 'codex', session)
                if remediation is not None:
                    decision = remediation.on_hook(result, root, session, host='codex')
            except Exception:
                result = _inconclusive('HOOK_CHECK_INCONCLUSIVE')

    delta = result['delta']
    summary = {key: result[key] for key in ('status', 'coverage', 'scan_id', 'execution',
                                           'baseline_available', 'duration_ms')}
    summary.update(transport='codex-mcp-hook-poc', scanner_run=result['execution']['scanner_run'],
                   new_families=delta['new'], persisting_families=delta['persisting'],
                   resolved_families=delta['resolved'],
                   additional_occurrences=delta['additional_occurrences'],
                   removed_occurrences=delta['removed_occurrences'],
                   reused=result['status'] in {'NO_CHANGE', 'REUSED_LAST_RESULT'},
                   debounced=result['status'] == 'DEBOUNCED')
    if 'reason' in result:
        summary['reason'] = result['reason']
    if 'last_check_status' in result:
        summary['last_check_status'] = result['last_check_status']
    output = CodexHookAdapter().output({'hook_event_name': 'PostToolUse'}, result)
    if decision is not None:
        summary['remediation'] = decision
        if decision.get('feedback_required') is True and decision['action'] == 'AUTO_FIX':
            output.update(decision='block', reason=decision['guidance'])
            output['systemMessage'] = 'Security Runtime: automatic TLS remediation required.'
        elif decision.get('feedback_required') is True and decision['action'] == 'CONFIRM_REQUIRED':
            output.update(decision='block', reason=decision['guidance'])
            output['systemMessage'] = 'Security Runtime: explain the risk, ask for explicit repair approval, then wait.'
        elif decision['action'] == 'NONE':
            output['systemMessage'] = ('Security Runtime verified the local repair.'
                                       if decision['reason_code'] == 'SCANNER_VERIFIED_RESOLVED' else '')
    # Bounded metadata only; no families, findings, file contents or scanner errors.
    output['hookSpecificOutput']['additionalContext'] = json.dumps(summary, ensure_ascii=True)
    return {**summary, **output}


def codex_hook_output(result: dict) -> dict:
    """The documented Hook output shape for the MCP text content channel."""
    return {key: result[key] for key in ('systemMessage', 'hookSpecificOutput', 'decision', 'reason') if key in result}
