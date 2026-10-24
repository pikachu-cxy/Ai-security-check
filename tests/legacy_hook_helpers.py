"""Explicit historical hook-v1 fixtures; new SessionStart uses product epochs."""
from dataclasses import asdict

from security_runtime.hook_runtime import HookSnapshot, capture_snapshot
from security_runtime.hook_state import identity


def legacy_comparison(hooks, root, host, session, *, capture=capture_snapshot):
    captured = capture(root, hooks.key(root))
    summary = dict(status='COMPARISON_BASELINE', last_check_status='NOT_EXECUTED',
        coverage='UNKNOWN', execution_state='NOT_EXECUTED', capabilities={}, scanner_runs=[],
        delta=dict(new=0, persisting=0, resolved=0, additional_occurrences=0,
                   removed_occurrences=0, families=[]))
    value = asdict(HookSnapshot('hook-v1', hooks.workspace_directory(root).name, host,
        identity(session or 'default'), captured[0], captured[1], {}, None, 0,
        summary, captured.file_digests))
    with hooks.lock(root) as acquired:
        assert acquired
        hooks.save(hooks.path(root, host, session), value)
    return value
