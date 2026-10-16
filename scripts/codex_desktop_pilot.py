"""Bound-project desktop pilot; the ordinary global installation stays unchanged.

Launch with the existing Python interpreter and -I. This entrypoint explicitly
selects its own repository, never the user's editable formal package or demo code.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(RUNTIME_ROOT/'src'), str(RUNTIME_ROOT/'scripts')]

from install_codex_desktop_pilot import _locations
from security_runtime.hook_state import atomic_bytes, no_links

VERSION = 'codex-desktop-batch-pilot-v1'


def build_server(workspace, state_dir, *, codex=None, max_reviews=2):
    root, state, runtime_root, _home, _receipt = _locations(workspace, state_dir, RUNTIME_ROOT)
    if not 1 <= max_reviews <= 8:
        raise ValueError('Pilot review limit must be between 1 and 8')
    state.mkdir(parents=True, exist_ok=True)
    os.environ.update(SECURITY_RUNTIME_GLOBAL='0', SECURITY_RUNTIME_WORKSPACE=str(root),
        SECURITY_RUNTIME_INTEGRATION='codex', SECURITY_RUNTIME_STATE_DIR=str(state),
        SECURITY_RUNTIME_BATCH_REVIEW='1', SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_TRIVY_CACHE_DIR=str(state/'engine-cache/trivy'))
    import security_runtime
    if not Path(security_runtime.__file__).resolve().is_relative_to(runtime_root/'src'):
        raise RuntimeError('Experimental package provenance mismatch')
    from security_runtime.integration_state import WorkspaceBinding
    from security_runtime.mcp_server import create_server
    from security_runtime.workspace_services import workspace_services
    engine, hooks, is_git = workspace_services(root, state)
    binding = WorkspaceBinding(
        hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest()[:24],
        str(root), str(root) if is_git else '', 'codex', 'PROJECT',
        datetime.now(timezone.utc).isoformat())
    connection_path = state/'pilot-connection.json'
    no_links(connection_path)

    def observation(readiness=False):
        now = datetime.now(timezone.utc).isoformat()
        record = dict(version=VERSION, workspace=str(root), source_root=str(runtime_root),
            entrypoint=str(Path(__file__).resolve()), startup_observed=True,
            readiness_callback_observed=readiness, recorded_at=now,
            provenance='RUNTIME_REPORTED; NOT_NATIVE_EVENT_OR_SECURITY_PROOF')
        if connection_path.exists():
            if connection_path.stat().st_size>16384:
                raise ValueError('Pilot observation record exceeds its limit')
            old = json.loads(connection_path.read_bytes())
            if old.get('workspace') != str(root):
                raise ValueError('Pilot state belongs to another workspace')
            if old.get('readiness_callback_observed') is True:
                record['readiness_callback_observed'] = True
            if old.get('last_readiness_at'):
                record['last_readiness_at'] = old['last_readiness_at']
        if readiness:
            record['last_readiness_at'] = now
        atomic_bytes(connection_path, (json.dumps(record,ensure_ascii=False,indent=2)+'\n').encode())
        return record

    def readiness_adapter(bound_root, session_id, tools):
        if Path(bound_root).resolve() != root:
            raise ValueError('Pilot readiness workspace mismatch')
        # The native session callback records a comparison snapshot only. It
        # neither scans nor substitutes for begin_security_task before editing.
        from security_runtime.hook_runtime import HookEvent
        baseline = hooks.handle(HookEvent.SESSION_START, root, 'codex', session_id, _lifecycle=True)
        observation(readiness=True)
        return dict(**{'continue':True}, status='EXPERIMENTAL_CONNECTION_OBSERVED',
            coverage='UNKNOWN', scanner_run=False, model_run=False,
            experimental_desktop_pilot=True, workspace=str(root),
            comparison_baseline_status=baseline.get('status'),
            tool_count=len(tools), security_proof=False,
            systemMessage='当前测试项目已连接安全实验版；后台审查在开发检查点启动，最终仍核对当前代码。')

    def factory(tasks, batches, bound_root):
        from experimental_batch_host import ExperimentalBatchHost
        return ExperimentalBatchHost(tasks, batches, bound_root, state/'background',
            codex=codex, max_reviews_per_task=max_reviews)

    server = create_server(engine, hook_coordinator=hooks, workspace_binding=binding,
        global_mode=False, include_batch_review=True,
        batch_review_host_factory=factory, project_readiness_adapter=readiness_adapter)
    server._pilot_observe_startup = observation
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True, type=Path)
    parser.add_argument('--state-dir', required=True, type=Path)
    parser.add_argument('--codex', type=Path)
    parser.add_argument('--max-reviews', type=int, default=2)
    parser.add_argument('--check', action='store_true', help='Local capability diagnostic; no model/scan/native event claim')
    args = parser.parse_args()
    server = build_server(args.workspace,args.state_dir,codex=args.codex,max_reviews=args.max_reviews)
    if args.check:
        info = server._tool_manager.get_tool('get_runtime_info').fn()
        print(json.dumps(dict(version=VERSION, source_root=str(RUNTIME_ROOT),
            workspace=str(args.workspace), experimental_desktop_pilot=info['experimental_desktop_pilot'],
            model_run=False,scanner_run=False,native_event_observed=False),ensure_ascii=False))
        return 0
    from security_runtime.logging_utils import configure_logging
    configure_logging(mcp=True)
    server._pilot_observe_startup()
    try:
        server.run(transport='stdio')
    finally:
        server._experimental_batch_host_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
