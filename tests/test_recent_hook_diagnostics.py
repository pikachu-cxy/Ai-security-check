"""Persistent safe observations, real SDK ingress, independent read-only CLI."""
import asyncio
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from security_runtime.cli import main
from security_runtime.recent_hooks import Observation, RecentHookStore, RETENTION, TOTAL_RETENTION
from test_codex_host_claims import connected, claims, invoke
from test_global_integration import installed, projects


@pytest.fixture(autouse=True)
def diagnostic_state(monkeypatch, tmp_path):
    state = tmp_path/'diagnostic-state'
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(state))
    return state


def stages(row):
    return [p['stage'] for p in row['stages']]


def recent(root):
    return RecentHookStore().recent(root)['records']


def test_valid_readonly_claims_persist_one_global_not_child_record(connected, projects):
    server, _, runtimes = connected
    root = projects[0]
    before = len(runtimes[root].calls)
    out = invoke(server, claims(root))
    rows = recent(root)
    assert len(rows) == 1
    row = rows[0]
    assert stages(row) == ['HOOK_RECEIVED', 'CLAIMS_VALID', 'READ_ONLY_SKIPPED']
    assert row['host_claim_status'] == 'VALID' and row['completed']
    assert row['tool_classification'] == 'READ_ONLY' and row['scanner_run'] is False
    assert out['recent_hook_diagnostic_id'] == row['diagnostic_id']
    assert len(runtimes[root].calls) == before


@pytest.mark.parametrize('field,value', [('turn_id', None), ('tool_use_id', ''), ('tool_input', 'malformed-private')])
def test_rejected_claims_before_child_admission_remain_queryable(connected, projects, field, value):
    server, _, runtimes = connected
    args = claims(projects[0])
    if value is None:
        del args[field]
    else:
        args[field] = value
    before = len(runtimes[projects[0]].calls)
    out = invoke(server, args)
    row = recent(projects[0])[0]
    assert row['last_stage'] == 'CLAIMS_REJECTED'
    assert field in row['missing_claims'] + row['invalid_claims']
    assert row['handler_reason'] == 'INVALID_HOST_CLAIMS'
    assert out['host_claim_status'] == 'INVALID'
    assert len(runtimes[projects[0]].calls) == before


def test_real_reconciliation_and_scanner_boundaries_observed(connected, projects):
    server, _, _ = connected
    root = projects[0]
    (root/'src/A.java').write_text('class A { int changed; }\n')
    args = claims(root)
    args.update(tool_name='apply_patch', tool_input={'command': 'synthetic patch'})
    out = invoke(server, args)
    row = recent(root)[0]
    assert out['scanner_run'] and row['scanner_run']
    assert row['workspace_mutation_observed'] is True and row['changed_file_count'] > 0
    assert 'SCANNER_TRIGGERED' in stages(row) and row['last_stage'] == 'SCANNER_COMPLETED'
    assert row['scanner_trigger_reason'] == 'POST_TOOL_USE_MUTATION'


def test_same_snapshot_no_mutation_is_distinct_from_readonly(connected, projects):
    server, _, _ = connected
    args = claims(projects[0]); args.update(tool_name='apply_patch')
    out = invoke(server, args)
    row = recent(projects[0])[0]
    assert not out['scanner_run'] and row['scanner_run'] is False
    assert row['workspace_mutation_observed'] is False
    assert row['last_stage'] == 'MUTATION_NOT_OBSERVED'


def test_suppressed_handler_exception_still_has_entry_and_error(connected, projects, monkeypatch):
    server, pool, _ = connected
    def failure(*args, **kwargs):
        raise RuntimeError('private-exception-source-token')
    monkeypatch.setattr(pool.children[projects[0]][1], 'handle', failure)
    args = claims(projects[0]); args.update(tool_name='apply_patch')
    out = invoke(server, args)
    row = recent(projects[0])[0]
    assert stages(row)[0] == 'HOOK_RECEIVED' and row['last_stage'] == 'HANDLER_ERROR'
    assert row['handler_reason'] == 'HOOK_CHECK_INCONCLUSIVE'
    assert out['reason'] == 'HOOK_CHECK_INCONCLUSIVE'
    assert 'private-exception' not in json.dumps(row)


def test_identifiers_commands_input_and_source_not_persisted(connected, projects):
    server, _, _ = connected
    args = claims(projects[0]); args.update(session_id='private-session-id', turn_id='private-turn-id',
        tool_use_id='private-tool-use-id', tool_input={'command':'git status # private-shell-command',
                                                     'source':'private-source-secret-token'})
    invoke(server, args)
    contents = json.dumps(recent(projects[0]))
    raw = RecentHookStore().path.read_bytes()
    for marker in ('private-session-id', 'private-turn-id', 'private-tool-use-id', 'private-shell-command',
                   'private-source-secret-token', '"tool_input"', 'transcript', 'tool_response'):
        assert marker not in contents and marker.encode() not in raw


def test_default_workspace_query_does_not_leak_other_workspace(connected, projects):
    server, _, _ = connected
    invoke(server, claims(projects[0]))
    args = claims(projects[1], 'second-call'); args['session_id'] = 'second-session'
    invoke(server, args)
    a, b = recent(projects[0]), recent(projects[1])
    assert len(a) == len(b) == 1
    assert a[0]['diagnostic_id'] != b[0]['diagnostic_id']
    assert a[0]['workspace_hash'] != b[0]['workspace_hash']


def test_missing_workspace_is_explicitly_unbound(connected):
    server, _, _ = connected
    args = claims('/not-used'); del args['workspace_path']
    invoke(server, args)
    row = RecentHookStore().recent(unbound=True)['records'][0]
    assert row['workspace_hash'] is None and row['last_stage'] == 'CLAIMS_REJECTED'
    assert 'workspace_path' in row['missing_claims']


def test_bounded_retention_and_late_finish_cannot_resurrect_evicted_event(tmp_path):
    root = tmp_path/'workspace'
    observations = []
    for number in range(RETENTION + 3):
        item = Observation('handle_hook_event', claims(root, str(number)))
        item.bind(root)
        observations.append(item)
    records = RecentHookStore().recent(root, limit=32)['records']
    assert len(records) == RETENTION
    first = observations[0]
    first.finish(dict(status='NOT_SCANNED', scanner_run=False))
    assert first.expired
    assert first.record['diagnostic_id'] not in {r['diagnostic_id'] for r in RecentHookStore().recent(root, limit=32)['records']}


def test_read_only_cli_does_not_create_diagnostic_or_security_state(projects, diagnostic_state, capsys, monkeypatch):
    monkeypatch.chdir(projects[0])
    assert main(['hooks', 'recent', '--json']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['status'] == 'NO_RECORDS' and out['records'] == []
    assert not diagnostic_state.exists()


def test_read_only_cli_existing_state_bytes_unchanged(connected, projects, capsys):
    invoke(connected[0], claims(projects[0]))
    path = RecentHookStore().path
    before = path.read_bytes()
    assert main(['hooks', 'recent', '--path', str(projects[0]), '--limit', '1', '--json']) == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out['records']) == 1 and path.read_bytes() == before


def test_storage_failure_is_advisory_and_does_not_bypass_claims_or_core(connected, projects, monkeypatch):
    def failure(*args, **kwargs):
        raise sqlite3.OperationalError('private-storage-message')
    monkeypatch.setattr(RecentHookStore, 'write', failure)
    out = invoke(connected[0], claims(projects[0]))
    assert out['host_claim_status'] == 'VALID' and not out['scanner_run']
    assert out['recent_hook_diagnostic_status'] == 'WRITE_UNAVAILABLE'
    args = claims(projects[0], 'other'); del args['turn_id']
    assert invoke(connected[0], args)['host_claim_status'] == 'INVALID'
    (projects[0]/'src/A.java').write_text('class A { int changed; }\n')
    args = claims(projects[0], 'mutation-with-storage-error'); args['tool_name'] = 'apply_patch'
    assert invoke(connected[0], args)['scanner_run']


@pytest.mark.parametrize('kind', [RuntimeError, ValueError])
def test_unexpected_global_transport_error_is_not_hidden_by_generic_rejection(connected, projects, monkeypatch, kind):
    server, pool, _ = connected
    child = pool.children[projects[0]][0]
    def failure(*args, **kwargs):
        raise kind('private-transport-error')
    monkeypatch.setattr(child._tool_manager, 'get_tool', failure)
    out = invoke(server, claims(projects[0]))
    row = recent(projects[0])[0]
    assert out['reason_code'] == 'WORKSPACE_OR_REFERENCE_REJECTED'  # existing protocol unchanged
    assert row['last_stage'] == 'HANDLER_ERROR'
    assert stages(row)[0] == 'HOOK_RECEIVED'
    assert 'private-transport-error' not in json.dumps(row)


def test_rejected_subdirectory_claim_is_queryable_from_canonical_workspace(connected, projects):
    args = claims(projects[0]); args['workspace_path'] = str(projects[0]/'src'); del args['turn_id']
    invoke(connected[0], args)
    assert recent(projects[0])[0]['last_stage'] == 'CLAIMS_REJECTED'


def test_initializing_early_return_keeps_actual_classification(connected, projects, monkeypatch):
    server, pool, _ = connected
    monkeypatch.setattr(pool, 'bootstrap', lambda *args: {'status':'INITIALIZING', 'security_proof':False})
    args = claims(projects[0]); args['tool_input'] = {'command':'Set-Content src/A.java fixture'}
    out = invoke(server, args)
    row = recent(projects[0])[0]
    assert out['reason_code'] == 'WORKSPACE_INITIALIZING' and not out['scanner_run']
    assert row['host_claim_status'] == 'VALID' and row['tool_classification'] == 'POSSIBLE_WORKSPACE_MUTATION'
    assert row['workspace_mutation_observed'] is None and row['scanner_run'] is False
    assert 'SCANNER_TRIGGERED' not in stages(row)


def test_project_lifecycle_events_use_own_schema_and_record_valid_boundary(projects):
    from security_runtime.mcp_server import create_server
    from test_codex_mcp_hook import binding
    server = create_server(workspace_binding=binding(projects[0]), global_mode=False)
    for name, event in [('handle_readiness_event', 'SessionStart'), ('handle_stop_event', 'Stop')]:
        args = dict(event=event, workspace_path=str(projects[0]), session_id='lifecycle-fixture')
        if event == 'Stop':
            args['stop_hook_active'] = False
        asyncio.run(server.call_tool(name, args))
        row = recent(projects[0])[0]
        assert row['event_schema'] == 'codex-'+event+'-v1'
        assert 'CLAIMS_VALID' in stages(row) and row['host_claim_status'] == 'VALID'
        assert not row['tool_use_claim_present'] and not row['turn_claim_present']


def test_entry_is_readable_before_handler_completes(projects):
    from security_runtime.recent_hooks import instrument
    from security_runtime.codex_host_claims import EVENTS
    args = claims(projects[0])
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        async def call(name, arguments):
            entered.set()
            await release.wait()
            return dict(status='NOT_SCANNED', scanner_run=False)
        recorded = instrument(call, schemas={'handle_hook_event': {'type':'object'}},
                              resolve_root=lambda values: projects[0])
        task = asyncio.create_task(recorded('handle_hook_event', args))
        await entered.wait()
        row = recent(projects[0])[0]
        assert stages(row) == ['HOOK_RECEIVED'] and row['completed'] is False
        assert row['event_schema'] == 'codex-PostToolUse-v1'
        release.set()
        await task
    asyncio.run(scenario())


def test_total_retention_is_bounded_across_unbound_and_multiple_workspaces(tmp_path, monkeypatch):
    import security_runtime.recent_hooks as module
    monkeypatch.setattr(module, 'TOTAL_RETENTION', 4)
    for number in range(6):
        item = Observation('handle_hook_event', claims(tmp_path, str(number)))
        item.bind(tmp_path/str(number))
    with sqlite3.connect(RecentHookStore().path) as db:
        assert db.execute('SELECT count(*) FROM recent_hook_diagnostics').fetchone()[0] == 4


def test_observer_exception_never_repeats_or_blocks_original_handler(projects, monkeypatch):
    import security_runtime.recent_hooks as module
    calls = []
    def failure(*args, **kwargs):
        raise RuntimeError('diagnostic failure')
    from security_runtime.codex_event_adapter import CodexEventAdapter
    monkeypatch.setattr(CodexEventAdapter, 'validate_claims', failure)
    async def original(name, arguments):
        calls.append(name)
        return dict(status='NOT_SCANNED', scanner_run=False)
    recorded = module.instrument(original, schemas={'handle_hook_event': {}}, resolve_root=lambda values: projects[0])
    out = asyncio.run(recorded('handle_hook_event', claims(projects[0])))
    assert calls == ['handle_hook_event'] and out['status'] == 'NOT_SCANNED'
    assert out['recent_hook_diagnostic_status'] == 'WRITE_UNAVAILABLE'


def test_scanner_exception_does_not_claim_completion_or_hide_observed_invocation(connected, projects, monkeypatch):
    from security_runtime.verification_policy import scanner_process_observed
    server, pool, _ = connected
    core = pool.children[projects[0]][1]
    def failure(*args, **kwargs):
        scanner_process_observed()
        raise RuntimeError('private-scanner-error')
    monkeypatch.setattr(core.runtime, 'scan', failure)
    (projects[0]/'src/A.java').write_text('class A { int changed; }\n')
    args = claims(projects[0]); args['tool_name'] = 'apply_patch'
    out = invoke(server, args)
    row = recent(projects[0])[0]
    assert out['reason'] == 'HOOK_CHECK_INCONCLUSIVE'  # security protocol unchanged
    assert 'SCANNER_TRIGGERED' in stages(row) and 'SCANNER_COMPLETED' not in stages(row)
    assert row['scanner_run'] is True and row['last_stage'] == 'HANDLER_ERROR'


def test_database_corrupt_values_are_not_echoed(connected, projects, capsys):
    invoke(connected[0], claims(projects[0]))
    path = RecentHookStore().path
    with sqlite3.connect(path) as db:
        db.execute('UPDATE recent_hook_diagnostics SET data=?', (json.dumps({'source':'private-corrupt-source'}),))
    assert main(['hooks', 'recent', '--path', str(projects[0]), '--json']) == 2
    assert 'private-corrupt-source' not in capsys.readouterr().out


def test_cross_process_real_stdio_mcp_write_cli_read_and_restart(projects, diagnostic_state):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    code = """
import sys
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.mcp_server import create_server
root=sys.argv[1]
binding=WorkspaceBinding('fixture',root,root,'codex','PROJECT','')
create_server(workspace_binding=binding,global_mode=False).run(transport='stdio')
"""
    async def request(args):
        params = StdioServerParameters(command=sys.executable, args=['-c', code, str(projects[0])], env=dict(os.environ))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await session.call_tool('handle_hook_event', args)
    first = asyncio.run(request(claims(projects[0])))
    assert not first.isError
    # A separate native CLI process reads the SQLite row after the MCP process exited.
    command = [sys.executable, '-m', 'security_runtime.cli', 'hooks', 'recent', '--path', str(projects[0]), '--json']
    proc = subprocess.run(command, env=dict(os.environ), capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    rows = json.loads(proc.stdout)['records']
    assert len(rows) == 1 and rows[0]['last_stage'] == 'READ_ONLY_SKIPPED'
    first_scope = rows[0]['monotonic_scope']
    # Restart does not fabricate continuity; old records remain, new clock scope differs.
    second = asyncio.run(request(claims(projects[0], 'call-after-restart')))
    assert not second.isError
    rows = recent(projects[0])
    assert len(rows) == 2 and rows[0]['monotonic_scope'] != first_scope
    missing = claims(projects[0], 'missing-invocation'); del missing['turn_id']
    assert asyncio.run(request(missing)).isError
    assert recent(projects[0])[0]['last_stage'] == 'CLAIMS_REJECTED'
