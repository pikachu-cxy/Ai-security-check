"""Default hooks observe bounded edits without walking task/source snapshots."""
from types import SimpleNamespace

import pytest

from security_runtime.codex_event_adapter import edit_path_hints
from security_runtime.codex_mcp_hook import codex_hook_output, handle_codex_hook
from security_runtime.host_events import EventKind, OperationClass
from security_runtime.host_event_runtime import handle_normalized_event
from security_runtime.integration_state import WorkspaceBinding
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_host_event_normalization import generic_event


PATCH = '''*** Begin Patch
*** Add File: src/new.py
+print("*** Update File: not-a-header.py")
*** Update File: src/old.py
*** Move to: src/renamed.py
@@
-old
+new
*** Delete File: src/gone.py
*** End Patch'''


@pytest.mark.parametrize('inputs', [PATCH, {'patch': PATCH}, {'input': PATCH},
                                  {'command': PATCH}, {'patch': None, 'command': PATCH}])
def test_patch_add_edit_delete_rename_hints_never_retain_source(repo, inputs):
    paths, unknown = edit_path_hints('apply_patch', inputs, repo)
    assert paths == ('src/new.py', 'src/old.py', 'src/renamed.py', 'src/gone.py')
    assert not unknown


def test_connected_claims_accept_raw_patch_but_not_raw_shell(repo):
    from security_runtime.codex_host_claims import diagnostics
    claims = dict(event='PostToolUse', workspace_path=str(repo), session_id='s',
                  tool_name='apply_patch', tool_input=PATCH, turn_id='t', tool_use_id='i')
    assert diagnostics(claims, 'PostToolUse')['host_claim_status'] == 'VALID'
    assert diagnostics(dict(claims, tool_name='Bash'), 'PostToolUse')['invalid_claims'] == ['tool_input']
    assert diagnostics(dict(claims, tool_input='x' * 262145), 'PostToolUse')['invalid_claims'] == ['tool_input']


@pytest.mark.parametrize('bad', ['../escape.py', '/outside.py', 'C:/outside.py',
                               '\\\\server\\share\\file.py', 'src/../escape.py'])
def test_invalid_patch_path_preserves_valid_scope_and_marks_gap(repo, bad):
    patch = f'*** Begin Patch\n*** Update File: valid.py\n*** Delete File: {bad}\n*** End Patch'
    paths, unknown = edit_path_hints('apply_patch', patch, repo)
    assert paths == ('valid.py',) and unknown


def test_patch_bounds_and_unknown_commands_never_expand_to_workspace(repo):
    assert edit_path_hints('apply_patch', PATCH + 'x' * 262144, repo) == ((), True)
    assert edit_path_hints('Bash', {'command': 'opaque script'}, repo) == ((), True)
    assert edit_path_hints('apply_patch', '*** Update File: valid.py', repo) == (('valid.py',), True)
    assert edit_path_hints('Write', {'file_path': str(repo / 'new.py')}, repo) == (('new.py',), False)
    assert edit_path_hints('Write', {'file_path': 'new.py'}, repo, cwd=repo / 'src') == (('src/new.py',), False)


def no_old_task_reads(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Default quiet hooks must not read task snapshots, inventory, or scan')
    monkeypatch.setattr('security_runtime.tasks.security.capture', forbidden)
    monkeypatch.setattr('security_runtime.hook_runtime.capture_snapshot', forbidden)
    monkeypatch.setattr('security_runtime.tasks.security_state.TaskSecurityStore.get', forbidden)
    monkeypatch.setattr('security_runtime.tasks.security_state.TaskSecurityStore.records', forbidden)
    monkeypatch.setattr('security_runtime.tasks.attribution.session_activity', forbidden)
    monkeypatch.setattr('security_runtime.codex_mcp_hook._record_task_hook', forbidden)
    return forbidden


def test_readonly_and_stop_do_not_open_historical_task_pages(repo, tmp_path, monkeypatch):
    forbidden = no_old_task_reads(monkeypatch)
    runtime = FakeRuntime()
    monkeypatch.setattr(runtime, 'scan', forbidden)
    core = coordinator(tmp_path, runtime, task_audit_mode=True)
    readonly = generic_event(repo, EventKind.WORKSPACE_ACTIVITY, OperationClass.READ_ONLY)
    result, _ = handle_normalized_event(readonly, coordinator=core)
    assert result['status'] == 'NOT_SCANNED'
    stop = generic_event(repo, EventKind.SESSION_STOP)
    result, _ = handle_normalized_event(stop, coordinator=core)
    assert result['status'] == 'SESSION_FINALIZED' and not result['execution']['scanner_run']
    binding = WorkspaceBinding('fixture', str(repo), str(repo), 'codex', 'PROJECT', '')
    result = handle_codex_hook('PostToolUse', str(repo), 's', 'Bash', {'command': 'git status'},
                              binding=binding, coordinator=core)
    assert codex_hook_output(result) == {}


def test_default_stop_keeps_explicit_repair_continuation(repo, tmp_path, monkeypatch):
    no_old_task_reads(monkeypatch)
    core = coordinator(tmp_path, FakeRuntime(), task_audit_mode=True)
    calls = []
    def handle(*args, **kwargs):
        calls.append((args, kwargs))
        return dict(status='ALLOW_STOP', decision='block', reason='approved-repair-continuation')
    result, _ = handle_normalized_event(generic_event(repo, EventKind.SESSION_STOP),
        coordinator=core, continuation=SimpleNamespace(handle=handle))
    assert result['decision'] == 'block' and len(calls) == 1


@pytest.mark.parametrize('inputs', [PATCH, {'command': PATCH}])
def test_default_edit_records_only_hint_metadata_and_keeps_hook_quiet(repo, tmp_path, monkeypatch, inputs):
    no_old_task_reads(monkeypatch)
    calls = []
    def record(hooks, root, owner, paths=(), **kwargs):
        calls.append((root, owner, paths, kwargs))
        return dict(check_ref='dc1-'+'a'*32, status='DIRTY',
            contract='observed-development-check-v1', dirty_seq=1, scanned_seq=0,
            baseline_created=False, scanner_run=False,
            scope=dict(kind='OBSERVED_FILES', paths=list(paths), scope_unknown=kwargs['scope_unknown'],
                       full_project=False, expanded_to_project=False))
    monkeypatch.setattr('security_runtime.development_check.record_hook', record)
    core = coordinator(tmp_path, FakeRuntime(), task_audit_mode=True)
    binding = WorkspaceBinding('fixture', str(repo), str(repo), 'codex', 'PROJECT', '')
    result = handle_codex_hook('PostToolUse', str(repo), 's', 'apply_patch', inputs,
                              binding=binding, coordinator=core)
    assert result['status'] == 'DIRTY' and result['development_check_ref'].startswith('dc1-')
    assert result['scope']['paths'] == ['src/new.py', 'src/old.py', 'src/renamed.py', 'src/gone.py']
    assert len(calls) == 1 and not result['scanner_run']
    assert codex_hook_output(result) == {}


def test_cursor_default_pre_and_stop_never_create_strict_baseline(repo, tmp_path, monkeypatch):
    from security_runtime.cursor_tasks import CursorTaskBridge
    no_old_task_reads(monkeypatch)
    core = coordinator(tmp_path, FakeRuntime(), task_audit_mode=True)
    bridge = CursorTaskBridge(core, repo, 's', 'generation')
    assert bridge.before(dict(tool_name='Write', tool_input={'path': 'A.java'}))['status'] == 'EDIT_OBSERVATION_READY'
    assert bridge.before(dict(tool_name='Shell', tool_input={'command': 'git status'}))['status'] == 'READ_ONLY_OR_UNSUPPORTED'
    assert bridge.followup(dict(status='completed', loop_count=0)) is None


def test_cursor_automatic_default_records_paths_and_keeps_chat_quiet(repo, tmp_path, monkeypatch):
    from test_cursor_automatic import ingress, tool
    no_old_task_reads(monkeypatch)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'scan-state'))
    monkeypatch.setattr('security_runtime.development_check_worker.launch_worker',
                        lambda *a, **k: pytest.fail('An edit must not launch a scanner worker'))
    core = coordinator(tmp_path, FakeRuntime(), task_audit_mode=True)
    output, started = ingress(repo, tmp_path, core, 'sessionStart')
    assert 'additional_context' in output and started['status'] == 'CONNECTED'
    assert tool(repo, tmp_path, core, path='A.java')[1]['status'] == 'EDIT_OBSERVATION_READY'
    output, edited = ingress(repo, tmp_path, core, 'postToolUse', tool_name='Write',
        tool_use_id='opaque', tool_input={'path': 'A.java'})
    assert output == {} and edited['status'] == 'DIRTY'
    assert edited['scope']['paths'] == ['A.java'] and not edited['scanner_run']
    output, read = ingress(repo, tmp_path, core, 'postToolUse', tool_name='Read', tool_use_id='read')
    assert output == {} and read['scanner_skipped_reason'] == 'READ_ONLY_ACTIVITY'
    output, stopped = ingress(repo, tmp_path, core, 'stop')
    assert output == {} and stopped['status'] == 'NOT_APPLICABLE'
