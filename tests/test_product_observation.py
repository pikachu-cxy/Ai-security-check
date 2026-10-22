"""Product facts remain optional and never acquire routing or execution authority."""
import copy
import sys
from types import SimpleNamespace

import pytest

from security_runtime.codex_event_adapter import CodexEventAdapter
from security_runtime.codex_host_claims import CodexClaimGuard
from security_runtime.hook_state import HookStateStore, identity
from security_runtime.host_event_runtime import handle_normalized_event
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.task_ownership import issue_session_ref, session_owner, verify_session_ref
from security_runtime.task_security import TaskSecurityService
from test_host_event_journal import event
from test_hook_runtime import repo
from test_task_security import service


@pytest.fixture
def port(monkeypatch):
    calls = []
    def bind(name):
        return lambda *args, **kwargs: calls.append((name, copy.deepcopy(args), dict(kwargs)))
    monkeypatch.setitem(sys.modules, 'security_runtime.observation', SimpleNamespace(
        bind_chat=bind('chat'), bind_host=bind('host'), bind_product=bind('product')))
    return calls


def codex_claims(root):
    return dict(event='PostToolUse', workspace_path=str(root), session_id='private-session',
                turn_id='private-turn', tool_use_id='private-host-call', tool_name='Bash',
                tool_input={'command': 'git status'})


def normalize(root, arguments):
    binding = WorkspaceBinding('fixture', str(root), str(root), 'codex', 'PROJECT', '')
    return CodexEventAdapter().bind_project(arguments, binding=binding, guard=CodexClaimGuard())


def test_host_bindings_follow_validation_and_keep_trigger_identity_distinct(repo, port):
    args = codex_claims(repo)
    normalized, diagnostics, reason = normalize(repo, args)
    assert reason is None and diagnostics['host_claim_status'] == 'VALID'
    assert normalized.context.invocation_binding == identity(args['tool_use_id'])
    assert port == [
        ('chat', (session_owner('codex', args['session_id']),), {}),
        ('host', ('codex', identity(args['session_id']), identity(args['tool_use_id']),
                  identity(args['turn_id'])), {}),
    ]
    port.clear()
    rejected, _, reason = normalize(repo, dict(args, turn_id=None))
    assert rejected is None and reason == 'INVALID_HOST_CLAIMS' and port == []
    CodexEventAdapter().normalize(args, repo, legacy=True)
    assert port == []


def test_signed_session_reference_binds_only_after_successful_verification(repo, tmp_path, port):
    hooks = HookStateStore(tmp_path / 'session-state')
    token = issue_session_ref(hooks, repo, 'codex', 'private-session')
    owner = verify_session_ref(hooks, repo, token)
    assert port == [('chat', (owner,), {})]
    port.clear()
    with pytest.raises(ValueError, match='invalid, expired'):
        verify_session_ref(hooks, repo, token + '0')
    assert port == []


def test_task_facts_do_not_adopt_historical_owners_or_run_scans(service, port):
    original, root, runtime = service
    first = TaskSecurityService(runtime, original.hooks, owner=session_owner('codex', 'first'))
    second = TaskSecurityService(runtime, original.hooks, owner=session_owner('codex', 'second'))
    ref = first.begin(root, 'work')['task_ref']
    assert ('product', ('task', ref), {'relation': 'TASK_CREATED'}) in port
    assert ('product', ('task', ref), {'relation': 'TASK_RESULT_RETURNED'}) in port
    port.clear()
    with pytest.raises(ValueError, match='another session'):
        second.load(root, ref)
    assert port == []
    historical = second.load(root, ref, read_only=True)
    assert historical['task_owner'] == first._owner()
    assert port == [('product', ('task', ref), {'relation': 'TASK_RECORD_READ'})]
    result = first.finish(root, ref)
    assert result['status'] == 'NO_CHANGES' and result['development_summary'] == ''
    assert runtime.calls == [] and all(name != 'chat' for name, _, _ in port)


def test_host_event_claim_and_replay_keep_one_product_dispatch(repo, tmp_path, port):
    hooks = HookStateStore(tmp_path / 'host-state')
    calls = []
    def handle(*args, **kwargs):
        calls.append((args, kwargs))
        return dict(status='SCANNED', scan_id='fixture-scan', execution={'scanner_run': True},
                    workspace_mutation_observed=True, changed_file_count=1)
    coordinator = SimpleNamespace(store=hooks, handle=handle)
    normalized = event(repo)
    first, _ = handle_normalized_event(normalized, coordinator=coordinator)
    reference = first['event_processing']['event_ref']
    second, _ = handle_normalized_event(normalized, coordinator=coordinator)
    assert len(calls) == 1 and second['event_processing']['state'] == 'ALREADY_COMPLETED'
    assert ('product', ('host_event', reference), {'relation': 'HOST_EVENT_CLAIMED'}) in port
    assert ('product', ('host_event', reference), {'relation': 'HOST_EVENT_REUSED'}) in port


@pytest.mark.parametrize('failure', ['missing', 'raising'])
def test_optional_port_failure_preserves_sessions_tasks_and_hook_decisions(service, monkeypatch, failure):
    original, root, runtime = service
    def unavailable(*args, **kwargs):
        raise RuntimeError('observer unavailable')
    monkeypatch.setitem(sys.modules, 'security_runtime.observation', None if failure == 'missing' else
        SimpleNamespace(bind_chat=unavailable, bind_host=unavailable, bind_product=unavailable))
    token = issue_session_ref(original.hooks, root, 'codex', 'private-session')
    owner = verify_session_ref(original.hooks, root, token)
    normalized, _, reason = normalize(root, codex_claims(root))
    assert reason is None and normalized.operation.value == 'READ_ONLY'
    tasks = TaskSecurityService(runtime, original.hooks, owner=owner)
    ref = tasks.begin(root, 'work')['task_ref']
    assert tasks.load(root, ref)['task_owner'] == owner
    result = tasks.finish(root, ref)
    assert result['status'] == 'NO_CHANGES' and not result['review_required'] and runtime.calls == []
    with pytest.raises(ValueError, match='invalid, expired'):
        verify_session_ref(original.hooks, root, token + '0')


def test_scan_fact_is_emitted_only_after_persistence(repo, tmp_path, port, monkeypatch):
    store = SQLiteStore(tmp_path / 'scan-state' / 'scans.db')
    runtime = SecurityRuntime(ScannerRegistry([]), store)
    result = runtime.scan(repo, 'quick')
    assert result.status == 'NO_CHANGES' and store.get_scan(result.scan_id) is not None
    assert ('product', ('scan', result.scan_id), {'relation': 'SCAN_PERSISTED'}) in port
    port.clear()
    def fail_save(result):
        raise OSError('fixture persistence failure')
    monkeypatch.setattr(store, 'save', fail_save)
    with pytest.raises(OSError, match='fixture persistence failure'):
        runtime.scan(repo, 'quick')
    assert port == []


def test_optional_scan_observation_failure_preserves_saved_result(repo, tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError('observer unavailable')
    monkeypatch.setitem(sys.modules, 'security_runtime.observation', SimpleNamespace(bind_product=unavailable))
    store = SQLiteStore(tmp_path / 'scan-state' / 'scans.db')
    result = SecurityRuntime(ScannerRegistry([]), store).scan(repo, 'quick')
    assert result.status == 'NO_CHANGES' and store.get_scan(result.scan_id) is not None
