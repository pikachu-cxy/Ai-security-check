"""Strict versioned review API routing, without scanner/model execution."""
import asyncio
import json

import pytest

from security_runtime.global_mcp import create_global_server
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.mcp_server import create_server
from security_runtime.tasks.ownership import issue_session_ref, session_owner
from security_runtime.tasks.security import TaskSecurityService
from test_global_integration import installed, projects
from test_task_context_global_transport import call, task_pool
from test_task_security import service


def local_call(server, name, **arguments):
    result = asyncio.run(server._tool_manager.call_tool(name, arguments, convert_result=True))
    return result.structuredContent if hasattr(result, 'structuredContent') else json.loads(result[0].text)


@pytest.fixture
def protocol_routes(monkeypatch):
    """Exercise the public transport/owner fence independently of packet internals."""
    calls = []

    def checked(self, root, ref, operation, **arguments):
        self.load(root, ref)
        row = dict(operation=operation, task_ref=ref, owner=self._owner(), **arguments)
        calls.append(row)
        return row

    monkeypatch.setattr(TaskSecurityService, 'prepare',
        lambda self, root, ref, protocol_version=3, resume_capacity=False: checked(self, root, ref, 'prepare',
            protocol_version=protocol_version, resume_capacity=resume_capacity))
    monkeypatch.setattr(TaskSecurityService, 'review_plan',
        lambda self, root, ref, session, cursor=0, limit=10: checked(self, root, ref, 'plan',
            review_session=session, cursor=cursor, limit=limit), raising=False)
    monkeypatch.setattr(TaskSecurityService, 'review_method',
        lambda self, root, ref, session: checked(self, root, ref, 'method', review_session=session),
        raising=False)
    monkeypatch.setattr(TaskSecurityService, 'submit_batch',
        lambda self, root, ref, session, unit_ids, coverage, limitations: checked(self, root, ref, 'batch',
            review_session=session, unit_ids=unit_ids, coverage=coverage, limitations=limitations),
        raising=False)
    return calls


def test_local_review_protocol_defaults_to_v3_and_forwards_v3_arguments(service, protocol_routes):
    tasks, root, runtime = service
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, tasks.hooks), global_mode=False)
    ref = local_call(server, 'begin_security_task', workspace_path=str(root), task_key='protocol')['task_ref']
    base = dict(workspace_path=str(root), task_ref=ref)
    assert local_call(server, 'prepare_task_security_review', **base)['protocol_version'] == 3
    assert local_call(server, 'prepare_task_security_review', **base, protocol_version=3)['protocol_version'] == 3
    assert local_call(server, 'prepare_task_security_review', **base)['resume_capacity'] is False
    assert local_call(server, 'prepare_task_security_review', **base, resume_capacity=True)['resume_capacity'] is True
    session = dict(base, review_session='tr1-protocol-test')
    plan = local_call(server, 'get_task_review_plan', **session)
    assert (plan['cursor'], plan['limit']) == (0, 10)
    page = local_call(server, 'get_task_review_plan', **session, cursor=10, limit=4)
    assert (page['cursor'], page['limit']) == (10, 4)
    assert local_call(server, 'get_task_review_method', **session)['operation'] == 'method'
    batch = local_call(server, 'submit_task_review_batch', **session, unit_ids=['unit-a', 'unit-b'],
        coverage='PARTIAL', limitations=['Caller context remains unread'])
    assert batch['unit_ids'] == ['unit-a', 'unit-b'] and batch['coverage'] == 'PARTIAL'
    assert len(protocol_routes) == 8 and not runtime.calls


@pytest.mark.parametrize('protocol', [1, 2, None, True, '3', 3.0])
def test_local_old_or_invalid_protocol_is_rejected_before_business_routing(service, protocol_routes, protocol):
    tasks, root, runtime = service
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, tasks.hooks), global_mode=False)
    ref = local_call(server, 'begin_security_task', workspace_path=str(root), task_key='old-protocol')['task_ref']
    before = tasks.load(root, ref)
    result = local_call(server, 'prepare_task_security_review', workspace_path=str(root), task_ref=ref,
                        protocol_version=protocol)
    assert result['reason_code'] == result['status'] == 'UNSUPPORTED_TASK_REVIEW_PROTOCOL'
    assert result['protocol_version'] == 3 and result['read_only_supported'] is True
    assert result['scanner_run'] is False and result['repair_authorized'] is False
    assert protocol_routes == [] and not runtime.calls
    assert tasks.load(root, ref) == before


@pytest.mark.parametrize('name,extra', [
    ('prepare_task_security_review', {'protocol_version': 3, 'source': 'forbidden'}),
    ('get_task_review_plan', {'review_session': 'tr1-test', 'cursor': True}),
    ('get_task_review_method', {'review_session': 'tr1-test', 'source': 'forbidden'}),
    ('submit_task_review_batch', {'review_session': 'tr1-test', 'unit_ids': [4],
        'coverage': 'REVIEWED', 'limitations': []}),
])
def test_local_review_protocol_rejects_coercion_and_extra_fields(service, protocol_routes, name, extra):
    tasks, root, runtime = service
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, tasks.hooks), global_mode=False)
    ref = local_call(server, 'begin_security_task', workspace_path=str(root), task_key='strict')['task_ref']
    with pytest.raises(Exception):
        local_call(server, name, task_ref=ref, workspace_path=str(root), **extra)
    assert protocol_routes == [] and not runtime.calls


def test_new_review_routes_resume_only_with_same_signed_owner(service, protocol_routes):
    tasks, root, runtime = service
    core = HookCoordinator(runtime, tasks.hooks)
    owner = session_owner('codex', 'protocol-owner')
    token = issue_session_ref(tasks.hooks, root, 'codex', 'protocol-owner')
    other = issue_session_ref(tasks.hooks, root, 'codex', 'other-chat')
    first = create_server(runtime, hook_coordinator=core, global_mode=False)
    ref = local_call(first, 'begin_security_task', workspace_path=str(root), task_key='reconnect',
        session_ref=token)['task_ref']
    baseline = tasks.store(root).get(ref)['baseline']
    second = create_server(runtime, hook_coordinator=core, global_mode=False)
    base = dict(workspace_path=str(root), task_ref=ref, review_session='tr1-protocol-test')
    for name, extra in [('get_task_review_plan', {}), ('get_task_review_method', {}),
            ('submit_task_review_batch', dict(unit_ids=['unit-a'], coverage='REVIEWED', limitations=[]))]:
        with pytest.raises(Exception, match='another session'):
            local_call(second, name, **base, session_ref=other, **extra)
        assert local_call(second, name, **base, session_ref=token, **extra)['owner'] == owner
    assert tasks.store(root).get(ref)['baseline'] == baseline
    assert len(tasks.store(root).records()) == 1 and not runtime.calls


def test_global_review_protocol_errors_do_not_report_workspace_failure(installed, projects, tmp_path, protocol_routes):
    pool, ledgers = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        ref = call(server, 'begin_security_task', root, task_key='protocol')['task_ref']
        assert call(server, 'prepare_task_security_review', root, task_ref=ref)['protocol_version'] == 3
        for protocol in (1, 2):
            rejected = call(server, 'prepare_task_security_review', root, task_ref=ref,
                            protocol_version=protocol)
            assert rejected['status'] == rejected['reason_code'] == 'UNSUPPORTED_TASK_REVIEW_PROTOCOL'
            assert rejected['scanner_run'] is False and rejected['repair_authorized'] is False
            assert 'workspace_readiness' not in rejected
        assert call(server, 'prepare_task_security_review', root, task_ref=ref,
            protocol_version=3)['protocol_version'] == 3
        base = dict(task_ref=ref, review_session='tr1-protocol-test')
        malformed = call(server, 'get_task_review_plan', root, **base, cursor='10')
        assert malformed['reason_code'] == 'TASK_REQUEST_INVALID'
        token = issue_session_ref(pool.children[root][1].store, root, 'codex', 'foreign-chat')
        foreign = call(server, 'get_task_review_method', root, **base, session_ref=token)
        assert foreign['reason_code'] == 'TASK_CONNECTION_SCOPE_MISMATCH'
        for result in (malformed, foreign):
            assert result['status'] == 'INCONCLUSIVE' and not result['scanner_run']
            assert 'workspace_readiness' not in result
        assert call(server, 'get_task_review_plan', root, **base, cursor=10, limit=4)['cursor'] == 10
        assert call(server, 'get_task_review_method', root, **base)['operation'] == 'method'
        assert call(server, 'submit_task_review_batch', root, **base, unit_ids=['unit-a'],
            coverage='REVIEWED', limitations=[])['unit_ids'] == ['unit-a']
        assert not ledgers[root].calls
    finally:
        pool.close()


@pytest.mark.parametrize('kind,reason', [
    ('plan', 'REVIEW_PLAN_SESSION_MISMATCH'),
    ('plan', 'REVIEW_PLAN_STALE'),
    ('revision', 'TASK_REVIEW_REVISION_CAPACITY'),
    ('revision', 'REVIEW_PLAN_REVISION_INVALID'),
    ('plan', 'UNTRUSTED_DYNAMIC_REASON'),
])
def test_global_revision_errors_keep_fixed_diagnostics_without_exception_text(
        installed, projects, tmp_path, monkeypatch, kind, reason):
    from security_runtime import build_identity
    from security_runtime.task_review.plan import ReviewPlanError
    from security_runtime.task_review.revisions import ReviewRevisionError
    build_observations, health_observations = [], []
    original_build, original_status = build_identity.build_identity, installed.configuration_status
    def observed_build():
        value = original_build()
        build_observations.append({key:value.get(key) for key in ('status', 'build_id')})
        return value
    def observed_status():
        start = len(build_observations)
        value = original_status()
        receipt = installed._manifest(installed.home)
        health_observations.append(dict(overall=value['overall'], diagnostics=value['diagnostics'],
            enrolled_build=(receipt or {}).get('build_id'),
            observed_builds=build_observations[start:]))
        return value
    monkeypatch.setattr(build_identity, 'build_identity', observed_build)
    monkeypatch.setattr(installed, 'configuration_status', observed_status)
    pool, _ = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    error = ReviewPlanError if kind == 'plan' else ReviewRevisionError

    def reject(*args, **kwargs):
        raise error(reason, 'private source or environment must never be reflected')

    monkeypatch.setattr(TaskSecurityService, 'prepare', reject)
    try:
        result = call(server, 'prepare_task_security_review', projects[0],
            task_ref='ts1-'+'a'*32, protocol_version=3)
        expected = 'TASK_REQUEST_REJECTED' if reason == 'UNTRUSTED_DYNAMIC_REASON' else reason
        assert result['reason_code'] == expected, health_observations
        assert result['status'] == 'INCONCLUSIVE'
        assert 'private source' not in json.dumps(result)
        assert 'workspace_readiness' not in result
        assert result['scanner_run'] is False
    finally:
        pool.close()


def test_global_runtime_compatibility_failure_keeps_same_task_recovery(installed, projects, tmp_path, monkeypatch):
    from security_runtime.tasks.diagnostics import TaskRuntimeRestartRequired
    pool, ledgers = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)

    def reject(*args, **kwargs):
        raise TaskRuntimeRestartRequired() from TypeError('private source must never be returned')

    monkeypatch.setattr(TaskSecurityService, 'prepare', reject)
    try:
        result = call(server, 'prepare_task_security_review', projects[0], task_ref='ts1-'+'a'*32)
        assert result['reason_code'] == 'RUNTIME_RESTART_REQUIRED'
        assert result['status'] == 'INCONCLUSIVE' and result['original_task_preserved']
        assert result['recovery']['resume_tool'] == 'prepare_task_security_review'
        assert result['recovery']['same_task_required']
        assert 'private source' not in json.dumps(result)
        assert not result['scanner_run'] and not ledgers[projects[0]].calls
    finally:
        pool.close()
