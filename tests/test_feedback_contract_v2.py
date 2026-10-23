"""Public feedback contracts separate input, ownership, saved choices and review."""
import asyncio
import copy
import json

import pytest

from security_runtime.cursor_permissions import ROUTINE_TOOLS
from security_runtime.findings import FindingNormalizer
from security_runtime.global_mcp import create_global_server
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.local_evidence import snapshot_fingerprint
from security_runtime.mcp_server import create_server
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from security_runtime.tasks.ownership import issue_session_ref
from security_runtime.tasks.risk_feedback import TaskRiskFeedbackService
from test_finding_feedback import setup, stable_package  # noqa: F401
from test_finding_feedback_mcp import make_server, call as local_call
from test_global_integration import installed, projects, pool_fixture, structured  # noqa: F401
from test_task_context_global_transport import task_pool
from test_task_security import service  # noqa: F401


@pytest.fixture(autouse=True)
def immutable_installed_build(monkeypatch):
    # Other team members may edit source while transport tests run. An installed
    # delivery is immutable; installation ownership is tested independently.
    monkeypatch.setattr('security_runtime.build_identity.build_identity',
        lambda: dict(status='IDENTIFIED', build_id='c' * 64))


def global_call(server, name, root=None, **arguments):
    if root is not None:
        arguments['workspace_path'] = str(root)
    return structured(asyncio.run(server.call_tool(name, arguments)))


def review_arguments(server, finding):
    prepared = local_call(server, 'prepare_finding_feedback', scan_id='s1', finding_id=finding.id)
    return dict(scan_id='s1', finding_id=finding.id,
        feedback_session=prepared['feedback_session'], context_hash=prepared['packet']['context_hash'],
        verdict='FALSE_POSITIVE', reason='The call binds the supplied value separately.',
        context_complete=True,
        evidence_refs=[dict(file='app.py', start_line=2, end_line=2,
                            claim='The separate parameter tuple protects this call.')])


def test_evidence_item_schema_requires_all_four_fields_and_no_extras(tmp_path):
    _, store, _, _ = setup(tmp_path)
    server, _ = make_server(store, tmp_path)
    schema = server._tool_manager.get_tool('submit_finding_feedback').parameters
    item = schema['$defs']['FindingEvidenceReference']
    assert set(item['required']) == {'file', 'start_line', 'end_line', 'claim'}
    assert item['additionalProperties'] is False
    assert item['properties']['start_line']['type'] == 'integer'
    assert item['properties']['start_line']['minimum'] == 1
    assert item['properties']['claim']['minLength'] == 1
    assert item['properties']['claim']['maxLength'] == 500
    assert schema['properties']['evidence_refs']['items'] == {'$ref': '#/$defs/FindingEvidenceReference'}


@pytest.mark.parametrize('change', [
    lambda ref: ref.pop('claim'),
    lambda ref: ref.update(start_line=True),
    lambda ref: ref.update(line_start=2),
    lambda ref: ref.update(start_line=3, end_line=2),
])
def test_local_invalid_evidence_is_actionable_and_does_not_consume_handoff(tmp_path, change):
    _, store, finding, _ = setup(tmp_path)
    server, _ = make_server(store, tmp_path)
    arguments = review_arguments(server, finding)
    invalid = copy.deepcopy(arguments)
    change(invalid['evidence_refs'][0])
    with pytest.raises(Exception, match='FEEDBACK_INPUT_INVALID') as error:
        local_call(server, 'submit_finding_feedback', **invalid)
    assert 'WORKSPACE_OR_REFERENCE_REJECTED' not in str(error.value)
    assert 'INVALID_HOST_CLAIMS' not in str(error.value)
    saved = local_call(server, 'submit_finding_feedback', **arguments)
    assert saved['agent_review']['verdict'] == 'FALSE_POSITIVE'
    assert not saved['repair_authorized']


def feedback_pool(installed, tmp_path):
    stores, findings = {}, {}

    def child(root, directory, binding):
        source = root / 'app.py'
        source.write_text('def query(db, value):\n    db.execute(value)\n', encoding='utf-8')
        store = SQLiteStore(directory / 'scans.db')
        finding = FindingNormalizer(root).make(scanner='semgrep', category='sql-injection',
            title='Candidate', description='Review required', severity='HIGH', confidence='MEDIUM',
            file_path='app.py', line=2, rule_id='fixture.rule', evidence='candidate')
        finding.technical_details['evidence_locator'] = snapshot_fingerprint(root, 'app.py')
        store.save(ScanResult('scan-' + root.name, 'quick', TargetProfile(str(root), files=['app.py']),
            'COMPLETED', [finding], [ScannerRun('semgrep', '1.0', 'SUCCESS', 1)], '', 'REVIEW', 1))
        runtime = SecurityRuntime(store=store)
        core = HookCoordinator(runtime, HookStateStore(directory / 'hooks'))
        stores[root], findings[root] = store, finding
        return create_server(runtime, hook_coordinator=core, workspace_binding=binding,
                             global_mode=False), core

    return pool_fixture(installed, tmp_path, child), stores, findings


def test_global_feedback_schema_errors_do_not_claim_workspace_or_host_failure(installed, projects, tmp_path):
    pool, _, _ = feedback_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    try:
        tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
        for name in ('set_finding_disposition', 'set_task_risk_disposition', 'get_task_risk_feedback'):
            assert 'workspace_path' in tools[name].inputSchema['required']
        arguments = dict(scan_id='scan-a', finding_id='finding', feedback_session='token',
            context_hash='hash', verdict='FALSE_POSITIVE', reason='Review',
            evidence_refs=[dict(file='app.py', start_line=2, end_line=2)])
        rejected = global_call(server, 'submit_finding_feedback', projects[0], **arguments)
        assert rejected['reason_code'] == 'FEEDBACK_INPUT_INVALID'
        assert not rejected['saved'] and not rejected['repair_authorized']
        assert 'host_claim_status' not in rejected and 'workspace_readiness' not in rejected
        assert not pool.children
        missing_workspace = global_call(server, 'set_finding_disposition',
            scan_id='scan-a', finding_id='f', disposition='EXCLUDE', user_requested=True)
        assert missing_workspace['reason_code'] == 'FEEDBACK_INPUT_INVALID'
    finally:
        pool.close()


def test_global_saved_choice_is_independent_and_cannot_cross_projects(installed, projects, tmp_path):
    pool, stores, findings = feedback_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    first, other = projects
    try:
        pool.admit(first)
        pool.admit(other)
        before = copy.deepcopy(stores[first].get_scan('scan-a'))
        selected = dict(scan_id='scan-a', finding_id=findings[first].id)
        saved = global_call(server, 'set_finding_disposition', first, **selected,
            disposition='EXCLUDE', user_requested=True, request_id='exclude-1')
        assert saved['handling_status'] == 'EXCLUDED'
        assert saved['disposition']['active'] and saved['agent_review'] is None
        assert not saved['repair_authorized'] and stores[first].get_scan('scan-a') == before
        rejected = global_call(server, 'set_finding_disposition', other, **selected,
            disposition='RESTORE', user_requested=True)
        assert rejected['reason_code'] == 'FEEDBACK_REFERENCE_REJECTED'
        assert 'workspace_readiness' not in rejected and not rejected['saved']
        assert global_call(server, 'get_finding_feedback', first, **selected)['handling_status'] == 'EXCLUDED'
        restored = global_call(server, 'set_finding_disposition', first, **selected,
            disposition='RESTORE', user_requested=True)
        assert restored['handling_status'] == 'PENDING'
    finally:
        pool.close()


def test_global_review_submission_distinguishes_range_expiry_and_source_change(installed, projects, tmp_path):
    pool, _, findings = feedback_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        pool.admit(root)
        selected = dict(scan_id='scan-a', finding_id=findings[root].id)
        prepared = global_call(server, 'prepare_finding_feedback', root, **selected)
        arguments = dict(selected, feedback_session=prepared['feedback_session'],
            context_hash=prepared['packet']['context_hash'], verdict='STILL_RISK',
            reason='The call has no bound parameter tuple.', context_complete=True,
            evidence_refs=[dict(file='app.py', start_line=2, end_line=2,
                                claim='Input is passed directly into the database call.')])
        fabricated = copy.deepcopy(arguments)
        fabricated['evidence_refs'][0]['file'] = 'unissued.py'
        rejected = global_call(server, 'submit_finding_feedback', root, **fabricated)
        assert rejected['reason_code'] == 'FEEDBACK_EVIDENCE_REJECTED'
        saved = global_call(server, 'submit_finding_feedback', root, **arguments)
        assert saved['agent_review']['verdict'] == 'STILL_RISK'
        assert not saved['repair_authorized']
        expired = global_call(server, 'submit_finding_feedback', root, **arguments)
        assert expired['reason_code'] == 'FEEDBACK_SESSION_EXPIRED'
        prepared = global_call(server, 'prepare_finding_feedback', root, **selected)
        arguments.update(feedback_session=prepared['feedback_session'], context_hash=prepared['packet']['context_hash'])
        (root / 'app.py').write_text('def query(db, value):\n    return db.execute(value)\n', encoding='utf-8')
        stale = global_call(server, 'submit_finding_feedback', root, **arguments)
        assert stale['reason_code'] == 'FEEDBACK_EVIDENCE_CHANGED'
        for result in (rejected, expired, stale):
            assert 'workspace_readiness' not in result and 'host_claim_status' not in result
            assert not result['saved']
    finally:
        pool.close()


@pytest.mark.parametrize('value', [False, 1, 'true', None])
def test_disposition_requires_literal_user_intent_before_delegate(tmp_path, monkeypatch, value):
    _, store, finding, _ = setup(tmp_path)
    server, _ = make_server(store, tmp_path)
    calls = []
    monkeypatch.setattr('security_runtime.finding_feedback.FindingFeedbackService.set_disposition',
        lambda *args, **kwargs: calls.append(kwargs))
    with pytest.raises(Exception, match='FEEDBACK_INPUT_INVALID'):
        local_call(server, 'set_finding_disposition', scan_id='s1', finding_id=finding.id,
            disposition='EXCLUDE', user_requested=value)
    assert calls == []


def test_global_save_failure_is_explicit_and_never_echoes_exception(installed, projects, tmp_path, monkeypatch):
    from security_runtime.risk_disposition import RiskDispositionStore
    pool, _, findings = feedback_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        pool.admit(root)
        def fail(*args, **kwargs):
            raise OSError('private-source-and-secret-must-not-escape')
        monkeypatch.setattr(RiskDispositionStore, 'set', fail)
        failed = global_call(server, 'set_finding_disposition', root,
            scan_id='scan-a', finding_id=findings[root].id, disposition='EXCLUDE', user_requested=True)
        assert failed['reason_code'] == 'FEEDBACK_SAVE_FAILED'
        assert not failed['saved'] and not failed['repair_authorized']
        assert 'private-source' not in json.dumps(failed)
        current = global_call(server, 'get_finding_feedback', root,
            scan_id='scan-a', finding_id=findings[root].id)
        assert current['handling_status'] == 'PENDING'
    finally:
        pool.close()


def test_local_task_disposition_forwards_owner_bound_service_and_optional_fields(service, monkeypatch):
    tasks, root, runtime = service
    seen = []
    def save(self, service, workspace, ref, finding, disposition, reason='', **kwargs):
        service.load(workspace, ref)
        seen.append((ref, finding, disposition, reason, kwargs))
        return dict(saved=True, repair_authorized=False)
    monkeypatch.setattr(TaskRiskFeedbackService, 'set_disposition', save)
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, tasks.hooks), global_mode=False)
    token = issue_session_ref(tasks.hooks, root, 'codex', 'disposition-owner')
    foreign = issue_session_ref(tasks.hooks, root, 'codex', 'foreign-owner')
    ref = local_call(server, 'begin_security_task', workspace_path=str(root), task_key='disposition',
                     session_ref=token)['task_ref']
    args = dict(task_ref=ref, finding_id='risk-1', disposition='DEFER', reason='',
        user_requested=True, until='2099-01-01T00:00:00Z', request_id='decision-1', workspace_path=str(root))
    assert local_call(server, 'set_task_risk_disposition', **args, session_ref=token)['saved']
    assert seen[0][-1] == dict(user_requested=True, until=args['until'], request_id='decision-1')
    with pytest.raises(Exception, match='TASK_SESSION_SCOPE_MISMATCH'):
        local_call(server, 'set_task_risk_disposition', **args, session_ref=foreign)
    assert len(seen) == 1 and not runtime.calls


def test_global_task_disposition_preserves_owner_diagnostics(installed, projects, tmp_path, monkeypatch):
    def save(self, service, workspace, ref, finding, disposition, reason='', **kwargs):
        service.load(workspace, ref)
        return dict(saved=True, repair_authorized=False)
    monkeypatch.setattr(TaskRiskFeedbackService, 'set_disposition', save)
    pool, _ = task_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        pool.admit(root)
        core = pool.children[root][1]
        token = issue_session_ref(core.store, root, 'codex', 'owner')
        foreign = issue_session_ref(core.store, root, 'codex', 'other')
        ref = global_call(server, 'begin_security_task', root, task_key='disposition', session_ref=token)['task_ref']
        args = dict(task_ref=ref, finding_id='risk-1', disposition='EXCLUDE', user_requested=True)
        assert global_call(server, 'set_task_risk_disposition', root, **args, session_ref=token)['saved']
        rejected = global_call(server, 'set_task_risk_disposition', root, **args, session_ref=foreign)
        assert rejected['reason_code'] == 'TASK_SESSION_SCOPE_MISMATCH'
        assert 'workspace_readiness' not in rejected and not rejected['repair_authorized']
    finally:
        pool.close()


def test_task_feedback_read_reconnects_with_original_session_and_rejects_other_session(service):
    from security_runtime.tasks.ownership import session_owner
    from test_task_risk_feedback import host_risk
    tasks, root, runtime = service
    tasks.owner = session_owner('codex', 'original-feedback-reader')
    _, _, ref, finding_id = host_risk(service)
    token = issue_session_ref(tasks.hooks, root, 'codex', 'original-feedback-reader')
    foreign = issue_session_ref(tasks.hooks, root, 'codex', 'other-feedback-reader')
    original = copy.deepcopy(tasks.load(root, ref))
    arguments = dict(task_ref=ref, finding_id=finding_id, workspace_path=str(root))
    for _ in range(2):
        server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, tasks.hooks),
                               global_mode=False)
        viewed = local_call(server, 'get_task_risk_feedback', **arguments, session_ref=token)
        assert viewed['finding_id'] == finding_id
        assert viewed['original_risk_status'] == 'OPEN' and not viewed['repair_authorized']
        with pytest.raises(Exception, match='TASK_SESSION_SCOPE_MISMATCH'):
            local_call(server, 'get_task_risk_feedback', **arguments, session_ref=foreign)
        assert tasks.load(root, ref) == original


def test_cursor_preapproves_bounded_feedback_but_never_repair_or_scans():
    assert {'set_finding_disposition', 'set_task_risk_disposition', 'submit_finding_feedback',
            'prepare_task_risk_feedback', 'get_task_risk_feedback'} <= set(ROUTINE_TOOLS)
    assert not {'confirm_remediation', 'prepare_task_fix', 'scan_project', 'scan_diff',
                'generate_fix', 'verify_task_fix'} & set(ROUTINE_TOOLS)


@pytest.mark.parametrize('state,expected', [
    (dict(agent_review_current=False, technical_assessment_current=True, folded=False), False),
    (dict(agent_review_current=False, technical_false_positive=True, folded=True), False),
    (dict(agent_review_current=False, folded=True, disposition=dict(active=True)), False),
    (dict(agent_review_current=False, folded=True,
          disposition=dict(active=True, reassessment_required=True)), True),
    (dict(agent_review_current=False, folded=False), True),
])
def test_review_continuation_uses_current_assessment_and_keeps_saved_choices_quiet(tmp_path, monkeypatch,
                                                                               state, expected):
    _, store, finding, _ = setup(tmp_path)
    server, _ = make_server(store, tmp_path)
    monkeypatch.setattr('security_runtime.finding_feedback.FindingFeedbackService.status',
                        lambda *args, **kwargs: state)
    record = local_call(server, 'get_findings', scan_id='s1', view='full')[0]
    assert ('review_continuation' in record) is expected
    if expected:
        assert record['review_continuation']['arguments'] == dict(scan_id='s1', finding_id=finding.id)
        assert 'notify only after new material risk evidence' in record['review_continuation']['purpose']


@pytest.mark.parametrize('tool,method', [('get_security_summary', 'presentations'), ('get_findings', 'status')])
def test_local_projection_reports_unreadable_decisions_without_old_ai_fallback(tmp_path, monkeypatch,
                                                                             tool, method):
    from security_runtime.risk_disposition import DispositionUnavailable
    root, store, _, _ = setup(tmp_path)
    server, _ = make_server(store, tmp_path)
    def unreadable(*args, **kwargs):
        raise DispositionUnavailable('private-state-error-must-not-escape')
    monkeypatch.setattr('security_runtime.finding_feedback.FindingFeedbackService.' + method, unreadable)
    arguments = dict(scan_id='s1')
    if tool == 'get_security_summary':
        arguments['workspace_path'] = str(root)
    with pytest.raises(Exception, match='FEEDBACK_UNAVAILABLE') as failure:
        local_call(server, tool, **arguments)
    assert 'private-state-error' not in str(failure.value)


@pytest.mark.parametrize('tool,method', [('get_security_summary', 'presentations'), ('get_findings', 'status')])
def test_global_projection_preserves_typed_unavailable_instead_of_workspace_failure(installed, projects,
                                                                                   tmp_path, monkeypatch,
                                                                                   tool, method):
    from security_runtime.risk_disposition import DispositionUnavailable
    pool, _, findings = feedback_pool(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    root = projects[0]
    try:
        pool.admit(root)
        selected = dict(scan_id='scan-a', finding_id=findings[root].id)
        global_call(server, 'set_finding_disposition', root, **selected,
                    disposition='EXCLUDE', user_requested=True)
        with monkeypatch.context() as unavailable:
            def unreadable(*args, **kwargs):
                raise DispositionUnavailable('private-state-error-must-not-escape')
            unavailable.setattr('security_runtime.finding_feedback.FindingFeedbackService.' + method,
                                unreadable)
            result = asyncio.run(server.call_tool(tool, dict(workspace_path=str(root), scan_id='scan-a')))
            rejected = structured(result)
            assert result.isError and rejected['reason_code'] == 'FEEDBACK_UNAVAILABLE'
            assert 'workspace_readiness' not in rejected and 'host_claim_status' not in rejected
            assert 'risk_handling' not in rejected and not rejected['repair_authorized']
            assert 'private-state-error' not in json.dumps(rejected)
        current = global_call(server, 'get_finding_feedback', root, **selected)
        assert current['handling_status'] == 'EXCLUDED'
    finally:
        pool.close()
