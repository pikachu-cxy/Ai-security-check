"""Conversational feedback works through the public MCP and summary surfaces."""
import asyncio
import copy
import json

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from security_runtime.runtime import SecurityRuntime
from security_runtime.security_summary import SecuritySummaryService
from test_finding_feedback import setup, stable_package
from test_global_integration import structured
from summary_fixtures import sample


def call(server, name, **arguments):
    result = asyncio.run(server._tool_manager.call_tool(name, arguments, convert_result=True))
    data = structured(result)
    return data.get('result', data) if isinstance(data, dict) else data


def make_server(store, tmp_path):
    runtime = SecurityRuntime(store=store)
    hooks = HookStateStore(tmp_path / 'hooks')
    return create_server(runtime, global_mode=False,
                         hook_coordinator=HookCoordinator(runtime, hooks)), hooks


def review(server, finding):
    packet = call(server, 'prepare_finding_feedback', scan_id='s1', finding_id=finding.id)
    arguments = dict(scan_id='s1', finding_id=finding.id, feedback_session=packet['feedback_session'],
        context_hash=packet['packet']['context_hash'], verdict='FALSE_POSITIVE',
        reason='A separate bound parameter tuple supplies the value.', context_complete=True,
        evidence_refs=[dict(file='app.py', start_line=2, end_line=2,
                            claim='The selected call uses a separate parameter tuple.')])
    return arguments, call(server, 'submit_finding_feedback', **arguments)


def test_user_reply_review_projection_and_revoke_preserve_scanner_record(tmp_path):
    root, store, finding, _ = setup(tmp_path)
    server, hooks = make_server(store, tmp_path)
    before = copy.deepcopy(store.get_scan('s1'))
    label = call(server, 'mark_finding_false_positive', scan_id='s1', finding_id=finding.id,
                 reason='This call binds the input separately.', user_requested=True)
    assert label['state'] == 'USER_MARKED_UNCONFIRMED' and not label['folded']
    arguments, saved = review(server, finding)
    assert saved['folded'] and not saved['fix_authorized']
    found = call(server, 'get_findings', scan_id='s1', view='summary')['items'][0]
    assert found['false_positive_review']['folded']
    summary = SecuritySummaryService(store, hooks).get(root, 's1', details=True)
    assert summary['false_positive_feedback']['folded_finding_count'] == 1
    assert summary['recommended_tasks'] == [] and summary['tasks'][0]['active_finding_count'] == 0
    assert store.get_scan('s1') == before
    assert summary['release_status'] != 'NO_FINDINGS'
    with pytest.raises(Exception):  # A successful handoff is consumed.
        call(server, 'submit_finding_feedback', **arguments)
    state = call(server, 'revoke_finding_feedback', scan_id='s1', finding_id=finding.id,
                 reason='Reconsider this assessment.', user_requested=True)
    assert not state['folded']
    assert SecuritySummaryService(store, hooks).get(root, 's1')['recommended_tasks']


def test_feedback_cannot_cross_connection_or_fake_user_intent(tmp_path):
    _, store, finding, _ = setup(tmp_path)
    first, _ = make_server(store, tmp_path)
    arguments, _ = review(first, finding)
    other, _ = make_server(store, tmp_path)
    with pytest.raises(Exception):
        call(other, 'submit_finding_feedback', **arguments)
    for value in (False, 'true', 1):
        with pytest.raises(Exception):
            call(first, 'mark_finding_false_positive', scan_id='s1', finding_id=finding.id,
                 reason='Unconfirmed intent', user_requested=value)


def test_changed_code_expands_previously_folded_reminder(tmp_path):
    root, store, finding, _ = setup(tmp_path)
    server, hooks = make_server(store, tmp_path)
    review(server, finding)
    (root / 'app.py').write_text('def query(db, value):\n    db.execute(value)\n')
    saved = call(server, 'get_finding_feedback', scan_id='s1', finding_id=finding.id,
                 include_history=True)
    assert saved['state'] == 'REVIEW_STALE' and not saved['folded']
    summary = SecuritySummaryService(store, hooks).get(root, 's1')
    assert summary['recommended_tasks'] and summary['false_positive_feedback']['stale_review_count'] == 1


def test_one_folded_member_does_not_hide_other_risk_in_same_group(sample, monkeypatch):
    from security_runtime.finding_feedback import FindingFeedbackService
    root, scan, store = sample
    first_id = scan.findings[0].id
    # Exercise grouping with a previously validated presentation. Evidence and
    # freshness validation are covered by the public-tool tests above.
    monkeypatch.setattr(FindingFeedbackService, 'presentations', lambda self, scan_id: {
        finding.id: dict(finding_id=finding.id, folded=finding.id == first_id,
                         state='AGENT_FALSE_POSITIVE' if finding.id == first_id else 'UNREVIEWED',
                         message='Current reviewed opinion' if finding.id == first_id else '')
        for finding in scan.findings})
    summary = SecuritySummaryService(store).get(root, scan.scan_id, details=True)
    task = next(task for task in summary['tasks'] if task['topic'] == 'tls')
    assert task['finding_count'] == 2 and task['active_finding_count'] == 1
    assert task['folded_finding_count'] == 1
    assert task in summary['recommended_tasks']
    assert len(store.get_scan(scan.scan_id)['findings']) == 7


@pytest.mark.parametrize('fold_count', [1, 2])
def test_fix_handoff_excludes_reviewed_false_positives_but_keeps_original_reference(sample, monkeypatch, fold_count):
    from security_runtime.finding_feedback import FindingFeedbackService
    from security_runtime.tasks.fix import TaskFixService
    root, scan, store = sample
    original = next(task for task in SecuritySummaryService(store).get(root, scan.scan_id, details=True)['tasks']
                    if task['topic'] == 'tls')
    folded_ids = {finding.id for finding in scan.findings[:fold_count]}
    monkeypatch.setattr(FindingFeedbackService, 'presentations', lambda self, scan_id: {
        finding.id: dict(finding_id=finding.id, folded=finding.id in folded_ids,
                         state='AGENT_FALSE_POSITIVE' if finding.id in folded_ids else 'UNREVIEWED',
                         message='Reviewed opinion') for finding in scan.findings})
    prepared = TaskFixService(store).prepare(original['task_ref'], root)
    assert prepared['task_ref'] == original['task_ref']
    assert {item['finding_id'] for item in prepared['excluded_false_positive_findings']} == folded_ids
    assert not {item['finding_id'] for item in prepared['affected_findings']} & folded_ids
    if fold_count == 2:
        assert prepared['status'] == 'NO_ACTIVE_FINDINGS' and not prepared['recommended_changes']
        assert not prepared['repair_authorized']
    else:
        assert prepared['affected_finding_count'] == 1
        assert {packet['finding_id'] for packet in prepared['bounded_evidence']}.isdisjoint(folded_ids)
        assert prepared['verification_plan']['all_group_members_required']
        from security_runtime.fix_context import compact_packet
        compact = compact_packet(dict(prepared, remediation_authorization={}), {}, 'context-ref', {}, reuse=True)
        assert compact['affected_findings'] == prepared['affected_findings']
        assert compact['excluded_false_positive_findings'] == prepared['excluded_false_positive_findings']
        assert compact['fix_constraints'] == prepared['fix_constraints']
        assert 'do not repair excluded_false_positive_findings' in compact['host_protocol']['instructions']
