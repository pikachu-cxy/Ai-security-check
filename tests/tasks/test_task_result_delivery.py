"""Current completion delivery and history share bounds, never authority."""
import copy
import json
import sqlite3

import pytest

from security_runtime.compatibility import TASK_REVIEW_TOOLS, task_review_compatibility
from security_runtime.guidance.host_guidance import runtime_info
from security_runtime.tasks.ownership import session_owner, TaskOwnershipError
from security_runtime.task_review.results import bounded_history_result, MAX_RESULT_BYTES
from security_runtime.tasks.security import TaskSecurityService
from test_task_review_results import record
from test_task_risk_feedback import host_risk
from test_task_security import service  # noqa: F401


def assert_bound(packet):
    size = len(json.dumps(packet, ensure_ascii=False).encode('utf-8'))
    assert size == packet['response_bytes'] <= MAX_RESULT_BYTES


def test_current_delivery_preserves_four_sections_and_source_specific_routes():
    original = record(1, 1)
    original['review_revision'] = 3
    before = copy.deepcopy(original)
    packet = bounded_history_result(original, delivery=True)
    for label in ('📍', '**问题**', '**可能影响**', '**建议修复**', '**尚未确认**'):
        assert label in packet['development_summary']
    assert packet['development_summary'].count('请选择具体风险') == 1
    assert packet['delivery_read_only'] and not packet['history_read_only']
    assert not packet['repair_authorized'] and not packet['scanner_run']
    choices = {item['source']: item for item in packet['risk_choices']}
    assert choices['STATIC_SCAN']['scan_id'] == 'scan-id'
    assert choices['STATIC_SCAN']['handling_tool'] == 'set_finding_disposition'
    assert choices['STATIC_SCAN']['repair_workflow'] == 'SCANNER_TASK_GROUP'
    assert choices['HOST_TASK_REVIEW']['task_ref'] == original['task_ref']
    assert choices['HOST_TASK_REVIEW']['repair_workflow'] == 'HOST_TASK_RISK'
    assert original == before
    assert_bound(packet)


@pytest.mark.parametrize('source', ['static', 'host'])
@pytest.mark.parametrize('state', ['DEFERRED', 'EXCLUDED'])
def test_both_sources_keep_saved_details_but_never_reprompt_suppressed_risks(source, state):
    original = record(1, 1)
    identifier = source+'-0'
    values = {identifier: dict(reminder_suppressed=True, folded=True, handling_status=state,
        disposition=dict(disposition='DEFER' if state == 'DEFERRED' else 'EXCLUDE', active=True))}
    kwargs = {'static_feedback' if source == 'static' else 'feedback': values}
    packet = bounded_history_result(original, delivery=True, **kwargs)
    assert len(packet['findings']) == packet['risk_counts']['raw_total'] == 2
    assert packet['risk_counts']['current_pending_total'] == 1
    assert packet['reply_plan']['visible_risk_count'] == 1
    assert [item['finding_id'] for item in packet['risk_choices']] == [
        ('host-0' if source == 'static' else 'static-0')]
    item = next(item['detail'] for item in packet['findings'] if item['detail']['id'] == identifier)
    assert item['feedback']['handling_status'] == state
    assert item['impact'] == original['static' if source == 'static' else 'review']['findings'][0]['impact']
    assert_bound(packet)


def test_history_pages_never_repeat_choices_even_when_current_and_pending():
    packet = bounded_history_result(record(1, 1))
    assert packet['reply_plan']['visible_risk_count'] == 2
    assert packet['reply_plan']['action_count'] == 0
    assert not packet['risk_choices']
    assert '回复' not in packet['development_summary']
    assert packet['history_read_only']
    assert_bound(packet)


def test_no_change_delivery_is_quiet_without_hiding_requested_history():
    original = record(0, 0)
    original['phase'] = 'NO_CHANGES'
    assert bounded_history_result(original, delivery=True)['development_summary'] == ''
    assert '没有可检查' in bounded_history_result(original)['development_summary']


def test_current_pages_retain_revision_complete_details_and_separate_counts():
    original = record(2, 5)
    original['review_revision'] = 7
    original['review']['findings'][0]['impact'] = '条件影响' * 2000
    offset, returned = 0, []
    while True:
        packet = bounded_history_result(original, offset, 3, delivery=True)
        assert_bound(packet)
        assert packet['risk_counts']['raw_total'] == 7
        assert packet['risk_counts']['current_pending_total'] == 7
        assert packet['risk_counts']['page_visible'] == len(packet['findings'])
        returned.extend(item['detail']['id'] for item in packet['findings'])
        assert all(item['details_complete'] for item in packet['findings'])
        if not packet['finding_page']['has_more']:
            break
        assert packet['next_action']['completion_revision'] == 7
        offset = packet['next_action']['finding_offset']
    assert returned == ['static-0', 'static-1']+['host-'+str(i) for i in range(5)]


def test_oversized_current_detail_has_no_choice_and_can_continue_same_revision():
    original = record(0, 2)
    original['review']['findings'][0]['impact'] = '风' * 30_000
    packet = bounded_history_result(original, delivery=True)
    assert not packet['details_complete'] and packet['reason_code'] == 'RESULT_DETAIL_LIMIT'
    assert not packet['risk_choices']
    assert packet['next_action']['completion_revision'] == 1
    assert packet['next_action']['finding_offset'] == 1
    assert_bound(packet)


@pytest.mark.parametrize('failure', [OSError('unavailable'), ValueError('untrusted'),
                                     sqlite3.DatabaseError('unreadable')])
def test_feedback_failure_does_not_hide_committed_result_or_invent_pending_choices(service, monkeypatch, failure):
    tasks, root, ref, _ = host_risk(service)
    before = copy.deepcopy(tasks.load(root, ref))
    calls = len(service[2].calls)
    def unavailable(_record, **_kwargs):
        raise failure
    monkeypatch.setattr(tasks, '_current_handling', unavailable)
    for kwargs in ({}, dict(completion_revision=before.get('review_revision', 1))):
        packet = tasks.get(root, ref, **kwargs)
        assert packet['findings'][0]['details_complete']
        assert packet['risk_counts']['current_handling'] == 'UNKNOWN'
        assert packet['risk_counts']['current_pending_total'] is None
        assert packet['reply_plan']['visible_risk_count'] is None
        assert not packet['risk_choices'] and '回复' not in packet['development_summary']
        assert '无法读取' in packet['development_summary']
        assert_bound(packet)
    assert tasks.load(root, ref) == before and len(service[2].calls) == calls


def test_current_delivery_requires_original_owner_revision_and_current_source(service):
    tasks, root, ref, _ = host_risk(service)
    before = copy.deepcopy(tasks.load(root, ref))
    revision = before.get('review_revision', 1)
    calls = len(service[2].calls)
    current = tasks.get(root, ref, completion_revision=revision)
    assert current['delivery_status'] == 'CURRENT' and current['risk_choices']
    foreign = TaskSecurityService(service[2], tasks.hooks,
        owner=session_owner('codex', 'different-delivery-session'))
    assert foreign.get(root, ref)['history_read_only']
    with pytest.raises(TaskOwnershipError):
        foreign.get(root, ref, completion_revision=revision)
    for invalid in (True, revision+1, '1'):
        with pytest.raises(ValueError, match='completion revision'):
            tasks.get(root, ref, completion_revision=invalid)
    (root/'auth.py').write_text('def owns(user, order):\n    return True\n')
    stale = tasks.get(root, ref, completion_revision=revision)
    assert stale['delivery_status'] == 'SOURCE_NOT_CURRENT'
    assert stale['history_read_only'] and not stale['risk_choices']
    assert stale['delivery_notice'] in stale['development_summary']
    assert tasks.load(root, ref) == before and len(service[2].calls) == calls


def test_active_record_cannot_be_selected_as_current_completion(service):
    tasks, root, runtime = service
    ref = tasks.begin(root, 'no-terminal-delivery')['task_ref']
    before = copy.deepcopy(tasks.load(root, ref))
    with pytest.raises(ValueError, match='completion revision'):
        tasks.get(root, ref, completion_revision=1)
    assert tasks.load(root, ref) == before and not runtime.calls


def test_cold_mcp_history_uses_existing_scan_store_without_runtime_or_schema_writes(tmp_path, monkeypatch):
    from security_runtime.finding_feedback import FindingFeedbackService
    from security_runtime.mcp_contracts import MCPRegistry
    from security_runtime.mcp_server import create_server
    from security_runtime.storage import ReadOnlySQLiteStore, SQLiteStore

    root = tmp_path/'project'
    root.mkdir()
    database = tmp_path/'legacy-scans.db'
    with sqlite3.connect(database) as connection:
        connection.execute('CREATE TABLE scans(id TEXT PRIMARY KEY, data TEXT NOT NULL)')
        connection.execute('INSERT INTO scans VALUES (?, ?)', ('scan-id', '{"id":"scan-id"}'))
    original = record(1, 0)
    original['workspace'] = str(root)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'uncreated-state'))
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    monkeypatch.setattr(SQLiteStore, 'default_path', staticmethod(lambda: database))
    def no_runtime(*args, **kwargs):
        pytest.fail('A saved-result read initialized the writable runtime/store')
    monkeypatch.setattr('security_runtime.mcp_server.SecurityRuntime', no_runtime)
    monkeypatch.setattr(SQLiteStore, '__init__', no_runtime)
    monkeypatch.setattr(TaskSecurityService, 'load', lambda *args, **kwargs: original)
    monkeypatch.setattr('security_runtime.tasks.security.capture', lambda *args, **kwargs: original['end'])
    monkeypatch.setattr('security_runtime.tasks.risk_feedback.feedback_for_record', lambda *args: {})
    observed = []
    def presentations(feedback, scan_id):
        assert isinstance(feedback.store, ReadOnlySQLiteStore)
        observed.append(scan_id)
        return {'static-0': dict(reminder_suppressed=True, handling_status='DEFERRED')}
    monkeypatch.setattr(FindingFeedbackService, 'presentations', presentations)
    server = create_server(global_mode=False)
    before = {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}
    packet = MCPRegistry(server).tool('get_task_security_review').fn(original['task_ref'], workspace_path=str(root))
    assert observed == ['scan-id']
    assert packet['current_version'] is True
    assert packet['risk_counts']['current_pending_static'] == 0 and not packet['risk_choices']
    assert {path.relative_to(tmp_path): path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()} == before
    assert not (tmp_path/'uncreated-state').exists()


def test_same_semver_old_runtime_cannot_claim_current_delivery_compatibility():
    info = runtime_info()
    # Build identity is orthogonal and synthetic here, never scanner evidence.
    info['build_identity'] = dict(build_id='b' * 64)
    assert task_review_compatibility(info, TASK_REVIEW_TOOLS)['status'] == 'SUPPORTED'
    info['features'].pop('task_security_result_delivery')
    old = task_review_compatibility(info, TASK_REVIEW_TOOLS)
    assert old['status'] == 'UPGRADE_OR_RECONNECT_REQUIRED'
    assert 'TASK_RESULT_DELIVERY_REQUIRED' in old['reasons']
    assert not old['fallback_allowed']
