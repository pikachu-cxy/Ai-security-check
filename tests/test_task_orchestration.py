"""Shared task handoffs preserve owners, source records and observable delivery facts."""
import copy
import json

import pytest

from security_runtime.cursor_tasks import CursorTaskBridge, DELIVERY_CONTEXT_MARKER
from security_runtime.task_orchestration import (
    select_task, TaskSelectionError, review_protocol, task_needs_handoff,
    task_allows_followup, task_delivery_facts,
)
from security_runtime.task_ownership import session_owner
from security_runtime.task_review_protocol import UnsupportedTaskReviewProtocol
from security_runtime.task_security import TaskSecurityService
from security_runtime.task_security_state import TaskSecurityStore
from security_runtime.hook_reply_context import CONTROL_DELIMITER
from test_cursor_automatic import ingress, tool
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_task_hook_deferred_feedback import development, introduce_risk


def test_selection_fences_other_sessions_and_keeps_only_explicit_legacy_hook_fallback(repo, tmp_path):
    core = coordinator(tmp_path, FakeRuntime())
    first_owner, second_owner = session_owner('cursor', 'one'), session_owner('codex', 'two')
    first = TaskSecurityService(core.runtime, core.store, owner=first_owner).begin(repo, 'same-key')
    second = TaskSecurityService(core.runtime, core.store, owner=second_owner).begin(repo, 'same-key')
    store = TaskSecurityStore(core.store, repo)
    assert select_task(store, first_owner)['task_ref'] == first['task_ref']
    assert select_task(store, second_owner, hook=True)['task_ref'] == second['task_ref']
    with pytest.raises(TaskSelectionError):
        select_task(store, second_owner, task_ref=first['task_ref'], hook=True)
    assert select_task(store, session_owner('cursor', 'new'), hook=True) is None

    # Compatibility is an explicit Hook lookup, never automatic task adoption.
    other = tmp_path / 'legacy'; other.mkdir()
    legacy = TaskSecurityService(core.runtime, core.store).begin(other, 'unowned')
    old_store = TaskSecurityStore(core.store, other)
    assert select_task(old_store, second_owner, hook=True)['task_ref'] == legacy['task_ref']
    assert select_task(old_store, second_owner) is None


def test_explicit_v3_protocol_is_selected_without_rewriting_record():
    record = {'review_protocol': 3}
    before = copy.deepcopy(record)
    assert review_protocol(record) == 3
    assert record == before


@pytest.mark.parametrize('record', [{}, {'review_session': 'legacy'},
    *({'review_protocol': value} for value in [1, 2, True, '3', 0, 4, None])])
def test_legacy_or_invalid_review_protocol_is_read_only_and_never_upgraded(record):
    before = copy.deepcopy(record)
    with pytest.raises(UnsupportedTaskReviewProtocol):
        review_protocol(record)
    assert record == before
    assert not task_needs_handoff(record) and not task_allows_followup(record)


def test_delivery_projection_cannot_claim_scan_persistence_consumption_or_repair():
    record = dict(task_ref='task.exact', phase='READY', review_protocol=3)
    before = copy.deepcopy(record)
    facts = task_delivery_facts(record, context_returned=True, intent='TASK_CLOSEOUT')
    assert facts['check_execution'] == 'UNKNOWN'
    assert facts['observation_scope'] == 'CURRENT_EVENT'
    assert facts['task_recording'] == 'UNKNOWN'
    assert facts['host_report_submitted'] == 'NOT_OBSERVED'
    assert facts['user_consumption'] == 'UNKNOWN'
    assert facts['risk_ledger_sync'] == dict(state='LEGACY_NOT_RECORDED', pending=False)
    assert facts['context_returned'] is True and facts['repair_authorized'] is False
    assert facts['review_protocol'] == 3 and facts['task_pending']
    assert record == before
    assert task_needs_handoff(record) and task_allows_followup(record)
    assert task_needs_handoff(dict(record, phase='STATIC_RUNNING'))
    assert not task_allows_followup(dict(record, phase='STATIC_RUNNING'))
    assert not task_needs_handoff(dict(record, phase='COMPLETE'))


@pytest.mark.parametrize('protocol', [1, 2, None])
def test_historical_delivery_facts_do_not_fabricate_v3_or_pending_work(protocol):
    record = dict(task_ref='task.history', phase='REVIEWING')
    if protocol is not None:
        record['review_protocol'] = protocol
    before = copy.deepcopy(record)
    facts = task_delivery_facts(record)
    assert facts['review_protocol'] == protocol
    assert facts['task_pending'] is False and facts['repair_authorized'] is False
    assert record == before


def test_cursor_context_rejects_foreign_records_and_never_reuses_delivery_facts(repo, tmp_path):
    core = coordinator(tmp_path, FakeRuntime())
    tool(repo, tmp_path, core)
    bridge = CursorTaskBridge(core, repo, 'private-cursor-conversation', 'private-generation')
    record = bridge.current()
    assert bridge.context(record) and bridge.last_delivery
    assert bridge.context(None) is None and bridge.last_delivery is None
    foreign = dict(record, task_owner=session_owner('cursor', 'different-session'))
    with pytest.raises(TaskSelectionError):
        bridge.context(foreign)
    assert bridge.last_delivery is None


def test_cursor_context_keeps_copyable_tool_arguments_separate_from_delivery_metadata(repo, tmp_path):
    core = coordinator(tmp_path, FakeRuntime())
    tool(repo, tmp_path, core)
    bridge = CursorTaskBridge(core, repo, 'private-cursor-conversation', 'private-generation')
    context = bridge.context()
    arguments = json.loads(context.splitlines()[1])
    assert set(arguments) == {'task_ref', 'workspace_path', 'session_ref'}
    assert arguments['task_ref'] == bridge.current()['task_ref']
    assert arguments['workspace_path'] == str(repo)
    metadata = json.loads(context.split(DELIVERY_CONTEXT_MARKER, 1)[1])
    assert metadata == {'task_delivery': bridge.last_delivery}
    assert metadata['task_delivery']['context_returned'] is True
    assert metadata['task_delivery']['repair_authorized'] is False


def test_completed_task_with_pending_projection_does_not_reopen_review_or_stop(repo, tmp_path):
    from security_runtime.task_projection import CONTRACT
    runtime = FakeRuntime(); core = coordinator(tmp_path, runtime)
    tool(repo, tmp_path, core)
    bridge = CursorTaskBridge(core, repo, 'private-cursor-conversation', 'private-generation')
    record = bridge.current()
    record.update(phase='COMPLETE', ledger_projection=dict(contract=CONTRACT, state='PENDING'))
    saved = bridge.tasks.store(repo).save(record)
    facts = task_delivery_facts(saved)
    assert facts['task_pending'] is False
    assert facts['risk_ledger_sync'] == dict(state='PENDING', pending=True)
    assert facts['check_execution'] == 'UNKNOWN' and facts['user_consumption'] == 'UNKNOWN'
    assert bridge.context() is None
    assert ingress(repo, tmp_path, core, 'stop')[0] == {}
    assert bridge.current() == saved and not runtime.calls


def test_codex_active_task_uses_common_facts_without_changing_deferred_feedback(development):
    result = introduce_risk(development)
    facts = result['task_delivery']
    assert facts['task_ref'] == development[-1]
    assert facts['check_execution'] == 'EXECUTED' and facts['task_recording'] == 'RECORDED'
    assert facts['delivery_intent'] == 'TASK_FINAL_SUMMARY'
    assert facts['context_returned'] is True and facts['task_pending']
    assert facts['review_protocol'] == 3
    assert facts['user_consumption'] == 'UNKNOWN' and facts['repair_authorized'] is False
    assert result['continue'] is True and 'systemMessage' not in result
    assert result['remediation']['action'] == 'CONFIRM_REQUIRED'
    control = json.loads(result['hookSpecificOutput']['additionalContext'].split(CONTROL_DELIMITER, 1)[1])
    assert control['task_delivery'] == facts


def test_cursor_check_context_and_bounded_followup_share_observations(repo, tmp_path):
    runtime = FakeRuntime(); core = coordinator(tmp_path, runtime)
    first = tool(repo, tmp_path, core)[1]['task_ref']
    bridge = CursorTaskBridge(core, repo, 'private-cursor-conversation', 'private-generation')
    before = copy.deepcopy(bridge.current()['baseline'])
    (repo / 'A.java').write_text('task bytes')
    output, checked = ingress(repo, tmp_path, core, 'afterFileEdit')
    assert output == {} and checked['task_delivery']['task_recording'] == 'RECORDED'
    assert checked['task_delivery']['check_execution'] == 'EXECUTED'
    assert checked['task_delivery']['context_returned'] is False
    output, delivered = ingress(repo, tmp_path, core, 'postToolUse', tool_name='Write', tool_use_id='opaque')
    assert first in output['additional_context']
    encoded = output['additional_context'].split('\n', 2)[1]
    assert set(json.loads(encoded)) == {'task_ref', 'workspace_path', 'session_ref'}
    metadata = output['additional_context'].split(DELIVERY_CONTEXT_MARKER, 1)[1]
    assert json.loads(metadata)['task_delivery'] == delivered['task_delivery']
    assert delivered['task_delivery']['check_execution'] == 'NOT_EXECUTED'
    assert delivered['task_delivery']['task_recording'] == 'UNKNOWN'
    assert delivered['task_delivery']['context_returned'] is True
    assert delivered['task_delivery']['user_consumption'] == 'UNKNOWN'
    output, stopped = ingress(repo, tmp_path, core, 'stop')
    assert first in output['followup_message']
    assert set(json.loads(output['followup_message'].splitlines()[1])) == {
        'task_ref', 'workspace_path', 'session_ref'}
    metadata = output['followup_message'].split(DELIVERY_CONTEXT_MARKER, 1)[1].splitlines()[0]
    assert json.loads(metadata)['task_delivery'] == stopped['task_delivery']
    assert stopped['task_delivery']['delivery_intent'] == 'TASK_CLOSEOUT'
    assert ingress(repo, tmp_path, core, 'stop')[0] == {}
    assert bridge.current()['baseline'] == before and len(runtime.calls) == 1
