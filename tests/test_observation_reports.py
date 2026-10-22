import json

from security_runtime.context_report import association_data, report_data
from security_runtime.context_cost import ContextCostStore
from security_runtime.monitoring.service import MonitorService


def test_report_aliases_preserve_relations_without_exporting_private_identities():
    events = [dict(tool='finish_security_task', call_id='local-call',
        correlation=dict(links=[dict(kind='task', reference_hash='private-keyed-task',
            relation='TASK_RECORD_READ')], trigger_invocation_hash='private-trigger',
            turn_hash='private-turn')), dict(tool='get_task_security_review', call_id='local-read',
        correlation=dict(links=[dict(kind='task', reference_hash='private-keyed-task',
            relation='TASK_RESULT_RETURNED')]))]
    value = association_data(events)
    assert value['linked_calls'] == 2
    assert value['calls'][0]['links'][0]['subject'] == value['calls'][1]['links'][0]['subject']
    assert value['calls'][0]['host_trigger']['relation'] == 'TRIGGERED_BY_HOST_TOOL'
    assert 'private-' not in json.dumps(value)
    assert value['model_usage_link'] == 'UNAVAILABLE'


def test_legacy_records_are_not_linked_by_matching_tool_or_timestamp():
    value = association_data([dict(tool='scan_files', started_at=123), dict(tool='scan_files', started_at=123)])
    assert value['linked_calls'] == 0 and value['legacy_calls'] == 2
    assert all(not call['links'] for call in value['calls'])


def test_incomplete_measurements_are_unknown_in_report_details(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_CONTEXT_MONITOR', raising=False)
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MODE', 'basic')
    store = ContextCostStore(tmp_path / 'cost.db')
    status = store.record_observation(dict(tool='scan_project', succeeded=True,
        measurements=dict(wire_bytes=0, text_bytes=0, structured_bytes=0, measurement_limited=True),
        observations=dict(inspection_limited=True, observation_status='PARTIAL'),
        correlation=dict(call_id='local-call', links=[dict(kind='scan', reference='private-scan',
            relation='SCAN_PERSISTED')], limited=False, chat_conflict=False)))
    assert status['status'] == 'RECORDED'
    report = report_data(store)
    assert report['events'][0]['wire_bytes'] is None
    assert report['associations']['linked_calls'] == 1
    live = MonitorService(store).snapshot()
    assert live['events'][0]['wire_bytes'] is None
    assert live['response_measurement_gaps'] == 1
    assert live['associations']['calls'][0]['links'][0]['relation'] == 'SCAN_PERSISTED'
    assert 'private-scan' not in json.dumps(live)


def test_drop_watermarks_are_per_producer_and_do_not_invent_tail_completeness():
    events = [dict(tool='get_runtime_info', collection=dict(producer_id='one', dropped_before=n,
              write_errors_before=1)) for n in (2, 5, 3)]
    value = association_data(events, limit=1)
    assert value['producer_drops_reported'] == 5
    assert value['producer_write_errors_reported'] == 1
    assert value['details_omitted'] == 2
    assert 'TAIL_UNKNOWN' in value['coverage']
