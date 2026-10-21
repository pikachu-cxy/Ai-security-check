"""Manual windows must not present records without time boundaries as zero."""
import pytest

from security_runtime.context_cost import ContextCostStore
from security_runtime.monitoring.service import MonitorService


@pytest.fixture
def setup(tmp_path, monkeypatch):
    for name in ('SECURITY_RUNTIME_CONTEXT_MODE', 'SECURITY_RUNTIME_CONTEXT_MONITOR',
                 'SECURITY_RUNTIME_CONTEXT_RUN'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr('security_runtime.monitoring.service.time.time', lambda: 1000)
    store = ContextCostStore(tmp_path / 'metrics.sqlite3')
    service = MonitorService(store)
    service.task('start')
    return store, service


def test_basic_window_totals_are_unknown_while_overview_keeps_actual_counts(setup):
    store, service = setup
    store.record_call('get_runtime_info', {}, elapsed_ms=15)
    report = service.snapshot('task')
    assert report['status'] == 'PARTIAL'
    assert report['window_untimed_retained_calls'] == 1
    assert report['tools_known'] is False
    for field in ('calls', 'elapsed_ms', 'wire_bytes', 'errors'):
        assert report[field] is None
    assert service.snapshot('all')['calls'] == 1
    assert service.snapshot('all')['status'] == 'AVAILABLE'
    assert store.monitoring()['mode'] == 'basic'


def test_mixed_window_retains_timed_details_without_claiming_complete_totals(setup):
    store, service = setup
    store.record_call('get_runtime_info', {}, elapsed_ms=15)
    store.set_monitoring('debug')
    store.record_call('get_security_summary', {}, elapsed_ms=5, started_at=1000, finished_at=1000)
    report = service.snapshot('task')
    assert report['calls'] is None and report['status'] == 'PARTIAL'
    assert [event['tool'] for event in report['events']] == ['get_security_summary']
    assert report['groups'][0]['calls'] == 1
    assert report['timing']['timed_calls'] == 1
    assert report['window_untimed_retained_calls'] == 1


def test_debug_window_can_still_report_zero_and_exclude_cross_boundary_calls(setup):
    store, service = setup
    store.set_monitoring('debug')
    store.record_call('get_runtime_info', {}, started_at=999, finished_at=1000)
    report = service.snapshot('task')
    assert report['status'] == 'AVAILABLE' and report['tools_known']
    assert report['calls'] == 0 and report['window_untimed_retained_calls'] == 0
    store.record_call('get_security_summary', {}, elapsed_ms=5, started_at=1000, finished_at=1000)
    assert service.snapshot('task')['calls'] == 1


def test_other_project_untimed_records_do_not_hide_selected_project_window(setup, tmp_path):
    store, _ = setup
    project = tmp_path / 'selected'
    service = MonitorService(store, project=project)
    service.task('start')
    store.record_call('get_runtime_info', {}, workspace=tmp_path / 'other')
    store.set_monitoring('debug')
    store.record_call('get_security_summary', {}, workspace=project, started_at=1000, finished_at=1000)
    report = service.snapshot('task')
    assert report['calls'] == 1 and report['tools_known']
    assert report['window_untimed_retained_calls'] == 0
