"""Original source values survive results; runtime credentials stay protected."""
from security_runtime.diagnostics import evidence_text, sanitize
from security_runtime.tasks.security import _clean, finding_view
from security_runtime.task_review.results import bounded_history_result
from security_runtime.risk_disposition import _safe_reason
from test_task_review_results import record


SOURCE = 'password="synthetic-raw-value-999"; url="https://example.invalid/?token=synthetic-token-999"'


def test_original_values_survive_review_submission_and_result_presentation():
    state = record(1, 1)
    for origin in ('static', 'review'):
        finding = state[origin]['findings'][0]
        finding['impact'] = _clean(SOURCE)
        finding['counterevidence'] = [_clean(SOURCE)]
        assert finding_view(finding)['impact'] == SOURCE
    packet = bounded_history_result(state, 0, 3)
    for row in packet['findings']:
        assert row['detail']['impact'] == SOURCE
        assert row['detail']['counterevidence'] == [SOURCE]
    assert _safe_reason(SOURCE) == SOURCE


def test_host_limitations_and_incomplete_reason_preserve_original_values():
    state = record(0, 0)
    state['review']['limitations'] = [SOURCE]
    state['skip_reason'] = SOURCE
    packet = bounded_history_result(state, 0, 3)
    assert packet['host_review']['limitations']['items'] == [SOURCE]
    assert packet['incomplete_reason']['items'] == [SOURCE]


def test_display_safety_is_separate_from_runtime_diagnostic_redaction():
    decorated = '\x1b[31m'+SOURCE+'\x1b[0m\x00'
    assert evidence_text(decorated, None) == SOURCE
    assert 'synthetic-raw-value-999' not in sanitize(decorated)
    assert 'synthetic-token-999' not in sanitize(decorated)
    assert evidence_text(SOURCE, 12) == SOURCE[:12]
