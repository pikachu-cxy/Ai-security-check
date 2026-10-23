"""A spent source-delivery ledger must not prevent an honest final save."""
import copy
import json

import pytest

from test_task_security import service  # noqa: F401
from test_task_security import candidate


@pytest.mark.parametrize('exhausted', ['total', 'source', 'navigation', 'control', 'response'])
def test_exhausted_delivery_budget_still_saves_partial_result_and_full_gaps(service, exhausted):
    tasks, root, runtime = service
    ref = tasks.begin(root, 'terminal-budget')['task_ref']
    (root/'routes.py').write_text('def route(user):\n    return policy.check(user)\n')
    prepared = tasks.prepare(root, ref, protocol_version=3)
    record = tasks.load(root, ref)
    ledger = record['review_ledger']
    if exhausted == 'total':
        ledger['total_bytes'] = ledger['limits']['total_bytes']
    elif exhausted in {'source', 'navigation', 'control'}:
        ledger[exhausted+'_bytes'] = ledger['category_limits'][exhausted]
        ledger['total_bytes'] = sum(ledger[name+'_bytes'] for name in ('source', 'navigation', 'control'))
    else:
        ledger['limits']['response_bytes'] = 1
    record['context_bytes'] = ledger['total_bytes']
    tasks.store(root).save(record)
    before = copy.deepcopy(record)
    detail = 'Specific unresolved caller context must remain in saved details.'

    result = tasks.submit(root, ref, prepared['review_session'], [], 'PARTIAL', [detail])

    assert result['status'] == 'COMPLETE'
    assert result['review_progress']['coverage'] == 'PARTIAL'
    assert 'host_review' not in result
    assert result['result_saved'] is True and result['result_details_required'] is True
    assert result['next_action'] == dict(tool='get_task_security_review', task_ref=ref,
                                       completion_revision=1, finding_offset=0, finding_limit=1)
    assert not result['repair_authorized'] and not result['scanner_run']
    assert len(json.dumps(result, ensure_ascii=False).encode()) <= 1600
    assert detail not in json.dumps(result)
    assert 'routes.py' not in json.dumps(result)
    saved = tasks.load(root, ref)
    assert saved['phase'] == 'COMPLETE'
    assert detail in saved['review']['limitations']
    assert saved['review_completion']['gaps']
    assert saved['review_ledger'] == before['review_ledger']
    assert saved['review_deadline'] == before['review_deadline']
    assert saved['evidence'] == before['evidence']
    assert saved['completion_delivery']['response_bytes'] == len(json.dumps(result, ensure_ascii=False).encode())
    assert saved['completion_delivery']['response_limit'] == 1600
    assert saved['completion_delivery']['source_evidence_delivered'] is False
    history = tasks.get(root, ref, finding_limit=1)
    assert history['host_review']['coverage'] == 'PARTIAL'
    assert tasks.load(root, ref)['review_ledger'] == before['review_ledger']
    retried = tasks.submit(root, ref, prepared['review_session'], [], 'PARTIAL', ['Retry only'])
    assert retried['delivery_read_only'] is True
    assert tasks.load(root, ref)['review'] == saved['review']
    assert len(runtime.calls) == 1


def test_budget_receipt_never_delivers_host_finding_or_gap_prose_but_saves_both(service):
    tasks, root, runtime = service
    ref = tasks.begin(root, 'terminal-private-prose')['task_ref']
    (root/'routes.py').write_text('def private_route_marker(user):\n    return policy.check(user)\n')
    prepared = tasks.prepare(root, ref, protocol_version=3)
    evidence = tasks.read(root, ref, prepared['review_session'], 'routes.py', 1, 2)
    finding = candidate(evidence['evidence_id'], evidence['evidence_id'])
    finding['title'] = 'Host finding title must only appear in saved details'
    finding['impact'] = 'Host impact must not be delivered outside the evidence ledger'
    detail = 'Named limitation must only appear in saved details'
    record = tasks.load(root, ref)
    record['review_ledger']['total_bytes'] = record['review_ledger']['limits']['total_bytes']
    record['context_bytes'] = record['review_ledger']['total_bytes']
    tasks.store(root).save(record)
    before = copy.deepcopy(record['review_ledger'])

    result = tasks.submit(root, ref, prepared['review_session'], [finding], 'PARTIAL', [detail])

    assert result['review_progress']['coverage'] == 'PARTIAL'
    assert 'host_review' not in result
    text = json.dumps(result)
    for private in (finding['title'], finding['impact'], detail, 'private_route_marker', 'routes.py'):
        assert private not in text
    assert set(result['review_progress']) == {'unit_count', 'reviewed_unit_count', 'coverage'}
    saved = tasks.load(root, ref)
    assert saved['review']['findings'][0]['title'] == finding['title']
    assert saved['review']['findings'][0]['impact'] == finding['impact']
    assert detail in saved['review']['limitations'] and saved['review_completion']['gaps']
    assert saved['review_ledger'] == before
    history = tasks.get(root, ref, finding_limit=1)
    assert history['host_review']['coverage'] == 'PARTIAL'
    assert history['host_review']['finding_count'] == 1
    assert history['findings'][0]['detail']['title'] == finding['title']
    assert len(runtime.calls) == 1


@pytest.mark.parametrize('invalid', ['session', 'source', 'idle_lease'])
def test_terminal_receipt_does_not_swallow_non_budget_validation_errors(service, monkeypatch, invalid):
    tasks, root, runtime = service
    ref = tasks.begin(root, 'terminal-validation')['task_ref']
    (root/'routes.py').write_text('def route(user):\n    return policy.check(user)\n')
    prepared = tasks.prepare(root, ref, protocol_version=3)
    session = prepared['review_session']
    before = tasks.load(root, ref)
    if invalid == 'session':
        session = 'tr1-wrong-session'
    elif invalid == 'source':
        (root/'routes.py').write_text('def route(user):\n    return policy.changed(user)\n')
    else:
        monkeypatch.setattr(tasks, 'now', lambda: before['review_deadline'] + 1)
    with pytest.raises(ValueError, match='session|stale|lease expired'):
        tasks.submit(root, ref, session, [], 'PARTIAL', ['Unread source'])
    after = tasks.load(root, ref)
    assert after['phase'] == 'REVIEWING' and 'completion_delivery' not in after
    assert after['review_ledger'] == before['review_ledger'] and after['evidence'] == before['evidence']
    assert len(runtime.calls) == 1


def test_terminal_storage_failure_never_returns_a_saved_receipt(service, monkeypatch):
    tasks, root, _ = service
    ref = tasks.begin(root, 'terminal-storage-failure')['task_ref']
    (root/'routes.py').write_text('def route(user):\n    return policy.check(user)\n')
    prepared = tasks.prepare(root, ref, protocol_version=3)
    record = tasks.load(root, ref)
    record['review_ledger']['total_bytes'] = record['review_ledger']['limits']['total_bytes']
    tasks.store(root).save(record)
    store_type = type(tasks.store(root))
    original_save = store_type.save

    def failed_save(store, value):
        if value['phase'] == 'COMPLETE':
            raise OSError('Fixture final storage failure')
        return original_save(store, value)

    monkeypatch.setattr(store_type, 'save', failed_save)
    with pytest.raises(OSError, match='final storage failure'):
        tasks.submit(root, ref, prepared['review_session'], [], 'PARTIAL', ['Unread source'])
    assert tasks.load(root, ref)['phase'] == 'REVIEWING'
