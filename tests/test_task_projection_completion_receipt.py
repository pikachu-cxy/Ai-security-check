"""Planned-review receipts describe the projection committed by this submission."""
import copy
import json
import sqlite3
from contextlib import nullcontext
from unittest.mock import patch

import pytest

from security_runtime.task_risk_ledger import TaskRiskLedger
from security_runtime.task_security_state import TaskSecurityStore
from test_task_security import service  # noqa: F401


def planned(sample, exhausted):
    tasks, root, _ = sample
    ref = tasks.begin(root, 'projection-terminal')['task_ref']
    (root / 'routes.py').write_text('def route(user):\n    return access.check(user)\n')
    prepared = tasks.prepare(root, ref, protocol_version=3)
    if exhausted:
        record = tasks.load(root, ref)
        ledger = record['review_ledger']
        ledger['source_bytes'] = ledger['category_limits']['source']
        tasks.store(root).save(record)
    return ref, prepared['review_session']


@pytest.mark.parametrize('exhausted', [False, True])
@pytest.mark.parametrize('failure', ['none', 'ledger', 'ack'])
def test_returned_receipt_has_actual_projection_state_and_preserves_saved_result(
        service, exhausted, failure):
    tasks, root, runtime = service
    ref, session = planned(service, exhausted)
    before = copy.deepcopy(tasks.load(root, ref))
    save = TaskSecurityStore.save

    def fail_ack(store, record, **kwargs):
        if (record['task_ref'] == ref and record['phase'] == 'COMPLETE'
                and record.get('ledger_projection', {}).get('state') == 'APPLIED'):
            raise sqlite3.OperationalError('Fixture projection acknowledgement failed')
        return save(store, record, **kwargs)

    fault = (patch.object(TaskRiskLedger, 'register', side_effect=OSError('Fixture ledger failed'))
             if failure == 'ledger' else patch.object(TaskSecurityStore, 'save', fail_ack)
             if failure == 'ack' else nullcontext())
    detail = 'Specific private context gap remains in the saved result.'
    with fault:
        result = tasks.submit(root, ref, session, [], 'PARTIAL', [detail])

    expected = dict(state='APPLIED', pending=False) if failure == 'none' else dict(state='PENDING', pending=True)
    assert result['status'] == 'COMPLETE'
    assert result['risk_ledger_sync'] == expected
    saved = tasks.load(root, ref)
    assert saved['ledger_projection']['state'] == expected['state']
    assert saved['phase'] == 'COMPLETE' and detail in saved['review']['limitations']
    assert saved['baseline'] == before['baseline'] and len(runtime.calls) == 1
    response_bytes = len(json.dumps(result, ensure_ascii=False).encode('utf-8'))
    delivery = saved['completion_delivery']
    assert result['result_saved'] is True and result['result_details_required'] is True
    assert response_bytes <= 1_600
    assert response_bytes <= delivery['response_bytes'] <= 1_600
    assert delivery['response_bytes_bound'] == 'PENDING_OR_APPLIED_UPPER_BOUND'
    assert delivery['response_bytes'] - response_bytes <= 1
    assert saved['review_ledger'] == before['review_ledger']
    assert detail not in json.dumps(result)
    recovered = tasks.submit(root, ref, session, [], 'PARTIAL', ['Retry must not replace saved review'])
    assert recovered['risk_ledger_sync'] == dict(state='APPLIED', pending=False)
    assert tasks.load(root, ref)['review'] == saved['review']
    assert len(runtime.calls) == 1


@pytest.mark.parametrize('exhausted', [False, True])
def test_source_commit_failure_does_not_return_a_saved_or_projection_receipt(service, exhausted):
    tasks, root, _ = service
    ref, session = planned(service, exhausted)
    before = tasks.load(root, ref)
    save = TaskSecurityStore.save

    def fail_source(store, record, **kwargs):
        if record['task_ref'] == ref and record['phase'] == 'COMPLETE':
            raise OSError('Fixture final source commit failed')
        return save(store, record, **kwargs)

    with patch.object(TaskSecurityStore, 'save', fail_source):
        with pytest.raises(OSError, match='final source commit failed'):
            tasks.submit(root, ref, session, [], 'PARTIAL', ['Unread context'])
    assert tasks.load(root, ref) == before
