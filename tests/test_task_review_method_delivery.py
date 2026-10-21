"""The shipped method uses bounded guidance delivery, not a short fixture."""
import copy
import hashlib
import json

import pytest

from security_runtime import task_review_plan as plans
from security_runtime.guidance_catalog import get_runtime_guidance
from security_runtime.task_review_budget import METHOD_CONTENT_BYTES, METHOD_RESPONSE_BYTES
from security_runtime.task_security import TaskContextError, method
from task_review_helpers import review_all
from test_task_security import prepared, service  # noqa: F401


def packet_bytes(packet):
    return len(json.dumps(packet, ensure_ascii=False).encode('utf-8'))


def test_shipped_method_is_complete_charged_and_allows_review_completion(service):
    tasks, root, runtime = service
    ref, session, packet = prepared(service)
    before = tasks.load(root, ref)
    delivered = tasks.review_method(root, ref, session)
    after = tasks.load(root, ref)
    canonical = get_runtime_guidance('task-review')

    assert delivered == {'quick_skill': method()}
    assert delivered['quick_skill']['content'] == canonical['content']
    assert delivered['quick_skill']['sha256'] == canonical['sha256']
    assert packet_bytes(delivered) <= METHOD_RESPONSE_BYTES
    assert after['review_ledger']['limits']['response_bytes'] == 16_000
    for field in ('control_bytes', 'total_bytes'):
        assert after['review_ledger'][field] - before['review_ledger'][field] == packet_bytes(delivered)
    for field in ('source_bytes', 'navigation_bytes', 'reads', 'activity_lease'):
        assert after['review_ledger'][field] == before['review_ledger'][field]
    assert after['evidence'] == before['evidence']
    assert after['review_session'] == session

    review_all(tasks, root, ref, packet)
    receipt = tasks.submit(root, ref, session, [], 'REVIEWED', [])
    assert receipt['result_saved'] and receipt['status'] == 'COMPLETE'
    assert len(runtime.calls) == 1


def test_method_delivery_still_exhausts_cumulative_control_allowance(service):
    tasks, root, _ = service
    ref, session, _ = prepared(service)
    size = packet_bytes({'quick_skill': method()})
    initial = tasks.load(root, ref)['review_ledger']
    available = initial['category_limits']['control'] - initial['control_bytes']
    deliveries = available // size
    for _ in range(deliveries):
        tasks.review_method(root, ref, session)
    before = tasks.load(root, ref)
    with pytest.raises(TaskContextError) as caught:
        tasks.review_method(root, ref, session)
    assert caught.value.reason_code == 'TASK_CONTEXT_CONTROL_BUDGET'
    after = tasks.load(root, ref)
    assert after['review_ledger'] == before['review_ledger']
    assert after['evidence'] == before['evidence']


@pytest.mark.parametrize('category', ['source', 'navigation', 'control'])
def test_other_packets_keep_the_original_response_limit(service, category):
    tasks, root, _ = service
    ref, _, _ = prepared(service)
    record = tasks.load(root, ref)
    before = copy.deepcopy(record['review_ledger'])
    with pytest.raises(plans.ReviewPlanError) as caught:
        plans.charge_packet(record, b'x' * 16_001, category)
    assert caught.value.reason_code == 'TASK_CONTEXT_RESPONSE_BUDGET'
    assert record['review_ledger'] == before


@pytest.mark.parametrize('change', ['version', 'digest', 'content', 'extra', 'oversized'])
def test_method_envelope_cannot_carry_unbound_or_oversized_content(service, change):
    tasks, root, _ = service
    ref, _, _ = prepared(service)
    record = tasks.load(root, ref)
    packet = {'quick_skill': method()}
    if change == 'version':
        packet['quick_skill']['version'] += '-other'
    elif change == 'digest':
        packet['quick_skill']['sha256'] = '0' * 64
    elif change == 'content':
        packet['quick_skill']['content'] += '\nchanged'
    elif change == 'extra':
        packet['source'] = 'not bundled guidance'
    else:
        content = 'x' * (METHOD_CONTENT_BYTES + 1)
        packet['quick_skill'].update(content=content, sha256=hashlib.sha256(content.encode()).hexdigest())
        record['packet']['quick_skill']['sha256'] = packet['quick_skill']['sha256']
    before = copy.deepcopy(record['review_ledger'])
    with pytest.raises(ValueError, match='fixed task-bound'):
        plans.charge_packet(record, packet, 'method')
    assert record['review_ledger'] == before
