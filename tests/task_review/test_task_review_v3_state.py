"""One signed authoritative v3 ledger, with legacy persistence unchanged."""
import copy

from security_runtime.closeout_state import encode
from security_runtime.task_review.plan import build_plan, finalize_plan
from security_runtime.tasks.security_state import persistent_record
from test_task_security import service  # noqa: F401


def test_v3_persistence_removes_only_the_duplicate_ledger_without_mutating_caller():
    ledger = dict(source_bytes=12, allocations={'source': [[1, 80]]})
    record = dict(review_protocol=3, review_ledger=ledger,
        review_plan=dict(contract='task-review-plan-v3', budget=ledger, units=[]))
    before = copy.deepcopy(record)
    saved = persistent_record(record)
    assert record == before and 'budget' in record['review_plan']
    assert saved['review_ledger'] is ledger
    assert 'budget' not in saved['review_plan']
    assert saved['review_plan']['units'] is record['review_plan']['units']
    assert len(encode(saved)) < len(encode(record))


def test_legacy_persistence_keeps_its_original_shape():
    for protocol in (1, 2):
        record = dict(review_protocol=protocol, review_ledger={'reads': 2},
            review_plan=dict(contract='task-review-plan-v2', budget={'reads': 2}))
        assert persistent_record(record) is record


def test_signed_v3_record_reloads_and_rebinds_the_original_ledger(service):
    service, root, _ = service
    ref = service.begin(root, 'signed-ledger-only')['task_ref']
    record = service.load(root, ref)
    record.update(end=copy.deepcopy(record['baseline']), changes=[], evidence={}, context_bytes=0)
    build_plan(record, now=service.now(), protocol_version=3)
    record['review_protocol'] = 3
    ledger = copy.deepcopy(record['review_ledger'])
    saved = service.store(root).save(record)
    assert 'budget' not in saved['review_plan']
    assert 'budget' in record['review_plan']
    loaded = service.load(root, ref)
    assert loaded['review_ledger'] == ledger
    assert 'budget' not in loaded['review_plan']
    assert finalize_plan(loaded, now=service.now())['coverage'] == 'REVIEWED'
    assert loaded['review_plan']['budget'] is loaded['review_ledger']
