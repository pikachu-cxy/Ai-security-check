"""The optional collector retains bounded facts, never response objects."""
import json
import threading

import pytest

from security_runtime.context_cost import ContextCostStore
from security_runtime.context_cost_worker import ObservationWorker, bounded_record


def observation():
    return dict(tool='read_task_review_context', transport='mcp', succeeded=True,
        elapsed_ms=2, started_at=100, finished_at=101, mode='basic',
        connection_id='private-connection', workspace='C:/private/project',
        chat_owner=dict(host='codex', session='a' * 64),
        measurements=dict(text_bytes=10, structured_bytes=20, wire_bytes=30, measurement_limited=False),
        observations=dict(source_lines_delivered=3, duplicate_receipts=0,
            evidence_hashes=['b' * 64], flags={'scanner_run': False},
            inspection_limited=False, observation_status='COMPLETE'),
        correlation=dict(call_id='local-call-1', host='codex', session_binding='a' * 64,
            trigger_invocation_binding='c' * 64, turn_binding='d' * 64,
            links=[dict(kind='task', reference='PRIVATE_TASK_REFERENCE', relation='TASK_RECORD_READ')],
            limited=False, chat_conflict=False))


@pytest.fixture
def store(tmp_path, monkeypatch):
    for name in ('SECURITY_RUNTIME_CONTEXT_MONITOR', 'SECURITY_RUNTIME_CONTEXT_MODE',
                 'SECURITY_RUNTIME_CONTEXT_RUN'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MODE', 'basic')
    return ContextCostStore(tmp_path / 'metrics.sqlite3')


def test_store_persists_v3_facts_and_keyed_links_without_raw_identity(store):
    data = observation()
    assert store.record_observation(data)['status'] == 'RECORDED'
    event = store.snapshot()['events'][0]
    assert event['schema_version'] == 3 and event['mode'] == 'basic'
    assert event['call_id'] == 'local-call-1' and event['started_at'] == 100
    assert event['correlation']['session_hash'] == event['chat_hash']
    assert event['correlation']['links'][0]['relation'] == 'TASK_RECORD_READ'
    assert event['evidence_identity_scope'] == 'PRODUCER_PROCESS'
    assert store.summary()['wire_bytes'] == 30
    raw = store.path.read_bytes()
    for forbidden in (b'private-connection', b'private/project', b'PRIVATE_TASK_REFERENCE',
                      b'a' * 64, b'c' * 64, b'd' * 64):
        assert forbidden not in raw
    assert 'reference' not in event['correlation']['links'][0]


def test_metadata_rejects_unknown_body_and_unbounded_fields_before_storage(store):
    bad = observation()
    bad['result'] = {'text': 'PRIVATE_BODY'}
    assert store.record_observation(bad)['reason_code'] == 'CONTEXT_COST_METADATA_INVALID'
    assert not store.path.exists()
    bad = observation()
    bad['correlation']['links'][0]['reference'] = 'x' * 257
    assert bounded_record(bad) is None
    bad = observation()
    bad['observations']['evidence_hashes'] = [object()]
    assert bounded_record(bad) is None
    bad = observation()
    bad['measurements']['wire_bytes'] = float('nan')
    assert bounded_record(bad) is None


def test_conflicting_chat_never_leaks_second_session_association(store):
    data = observation()
    data['correlation']['chat_conflict'] = True
    assert store.record_observation(data)['status'] == 'RECORDED'
    event = store.snapshot()['events'][0]
    assert 'chat_hash' not in event
    assert 'session_hash' not in event['correlation']
    assert 'trigger_invocation_hash' not in event['correlation']
    assert 'turn_hash' not in event['correlation']


def test_off_is_checked_again_before_creating_storage(store, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MONITOR', '0')
    assert store.record_observation(observation())['status'] == 'DISABLED'
    assert not store.path.exists() and not store.key_path.exists()


def test_worker_defers_store_construction_and_copies_queued_metadata():
    written, factory_threads = [], []
    class Store:
        def monitoring(self):
            return dict(status='AVAILABLE', mode='basic', source='default')

        def record_observation(self, record):
            written.append(record)
            return {'status': 'RECORDED'}

    def factory():
        factory_threads.append(threading.get_ident())
        return Store()

    worker = ObservationWorker(factory)
    assert not factory_threads and worker.snapshot_settings()['source'] == 'startup'
    data = observation()
    assert worker.offer(data)
    data['correlation']['links'][0]['reference'] = 'CHANGED_AFTER_OFFER'
    data['observations']['flags']['scanner_run'] = True
    worker.start()
    try:
        assert worker.wait_ready(2) and worker.wait_idle(2)
        assert factory_threads == [worker._thread.ident]
        assert factory_threads[0] != threading.get_ident()
        assert written[0]['correlation']['links'][0]['reference'] == 'PRIVATE_TASK_REFERENCE'
        assert written[0]['observations']['flags']['scanner_run'] is False
        assert written[0]['collection']['settings_source'] == 'startup'
        assert worker.stats()['persisted'] == 1
    finally:
        worker.close()


def test_queue_loss_and_write_failure_have_sequence_and_counters():
    entered, release = threading.Event(), threading.Event()
    written = []
    class Store:
        def monitoring(self):
            return dict(status='AVAILABLE', mode='basic', source='default')

        def record_observation(self, record):
            written.append(record)
            if len(written) == 1:
                entered.set()
                assert release.wait(2)
                raise OSError('PRIVATE_STORAGE_FAILURE')
            return {'status': 'RECORDED'}

    worker = ObservationWorker(Store, capacity=1).start()
    try:
        assert worker.wait_ready(2)
        assert worker.offer(observation()) and entered.wait(2)
        assert worker.offer(observation())
        assert not worker.offer(observation())
        release.set()
        assert worker.wait_idle(2)
        assert worker.offer(observation())
        assert worker.wait_idle(2)
        assert [record['collection']['producer_sequence'] for record in written] == [1, 2, 4]
        assert written[-1]['collection']['dropped_before'] == 1
        assert written[-1]['collection']['write_errors_before'] == 1
        stats = worker.stats()
        assert stats['offered'] == 4 and stats['enqueued'] == 3 and stats['dropped'] == 1
        assert stats['write_errors'] == 1 and stats['persisted'] == 2
        assert 'PRIVATE_STORAGE_FAILURE' not in json.dumps(stats)
    finally:
        release.set()
        worker.close()


def test_worker_settings_failure_and_closed_offer_are_explicit():
    class Store:
        def monitoring(self):
            raise OSError('private')

    worker = ObservationWorker(Store).start()
    try:
        assert worker.wait_ready(2)
        assert worker.snapshot_settings() == dict(status='UNAVAILABLE', mode='off', source='unavailable')
        assert worker.offer(observation()) and worker.wait_idle(2)
        assert worker.stats()['write_errors'] == 1
    finally:
        worker.close()
    assert not worker.offer(observation())


def test_global_worker_not_created_when_environment_disables(monkeypatch):
    from security_runtime import context_cost_worker as module
    monkeypatch.setattr(module, '_worker', None)
    for mode in ('off', 'invalid'):
        monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MODE', mode)
        assert module.get_worker() is None and module._worker is None


def maximum_observation():
    data = observation()
    data.update(run_label='r' * 64, workspace='C:/' + 'p' * 4093, connection_id='c' * 128,
        collection=dict(producer_id='p' * 64, process_id=2 ** 63 - 1,
            producer_sequence=2 ** 63 - 1, dropped_before=2 ** 63 - 1,
            write_errors_before=2 ** 63 - 1, settings_source='environment'))
    data['correlation']['call_id'] = 'c' * 64
    data['correlation']['links'] = [dict(kind='host_event', reference=str(index) + 'x' * 253,
        relation='HOST_EVENT_UNCONFIRMED') for index in range(64)]
    data['observations']['evidence_hashes'] = [f'{index:064x}' for index in range(64)]
    return data


def test_maximum_link_and_evidence_counts_fit_one_readable_record(store):
    assert store.record_observation(maximum_observation())['status'] == 'RECORDED'
    snapshot = store.snapshot()
    assert snapshot['invalid'] == 0 and len(snapshot['events']) == 1
    event = snapshot['events'][0]
    assert len(event['correlation']['links']) == 64
    assert len(event['evidence_hashes']) == 64
    assert len(json.dumps(event, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()) <= 16_384


def test_smaller_record_budget_preserves_call_and_marks_all_omitted_details(store, monkeypatch):
    from security_runtime import context_cost
    monkeypatch.setattr(context_cost, 'MAX_OBSERVATION_RECORD_BYTES', 3000)
    assert store.record_observation(maximum_observation())['status'] == 'RECORDED'
    event = store.snapshot()['events'][0]
    assert event['tool'] == 'read_task_review_context' and event['call_id'] == 'c' * 64
    assert event['metadata_limited'] and event['observation_status'] == 'PARTIAL'
    assert len(event['evidence_hashes']) + event['evidence_hashes_omitted'] == 64
    assert event['correlation']['limited']
    assert len(event['correlation']['links']) + event['correlation']['links_omitted'] == 64
    assert len(json.dumps(event, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()) <= 3000
