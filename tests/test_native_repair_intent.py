"""A selected native repair cannot replace its baseline with an ordinary begin."""
import copy
import hashlib
import sqlite3

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.native_repair_intent import NativeRepairIntents
from security_runtime.repair_impact_models import RepairImpactError
from security_runtime.task_security import TaskSecurityService


OWNER = dict(host='codex', session='a' * 64)
SOURCE = dict(kind='HOST_TASK_RISK', task_ref='ts1-' + '1' * 32,
              finding_id='tc1-fixture-risk', origin_review_revision=1)
ASSESSMENT = 'ria1-' + '2' * 32


class NoScanRuntime:
    def scan(self, *args, **kwargs):
        raise AssertionError('Intent and baseline preparation must never scan')


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'app.py').write_text('def read_document(user, document):\n    return document.body\n', encoding='utf8')
    hooks = HookStateStore(tmp_path / 'private')
    clock = lambda: 1000.0
    tasks = TaskSecurityService(NoScanRuntime(), hooks, owner=OWNER, now=clock)
    intents = NativeRepairIntents(hooks, root, OWNER, now=clock)
    preparation = dict(assessment_ref=ASSESSMENT, revision=1, source=copy.deepcopy(SOURCE),
        source_binding=dict(SOURCE, origin_snapshot_id='origin-1', finding_digest='b' * 64),
        proposal_revision='c' * 64, proposal_summary='Check existing membership policy',
        security_goal='Reject unrelated readers', preserve=['Keep shared-member access'],
        source_hashes={'app.py': hashlib.sha256((root / 'app.py').read_bytes()).hexdigest()})
    return tasks, intents, root, preparation


def ready(sample):
    _, intents, _, preparation = sample
    intents.request(SOURCE, ASSESSMENT)
    return intents.ready(preparation)


def test_absent_intent_reads_do_not_create_storage_or_block_development(sample):
    tasks, intents, root, _ = sample
    assert intents.get() is None and intents.guard() is None
    assert intents.cancel() is None
    assert not intents.store.path.exists() and not intents.store.key_path.exists()
    assert tasks.begin(root, 'ordinary-development')['status'] == 'ACTIVE'
    assert intents.get() is None


def test_impact_query_draft_does_not_imply_selected_repair_intent(sample):
    from security_runtime.repair_impact import RepairImpactService
    tasks, intents, root, _ = sample
    resolved = dict(binding=dict(SOURCE, origin_snapshot_id='origin-1'),
        source_paths=['app.py'], member_ids=[SOURCE['finding_id']],
        required_windows=[dict(file_path='app.py', start_line=1, end_line=2)])
    impacts = RepairImpactService(root, intents.store.directory, OWNER,
        lambda source: copy.deepcopy(resolved), now=tasks.now)
    draft = impacts.prepare(SOURCE, dict(summary='Consider the existing member check',
        security_goal='Preserve member access', preserve=['Shared members'],
        changes=[dict(file_path='app.py', start_line=1, end_line=2, reason='Selected impact query')]))
    assert draft['gate'] == 'CRITICAL_CONTEXT_MISSING'
    assert intents.get() is None
    assert tasks.begin(root, 'ordinary-development')['status'] == 'ACTIVE'


def test_waiting_blocks_both_existing_and_new_keys_before_capture(sample, monkeypatch):
    tasks, intents, root, _ = sample
    old = tasks.begin(root, 'existing-development')['task_ref']
    intents.request(SOURCE, ASSESSMENT)
    def no_capture(*args, **kwargs):
        raise AssertionError('A denied ordinary begin must not capture a replacement baseline')
    monkeypatch.setattr('security_runtime.task_security.capture', no_capture)
    for key in ('existing-development', 'new-development'):
        result = tasks.begin(root, key)
        assert result['status'] == 'NATIVE_REPAIR_PREPARATION_REQUIRED'
        assert result['scanner_run'] is result['source_modified'] is False
        assert 'task_ref' not in result
    assert [r['task_ref'] for r in tasks.store(root).records()] == [old]


def test_intent_survives_reconnection_but_other_owner_is_independent(sample):
    tasks, intents, root, _ = sample
    intents.request(SOURCE, ASSESSMENT)
    reconnected = NativeRepairIntents(tasks.hooks, root, OWNER, now=tasks.now)
    assert reconnected.get()['status'] == 'WAITING'
    assert reconnected.guard()['source'] == SOURCE
    other = TaskSecurityService(NoScanRuntime(), tasks.hooks,
        owner=dict(host='codex', session='d' * 64), now=tasks.now)
    assert other.begin(root, 'other-conversation')['status'] == 'ACTIVE'


def test_only_exact_ready_preparation_can_create_native_baseline(sample):
    tasks, intents, root, preparation = sample
    ready(sample)
    wrong = dict(preparation, proposal_revision='d' * 64)
    assert tasks.begin(root, 'forged', _native_preparation=wrong)['status'] == 'NATIVE_REPAIR_PREPARATION_REQUIRED'
    assert tasks.store(root).records() == []
    task = tasks.begin(root, 'native-repair', _native_preparation=preparation)
    record = tasks.load(root, task['task_ref'])
    assert record['native_repair'] == preparation
    assert intents.get()['repair_task_ref'] == task['task_ref']
    assert 'source_hashes' not in task['native_repair']
    assert task['native_repair']['repair_authorized'] is False


def test_bound_repair_reuses_original_baseline_after_own_edits(sample, monkeypatch):
    tasks, intents, root, preparation = sample
    ready(sample)
    first = tasks.begin(root, 'native-repair', _native_preparation=preparation)
    baseline = copy.deepcopy(tasks.load(root, first['task_ref'])['baseline'])
    (root / 'app.py').write_text('def read_document(user, document):\n    assert user in document.members\n    return document.body\n')
    def no_capture(*args, **kwargs):
        raise AssertionError('A resumed repair must retain its pre-repair bytes')
    monkeypatch.setattr('security_runtime.task_security.capture', no_capture)
    assert intents.request(SOURCE, ASSESSMENT)['status'] == 'BOUND'
    second = tasks.begin(root, 'different-key', _native_preparation=preparation)
    assert second['task_ref'] == first['task_ref']
    assert tasks.load(root, first['task_ref'])['baseline'] == baseline
    denied = tasks.begin(root, 'ordinary-key')
    assert denied['status'] == 'NATIVE_REPAIR_PREPARATION_REQUIRED'
    assert denied['repair_task_ref'] == first['task_ref']


def test_preparation_version_mismatch_never_publishes_a_task(sample):
    tasks, intents, root, preparation = sample
    ready(sample)
    (root / 'app.py').write_text('changed_after_impact = True\n')
    with pytest.raises(ValueError, match='NATIVE_REPAIR_BASELINE_MISMATCH'):
        tasks.begin(root, 'native-repair', _native_preparation=preparation)
    assert tasks.store(root).records() == []
    assert intents.get()['status'] == 'READY'


def test_saved_baseline_recovers_after_interrupted_intent_bind(sample, monkeypatch):
    tasks, intents, root, preparation = sample
    ready(sample)
    real_bind = NativeRepairIntents.bind
    def interrupted(*args, **kwargs):
        raise OSError('fixture interruption after baseline publication')
    monkeypatch.setattr(NativeRepairIntents, 'bind', interrupted)
    with pytest.raises(OSError):
        tasks.begin(root, 'native-repair', _native_preparation=preparation)
    original = tasks.store(root).records()[0]
    assert intents.get()['status'] == 'READY'
    (root / 'app.py').write_text('actual_repair_started = True\n')
    monkeypatch.setattr(NativeRepairIntents, 'bind', real_bind)
    result = tasks.begin(root, 'retry-with-new-key', _native_preparation=preparation)
    assert result['task_ref'] == original['task_ref']
    assert tasks.load(root, result['task_ref'])['baseline'] == original['baseline']


def test_explicit_cancel_unlocks_development_without_creating_risk_decision(sample):
    tasks, intents, root, _ = sample
    intents.request(SOURCE, ASSESSMENT)
    decisions = tasks.hooks.workspace_directory(root) / 'risk-dispositions.db'
    retained_decision = b'fixture-existing-user-risk-decision'
    decisions.write_bytes(retained_decision)
    with pytest.raises(RepairImpactError, match='NATIVE_REPAIR_USER_REQUEST_REQUIRED'):
        intents.cancel(user_requested=False)
    assert intents.cancel(user_requested=True)['status'] == 'CANCELLED'
    assert tasks.begin(root, 'unrelated-work')['status'] == 'ACTIVE'
    assert not (tasks.hooks.workspace_directory(root) / 'task-risk-ledger.json').exists()
    assert decisions.read_bytes() == retained_decision


def test_cancelled_bound_repair_cannot_hide_ongoing_edits_with_new_assessment(sample):
    tasks, intents, root, preparation = sample
    ready(sample)
    original = tasks.begin(root, 'native-repair', _native_preparation=preparation)
    (root / 'app.py').write_text('partially_repaired = True\n')
    intents.cancel(user_requested=True)
    with pytest.raises(RepairImpactError, match='NATIVE_REPAIR_ALREADY_BOUND'):
        intents.request(SOURCE, 'ria1-' + '3' * 32)
    assert intents.request(SOURCE, ASSESSMENT)['status'] == 'BOUND'
    resumed = tasks.begin(root, 'resume', _native_preparation=preparation)
    assert resumed['task_ref'] == original['task_ref']


def test_bound_request_cannot_switch_risk_or_assessment(sample):
    tasks, intents, root, preparation = sample
    ready(sample)
    tasks.begin(root, 'native-repair', _native_preparation=preparation)
    for source, assessment in ((dict(SOURCE, finding_id='tc1-other'), ASSESSMENT),
                               (SOURCE, 'ria1-' + '3' * 32)):
        with pytest.raises(RepairImpactError, match='NATIVE_REPAIR_ALREADY_BOUND'):
            intents.request(source, assessment)


@pytest.mark.parametrize('phase', ['COMPLETE', 'NO_CHANGES'])
def test_completed_repair_allows_new_work_and_new_risk_without_reusing_old_preparation(sample, phase):
    tasks, intents, root, preparation = sample
    ready(sample)
    original = tasks.begin(root, 'native-repair', _native_preparation=preparation)
    record = tasks.load(root, original['task_ref'])
    baseline = copy.deepcopy(record['baseline'])
    # A signed terminal task is a state fixture, not a claim of scanner proof.
    record['phase'] = phase
    tasks.store(root).save(record)
    (root / 'app.py').write_text('later_work = True\n')
    historical = tasks.begin(root, 'old-preparation-new-key', _native_preparation=preparation)
    assert historical['task_ref'] == original['task_ref'] and historical['status'] == phase
    assert len(tasks.store(root).records()) == 1
    ordinary = tasks.begin(root, 'new-ordinary-development')
    assert ordinary['status'] == 'ACTIVE' and ordinary['task_ref'] != original['task_ref']
    assert 'native_repair' not in ordinary
    assert intents.get()['status'] == 'BOUND'
    next_source = dict(SOURCE, finding_id='tc1-next-risk')
    pending = intents.request(next_source, 'ria1-' + '3' * 32)
    assert pending['status'] == 'WAITING' and pending['repair_task_ref'] is None
    assert tasks.load(root, original['task_ref'])['baseline'] == baseline
    denied = tasks.begin(root, 'old-preparation-again', _native_preparation=preparation)
    assert denied['status'] == 'NATIVE_REPAIR_PREPARATION_REQUIRED'


@pytest.mark.parametrize('phase', ['ACTIVE', 'READY', 'REVIEWING', 'INCOMPLETE'])
def test_unfinished_bound_task_does_not_unlock_new_work_or_new_risk(sample, phase):
    tasks, intents, root, preparation = sample
    ready(sample)
    original = tasks.begin(root, 'native-repair', _native_preparation=preparation)
    record = tasks.load(root, original['task_ref'])
    record['phase'] = phase
    tasks.store(root).save(record)
    blocked = tasks.begin(root, 'ordinary-bypass')
    assert blocked['status'] == 'NATIVE_REPAIR_PREPARATION_REQUIRED'
    assert blocked['next_action']['arguments']['workspace_path'] == str(root)
    with pytest.raises(RepairImpactError, match='NATIVE_REPAIR_ALREADY_BOUND'):
        intents.request(dict(SOURCE, finding_id='tc1-next-risk'), 'ria1-' + '3' * 32)
    assert len(tasks.store(root).records()) == 1


@pytest.mark.parametrize('mismatch', ['owner', 'preparation'])
def test_terminal_phase_without_exact_owner_and_context_does_not_release_guard(sample, mismatch):
    tasks, intents, root, preparation = sample
    ready(sample)
    original = tasks.begin(root, 'native-repair', _native_preparation=preparation)
    record = tasks.load(root, original['task_ref'])
    record['phase'] = 'COMPLETE'
    if mismatch == 'owner':
        record['task_owner'] = dict(host='codex', session='d' * 64)
    else:
        record['native_repair']['proposal_revision'] = 'd' * 64
    tasks.store(root).save(record)
    assert intents.guard()['status'] == 'NATIVE_REPAIR_PREPARATION_REQUIRED'
    with pytest.raises(RepairImpactError, match='NATIVE_REPAIR_ALREADY_BOUND'):
        intents.request(dict(SOURCE, finding_id='tc1-next-risk'), 'ria1-' + '3' * 32)


def test_missing_task_cannot_be_bound_to_ready_intent(sample):
    _, intents, _, _ = sample
    ready(sample)
    with pytest.raises(RepairImpactError, match='NATIVE_REPAIR_TASK_MISMATCH'):
        intents.bind('ts1-' + '4' * 32)
    assert intents.get()['status'] == 'READY'


def test_unsigned_intent_is_rejected_instead_of_unlocking_begin(sample):
    tasks, intents, root, _ = sample
    intents.request(SOURCE, ASSESSMENT)
    with sqlite3.connect(intents.store.path) as db:
        db.execute("UPDATE native_intents SET record='{}'")
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_STORAGE_INTEGRITY'):
        tasks.begin(root, 'ordinary-bypass')


def test_impact_only_legacy_database_is_read_without_schema_mutation(sample):
    _, intents, _, _ = sample
    with intents.store.connect(write=True) as db:
        db.execute('DROP TABLE native_intents')
    assert intents.get() is None
    with sqlite3.connect(intents.store.path) as db:
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='native_intents'").fetchone()
