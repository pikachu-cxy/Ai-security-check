"""Crash recovery at real feedback authority/derived-state transaction boundaries."""
import copy
import hashlib
import json
import sqlite3
from unittest.mock import patch

import pytest

from security_runtime.feedback_effects import pending
from security_runtime.persistence_effects import make_effect
from security_runtime.risk_disposition import RiskDispositionStore
from test_finding_feedback import setup, submit_fp


def test_target_failure_retains_authority_and_recovers_without_new_review(tmp_path):
    root, store, finding, service = setup(tmp_path)
    scan = copy.deepcopy(store.get_scan('s1'))
    with patch.object(service.dispositions, 'apply_effect', side_effect=OSError('offline')):
        result = submit_fp(service, finding)
    assert result['projection_sync'] == 'PENDING'
    assert not result['reminder_suppressed']
    assert len(store.finding_review_history(service.workspace)) == 1
    assert len(pending(store.path, service.workspace)) == 1
    assert service.reconcile_pending()['applied'] == 1
    assert service.status('s1', finding.id)['reminder_suppressed']
    assert store.get_scan('s1') == scan
    assert len(store.finding_review_history(service.workspace)) == 1


def test_authority_insert_and_outbox_rollback_together(tmp_path):
    _, store, finding, service = setup(tmp_path)
    with patch('security_runtime.feedback_effects.make_effect', side_effect=ValueError('injected')):
        with pytest.raises(ValueError, match='injected'):
            submit_fp(service, finding)
    assert store.finding_review_history(service.workspace) == []
    assert pending(store.path, service.workspace) == []
    assert not service.dispositions.path.exists()


def test_crash_after_target_commit_before_ack_replays_only_inbox(tmp_path):
    _, store, finding, service = setup(tmp_path)
    with patch.object(store, 'acknowledge_finding_effect', side_effect=OSError('crash')):
        submit_fp(service, finding)
    issue = pending(store.path, service.workspace)[0]['issue_key']
    before = service.dispositions.status(service.workspace, issue)['technical_assessment']
    with patch.object(service.dispositions, '_record_assessment', side_effect=AssertionError('must not write again')):
        assert service.reconcile_pending()['applied'] == 1
    after = service.dispositions.status(service.workspace, issue)['technical_assessment']
    assert before == after
    assert pending(store.path, service.workspace) == []


def assessment(store, root, *, revision, identifier, expected=None, verdict='NEEDS_CONTEXT'):
    return make_effect(kind='ASSESSMENT', source_id='authority-one', source_revision=revision,
        workspace=root, issue_key='issue-one', expected=expected or store.effect_versions(root, 'issue-one'),
        payload=dict(verdict=verdict, evidence_revision='version-one', assessment_id=identifier,
                     fresh=True, evidence_backed=True, metadata={}))


def test_out_of_order_source_effect_cannot_replace_newer_result(tmp_path):
    root = tmp_path / 'project'
    store = RiskDispositionStore(tmp_path / 'choices.db')
    old = assessment(store, root, revision=1, identifier='old')
    new = assessment(store, root, revision=2, identifier='new')
    assert store.apply_effect(new)['outcome'] == 'APPLIED'
    assert store.apply_effect(old)['outcome'] == 'SUPERSEDED'
    assert store.apply_effect(new)['already_applied']
    assert store.status(root, 'issue-one')['technical_assessment']['assessment_id'] == 'new'


def test_same_authority_queued_effects_can_advance_only_their_own_projection(tmp_path):
    root = tmp_path / 'project'
    store = RiskDispositionStore(tmp_path / 'choices.db')
    old = assessment(store, root, revision=1, identifier='old')
    new = assessment(store, root, revision=2, identifier='new')
    assert store.apply_effect(old)['outcome'] == 'APPLIED'
    assert store.apply_effect(new)['outcome'] == 'APPLIED'
    assert store.status(root, 'issue-one')['technical_assessment']['assessment_id'] == 'new'


def test_missing_legacy_watermark_does_not_invent_ownership(tmp_path):
    root = tmp_path / 'project'
    store = RiskDispositionStore(tmp_path / 'choices.db')
    delayed = assessment(store, root, revision=1, identifier='delayed')
    store.record_assessment(root, 'issue-one', 'NEEDS_CONTEXT', 'other', assessment_id='legacy')
    assert store.apply_effect(delayed)['outcome'] == 'SUPERSEDED'
    assert store.status(root, 'issue-one')['technical_assessment']['assessment_id'] == 'legacy'


def test_saved_new_choice_survives_delayed_technical_effect(tmp_path):
    root = tmp_path / 'project'
    store = RiskDispositionStore(tmp_path / 'choices.db')
    delayed = assessment(store, root, revision=1, identifier='delayed', verdict='STILL_RISK')
    chosen = store.set(root, 'issue-one', 'DEFER', user_requested=True, evidence_revision='old')
    assert store.apply_effect(delayed)['outcome'] == 'SUPERSEDED'
    result = store.status(root, 'issue-one', current_revision='version-one')
    assert result['active'] and result['event_id'] == chosen['event_id']


def test_material_change_and_target_inbox_rollback_as_one_transaction(tmp_path):
    root = tmp_path / 'project'
    store = RiskDispositionStore(tmp_path / 'choices.db')
    store.set(root, 'issue-one', 'EXCLUDE', user_requested=True, evidence_revision='old')
    effect = assessment(store, root, revision=1, identifier='new', verdict='STILL_RISK')
    effect['payload']['metadata'] = dict(material_change_confirmable=True)
    effect = make_effect(kind=effect['kind'], source_id=effect['source']['id'],
        source_revision=1, workspace=root, issue_key=effect['issue_key'],
        expected=effect['expected'], payload=effect['payload'])
    with patch.object(store, '_confirm_material_change', side_effect=OSError('fault')):
        with pytest.raises(OSError):
            store.apply_effect(effect)
    result = store.status(root, 'issue-one')
    assert result['active'] and result['technical_assessment'] is None
    assert store.apply_effect(effect)['outcome'] == 'APPLIED'
    assert not store.status(root, 'issue-one')['active']


def test_pending_status_is_read_only_and_does_not_replay(tmp_path):
    _, store, finding, service = setup(tmp_path)
    with patch.object(service.dispositions, 'apply_effect', side_effect=OSError('offline')):
        submit_fp(service, finding)
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in tmp_path.rglob('*') if p.is_file()}
    with patch.object(service.dispositions, 'apply_effect', side_effect=AssertionError('read must not replay')):
        assert service.status('s1', finding.id)['projection_sync'] == 'PENDING'
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in tmp_path.rglob('*') if p.is_file()}
    assert before == after


def test_choice_and_release_obligation_commit_once_for_request_retry(tmp_path):
    root = tmp_path / 'project'
    store = RiskDispositionStore(tmp_path / 'choices.db')
    template = dict(kind='RELEASE_NATIVE_INTENT', payload=dict(owner={'host': 'codex', 'session': 'a'*64},
        source={'kind': 'HOST_TASK_RISK'}, intent_sha256='b'*64))
    first = store.set(root, 'issue-one', 'DEFER', user_requested=True, request_id='same', effects=[template])
    effects = store.pending_effects(root)
    assert len(effects) == 1 and effects[0]['decision_event_id'] == first['event_id']
    store.set(root, 'issue-one', 'DEFER', user_requested=True, request_id='same', effects=[template])
    assert store.pending_effects(root) == effects
    store.acknowledge_effect(effects[0]['event_id'], 'APPLIED')
    assert store.pending_effects(root) == []


def test_failed_first_page_does_not_starve_an_unrelated_feedback_projection(tmp_path):
    from security_runtime.storage import SQLiteStore
    from security_runtime.feedback_effects import reconcile
    store = SQLiteStore(tmp_path / 'authority.db')
    target = RiskDispositionStore(tmp_path / 'target.db')
    root = tmp_path / 'project'
    for n in range(17):
        issue = 'blocked-'+str(n) if n < 16 else 'ready'
        template = dict(kind='ASSESSMENT', issue_key=issue,
            expected=target.effect_versions(root, issue),
            payload=dict(verdict='NEEDS_CONTEXT', evidence_revision='v', assessment_id=str(n),
                fresh=False, evidence_backed=False, metadata={}))
        store.save_finding_reviews(str(root), 's1', [dict(feedback_id=str(n))], effects=[template])
    apply = target.apply_effect
    def unavailable(effect):
        if effect['issue_key'].startswith('blocked-'):
            raise OSError('target unavailable for this issue')
        return apply(effect)
    with patch.object(target, 'apply_effect', side_effect=unavailable):
        assert reconcile(store, target, root, limit=16)['applied'] == 0
        assert reconcile(store, target, root, limit=16)['applied'] == 1
    assert target.status(root, 'ready')['technical_assessment']['assessment_id'] == '16'
    assert len(pending(store.path, root, limit=32)) == 16


def test_queued_assessment_may_follow_only_its_own_reminder_reopening(tmp_path):
    root=tmp_path/'project'
    store=RiskDispositionStore(tmp_path/'choices.db')
    chosen=store.set(root,'issue-one','DEFER',user_requested=True,evidence_revision='old')
    first=assessment(store,root,revision=1,identifier='reopen',verdict='STILL_RISK')
    first=make_effect(kind='ASSESSMENT',source_id=first['source']['id'],source_revision=1,
        workspace=root,issue_key=first['issue_key'],expected=first['expected'],
        payload=dict(first['payload'],metadata={'material_change_confirmable':True}))
    latest=assessment(store,root,revision=2,identifier='latest-fp',verdict='FALSE_POSITIVE')
    assert store.apply_effect(first)['outcome']=='APPLIED'
    assert not store.status(root,'issue-one')['active']
    assert store.apply_effect(latest)['outcome']=='APPLIED'
    result=store.status(root,'issue-one',current_revision='version-one')
    assert result['event_id']==chosen['event_id']
    assert result['technical_assessment']['assessment_id']=='latest-fp'
    assert result['technical_assessment']['automatic_exclusion']


def test_same_choice_id_with_unowned_material_change_rejects_delayed_effect(tmp_path):
    root=tmp_path/'project'
    store=RiskDispositionStore(tmp_path/'choices.db')
    chosen=store.set(root,'issue-one','DEFER',user_requested=True,evidence_revision='old')
    first=assessment(store,root,revision=1,identifier='first')
    latest=assessment(store,root,revision=2,identifier='delayed-fp',verdict='FALSE_POSITIVE')
    assert store.apply_effect(first)['outcome']=='APPLIED'
    store.confirm_material_change(root,'issue-one','foreign',assessment_id='other-authority',
        verdict='STILL_RISK',fresh=True,evidence_backed=True)
    assert store.status(root,'issue-one')['event_id']==chosen['event_id']
    assert store.apply_effect(latest)['outcome']=='SUPERSEDED'
    assert store.status(root,'issue-one')['technical_assessment']['assessment_id']=='first'


def test_legacy_watermark_without_choice_hash_does_not_claim_reopening(tmp_path):
    root=tmp_path/'project'
    store=RiskDispositionStore(tmp_path/'choices.db')
    store.set(root,'issue-one','DEFER',user_requested=True,evidence_revision='old')
    first=assessment(store,root,revision=1,identifier='first')
    latest=assessment(store,root,revision=2,identifier='delayed-fp',verdict='FALSE_POSITIVE')
    assert store.apply_effect(first)['outcome']=='APPLIED'
    with sqlite3.connect(store.path) as db:
        db.execute('ALTER TABLE effect_sources RENAME TO previous_sources')
        db.execute('CREATE TABLE effect_sources (workspace TEXT, issue_key TEXT, source_id TEXT, revision INTEGER NOT NULL, target_revision TEXT, PRIMARY KEY(workspace,issue_key,source_id))')
        db.execute('INSERT INTO effect_sources SELECT workspace,issue_key,source_id,revision,target_revision FROM previous_sources')
        db.execute('DROP TABLE previous_sources')
    store.confirm_material_change(root,'issue-one','foreign',assessment_id='other-authority',
        verdict='STILL_RISK',fresh=True,evidence_backed=True)
    assert store.apply_effect(latest)['outcome']=='SUPERSEDED'
    assert store.status(root,'issue-one')['technical_assessment']['assessment_id']=='first'
