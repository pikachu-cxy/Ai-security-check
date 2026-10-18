"""Technical assessment and its material-change decision share one transaction."""
import pytest

from security_runtime.risk_disposition import RiskDispositionStore


def test_failed_material_change_rolls_back_assessment_alias_and_decision(tmp_path, monkeypatch):
    root = tmp_path/'project'
    root.mkdir()
    store = RiskDispositionStore(tmp_path/'decisions.db')
    store.set(root, 'issue', 'DEFER', user_requested=True, evidence_revision='before')
    before = store.status(root, 'issue', current_revision='after', include_history=True)
    original = store._event
    def fail(*args):
        if args[-1]['event_kind'] == 'MATERIAL_RISK_CHANGE':
            raise OSError('fixture disposition event interruption')
        return original(*args)
    monkeypatch.setattr(store, '_event', fail)
    arguments = dict(assessment_id='assessment-1', fresh=True, evidence_backed=True,
                     metadata=dict(reference='reference', material_change_confirmable=True))
    with pytest.raises(OSError):
        store.record_assessment(root, 'issue', 'STILL_RISK', 'after', **arguments)
    assert store.status(root, 'issue', current_revision='after', include_history=True) == before
    assert store.find_reference(root, 'reference') is None
    monkeypatch.setattr(store, '_event', original)
    result = store.record_assessment(root, 'issue', 'STILL_RISK', 'after', **arguments)
    assert result['decision']['reopened'] is True
    assert result['technical_assessment']['assessment_id'] == 'assessment-1'
    store.record_assessment(root, 'issue', 'STILL_RISK', 'after', **arguments)
    events = store.status(root, 'issue', current_revision='after', include_history=True)['history']
    assert [event['event_kind'] for event in events] == ['USER_DISPOSITION', 'MATERIAL_RISK_CHANGE']
