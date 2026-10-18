"""Source adapters cannot replace a selected group or an archived native risk."""
import hashlib
from unittest.mock import Mock

import pytest

from summary_fixtures import sample
from test_task_triage import task
from security_runtime.repair_impact_sources import resolve_impact_source


def test_scanner_group_binding_contains_exact_active_members(sample):
    source = dict(kind='SCANNER_TASK_GROUP', task_ref=task(sample)['task_ref'])
    result = resolve_impact_source(source, sample[0], sample[2], None)
    assert result['binding']['scan_id'] == 'scan-a'
    assert set(result['member_ids']) == {f.id for f in sample[1].findings[:2]}
    assert result['source_paths'] == ['App.java']
    assert 'config.properties' in result['secret_ranges']


def test_scanner_group_is_not_an_arbitrary_member_subset(sample):
    source = dict(kind='SCANNER_TASK_GROUP', task_ref=task(sample)['task_ref'], finding_id='other')
    with pytest.raises(ValueError, match='IMPACT_SOURCE_INVALID'):
        resolve_impact_source(source, sample[0], sample[2], None)


def native(tmp_path, *, on_second_page=False, hidden=False):
    (tmp_path / 'app.py').write_text('def permitted(user):\n    return user.is_member\n')
    sha = hashlib.sha256((tmp_path / 'app.py').read_bytes()).hexdigest()
    finding = dict(id='risk-original', source='HOST_TASK_REVIEW', title='Candidate',
        evidence_locations=[dict(path='app.py', start_line=1, end_line=2,
                                 location_version='CURRENT_TASK_END')])
    record = dict(task_ref='ts1-original', review_revision=2,
        end=dict(hashes={'app.py': sha}), review=dict(source='HOST_TASK_REVIEW', findings=[]),
        review_history=[dict(revision=1, snapshot_id='original-snapshot',
                            source_hashes={'app.py': sha},
                            review=dict(source='HOST_TASK_REVIEW', findings=[finding]))])
    row = dict(finding_id='risk-original', status='OPEN', feedback=dict(folded=hidden),
               original_hashes={'app.py': sha})
    service = Mock()
    service.root.return_value = tmp_path
    service.load.return_value = record
    service.risk_ledger.side_effect = lambda *a, **k: (
        dict(items=[], has_more=True) if on_second_page and k['offset'] == 0 else
        dict(items=[row], has_more=False))
    return service, row


def test_archived_risk_uses_original_revision_and_pages_ledger(tmp_path):
    service, _ = native(tmp_path, on_second_page=True)
    source = dict(kind='HOST_TASK_RISK', task_ref='ts1-original', finding_id='risk-original', origin_review_revision=1)
    result = resolve_impact_source(source, tmp_path, None, service)
    assert result['binding']['origin_review_revision'] == 1
    assert result['binding']['origin_snapshot_id'] == 'original-snapshot'
    assert service.risk_ledger.call_count == 2
    service.load.assert_called_once_with(tmp_path, 'ts1-original', read_only=True)


def test_old_missing_or_hidden_risk_is_not_replaced_by_latest(tmp_path):
    service, _ = native(tmp_path, hidden=True)
    source = dict(kind='HOST_TASK_RISK', task_ref='ts1-original', finding_id='risk-original', origin_review_revision=1)
    with pytest.raises(ValueError, match='NOT_ACTIVE'):
        resolve_impact_source(source, tmp_path, None, service)
    source['origin_review_revision'] = 2
    with pytest.raises(ValueError, match='ORIGIN_REVISION_UNAVAILABLE'):
        resolve_impact_source(source, tmp_path, None, service)


def test_changed_origin_is_not_a_current_edit_locator(tmp_path):
    service, _ = native(tmp_path)
    (tmp_path / 'app.py').write_text('def replacement():\n    return 42\n')
    with pytest.raises(ValueError, match='ORIGIN_SOURCE_CHANGED'):
        resolve_impact_source(dict(kind='HOST_TASK_RISK', task_ref='ts1-original',
            finding_id='risk-original', origin_review_revision=1), tmp_path, None, service)


def test_selected_current_revision_does_not_use_first_ledger_hash(tmp_path):
    service, row = native(tmp_path)
    record = service.load.return_value
    finding = record['review_history'][0]['review']['findings'][0]
    record['review']['findings'] = [finding]
    row['original_hashes'] = {'app.py': 'a' * 64}
    result = resolve_impact_source(dict(kind='HOST_TASK_RISK', task_ref='ts1-original',
        finding_id='risk-original', origin_review_revision=2), tmp_path, None, service)
    assert result['binding']['origin_review_revision'] == 2
