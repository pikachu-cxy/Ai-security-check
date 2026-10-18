"""Native workspace-state paths retain genuine read-only history access."""
import sqlite3

import pytest

from security_runtime.hook_state import native_io_path
from security_runtime.repair_impact import RepairImpactService, RepairImpactError


@pytest.mark.parametrize('target_length', [220, 350])
def test_native_state_path_history_is_read_only(tmp_path, target_length):
    root = tmp_path/'project'
    root.mkdir()
    (root/'app.py').write_text('def access(member):\n    return member.active\n', encoding='utf8')
    directory = tmp_path/'state'
    while len(str(directory/'assessments.sqlite3')) < target_length:
        remaining = target_length-len(str(directory/'assessments.sqlite3'))
        directory /= 's'*min(60, max(1, remaining-1))
    # Match HookStateStore's native representation, including the extended
    # prefix on Windows, rather than merely a conventional long filename.
    directory = native_io_path(directory)
    source = dict(kind='SCANNER_TASK_GROUP', task_ref='test-original-group')
    resolved = dict(binding=dict(source, scan_id='scan-1', member_ids=['risk-1']),
        source_paths=['app.py'], required_windows=[dict(file_path='app.py', start_line=1, end_line=2)])
    proposal = dict(security_goal='Retain membership policy', summary='Use the selected check',
        changes=[dict(file_path='app.py', start_line=1, end_line=2, reason='Selected risk')], preserve=[])
    service = RepairImpactService(root, directory, dict(host='codex', session='test-session'), lambda _:resolved)
    prepared = service.prepare(source, proposal)
    ref = prepared['assessment_ref']
    evidence = service.read(ref, 'app.py', 1, 2)
    service.submit(ref, [dict(kind='NO_ADDITIONAL_CHANGE_IDENTIFIED',
        summary='The reviewed access condition is retained', evidence_refs=[evidence['evidence_ref']])], [])
    before, stamp = service.store.path.read_bytes(), service.store.path.stat().st_mtime_ns
    assert service.get(ref)['gate'] == 'READY_FOR_EXISTING_AUTH'
    assert service.validate_for_fix(ref, source)['gate'] == 'READY_FOR_EXISTING_AUTH'
    with service.store.connect() as db:
        with pytest.raises(sqlite3.OperationalError, match='readonly'):
            db.execute('DELETE FROM assessments')
    assert service.store.path.read_bytes() == before
    assert service.store.path.stat().st_mtime_ns == stamp


def test_native_spelling_cannot_put_private_state_inside_workspace(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    private = native_io_path(root/'private')
    with pytest.raises(RepairImpactError, match='REPAIR_IMPACT_PRIVATE_STORAGE_REQUIRED'):
        RepairImpactService(root, private, dict(host='codex', session='test-session'), lambda _:None)
    assert not private.exists()
