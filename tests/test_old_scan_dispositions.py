"""Read-only historical summaries keep occurrence handling across line movement.

The scanner and public feedback surfaces run against isolated temporary projects;
the fixture assessments are bounded storage inputs, not AI accuracy assertions.
"""
from contextlib import contextmanager
import copy
from dataclasses import asdict, replace
import json
import sqlite3
from types import SimpleNamespace
import uuid

import pytest

from security_runtime.finding_feedback import FindingFeedbackService
from security_runtime.risk_disposition import DispositionUnavailable
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.storage import ReadOnlySQLiteStore
from test_finding_feedback_mcp import call, make_server
from test_risk_decision_experience import SOURCE, assess, experience


def _review_and_defer(experience, tmp_path):
    root, store, scan = experience
    first = scan()
    server, _ = make_server(store, tmp_path)
    assessed = assess(server, first.scan_id, first.findings[0], 'FALSE_POSITIVE',
        'The local const Function returns a closure containing text and never compiles the input.')
    assert assessed['technical_false_positive']
    deferred = call(server, 'set_finding_disposition', scan_id=first.scan_id,
        finding_id=first.findings[1].id, disposition='DEFER', user_requested=True)
    assert deferred['disposition']['active']
    return root, store, scan


@contextmanager
def _unchanged_files_and_scan(store, root, result):
    """Queries must not create aliases, alter scans, or rewrite source files."""
    state_dir = store.path.parent
    state = {path.relative_to(state_dir): path.read_bytes()
             for path in state_dir.rglob('*') if path.is_file()}
    source = {path.relative_to(root): path.read_bytes()
              for path in root.rglob('*') if path.is_file()}
    historical = copy.deepcopy(store.get_scan(result.scan_id))
    try:
        yield
    finally:
        assert store.get_scan(result.scan_id) == historical
        assert {path.relative_to(state_dir): path.read_bytes()
                for path in state_dir.rglob('*') if path.is_file()} == state
        assert {path.relative_to(root): path.read_bytes()
                for path in root.rglob('*') if path.is_file()} == source


def _assert_handling_without_scan(root, store, result, *, explicit):
    # New read-only service instances model a different chat or process.
    reader = ReadOnlySQLiteStore(store.path)
    with _unchanged_files_and_scan(store, root, result):
        summary = SecuritySummaryService(reader).get(root,
            result.scan_id if explicit else None, details=True)
        feedback = FindingFeedbackService(ReadOnlySQLiteStore(store.path), root)
        safe = feedback.status(result.scan_id, result.findings[0].id)
        risky = feedback.status(result.scan_id, result.findings[1].id)
        assert summary['scan_id'] == result.scan_id
        assert summary['risk_handling']['pending_finding_count'] == 0, summary['risk_handling']
        assert summary['risk_handling']['excluded_by_agent'] == 1
        assert summary['risk_handling']['deferred'] == 1
        assert summary['risk_handling']['resolved'] == 0
        assert summary['risk_handling']['raw_finding_count'] == 2
        # A surviving reminder choice does not attest freshness of the old scan.
        assert not summary['scan_context']['full_project_reusable']
        assert safe['technical_false_positive'] and safe['reminder_suppressed']
        assert risky['disposition']['disposition'] == 'DEFER'
        assert risky['disposition']['active'] and risky['reminder_suppressed']


@pytest.mark.parametrize('explicit', [False, True], ids=['latest', 'explicit-scan'])
def test_reused_old_scan_keeps_choices_after_comment_without_rescan(experience, tmp_path, explicit):
    root, store, scan = _review_and_defer(experience, tmp_path)
    second = scan()
    _assert_handling_without_scan(root, store, second, explicit=explicit)
    (root/'fp_case.js').write_text('// harmless leading comment\n' + SOURCE +
        '\nexport function health() { return "ok"; }\n', encoding='utf-8')
    _assert_handling_without_scan(root, store, second, explicit=explicit)


@pytest.mark.parametrize('explicit', [False, True], ids=['latest', 'explicit-scan'])
def test_reused_moved_scan_keeps_choices_after_another_comment(experience, tmp_path, explicit):
    root, store, scan = _review_and_defer(experience, tmp_path)
    path = root/'fp_case.js'
    path.write_text('// first harmless comment\n' + SOURCE, encoding='utf-8')
    moved = scan()
    _assert_handling_without_scan(root, store, moved, explicit=explicit)
    # This occurrence was never directly assessed or given a user choice.
    path.write_text('// second harmless comment\n' + path.read_text(encoding='utf-8') +
        '\nexport function health() { return "ok"; }\n', encoding='utf-8')
    _assert_handling_without_scan(root, store, moved, explicit=explicit)


def test_old_scan_material_change_stales_ai_without_losing_manual_defer(experience, tmp_path):
    root, store, scan = _review_and_defer(experience, tmp_path)
    second = scan()
    (root/'fp_case.js').write_text('// source moved and the safe binding changed\n' +
        SOURCE.replace('const Function = (text) => () => text;',
                       'const Function = globalThis.Function;'), encoding='utf-8')
    with _unchanged_files_and_scan(store, root, second):
        feedback = FindingFeedbackService(ReadOnlySQLiteStore(store.path), root)
        safe = feedback.status(second.scan_id, second.findings[0].id)
        risky = feedback.status(second.scan_id, second.findings[1].id)
        assert not safe['technical_false_positive']
        assert not safe['technical_assessment_current']
        assert not safe['reminder_suppressed']
        assert risky['disposition'] and risky['disposition']['active']
        assert risky['disposition']['disposition'] == 'DEFER'
        summary = SecuritySummaryService(ReadOnlySQLiteStore(store.path)).get(root, details=True)
        assert summary['risk_handling']['pending_finding_count'] == 1
        assert summary['risk_handling']['excluded_by_agent'] == 0
        assert summary['risk_handling']['deferred'] == 1


def test_same_call_text_in_adjacent_function_is_not_automatically_excluded(experience, tmp_path):
    root, store, scan = experience
    path = root/'fp_case.js'
    identical_calls = SOURCE.replace('return globalThis.Function(body)();', 'return Function(body)();')
    path.write_text(identical_calls, encoding='utf-8')
    first = scan()
    server, _ = make_server(store, tmp_path)
    assess(server, first.scan_id, first.findings[0], 'FALSE_POSITIVE',
        'Only echoText has a local const Function returning text without compiling the input.')
    second = scan()
    path.write_text('// a harmless line shift\n' + identical_calls, encoding='utf-8')
    with _unchanged_files_and_scan(store, root, second):
        feedback = FindingFeedbackService(ReadOnlySQLiteStore(store.path), root)
        safe = feedback.status(second.scan_id, second.findings[0].id)
        risky = feedback.status(second.scan_id, second.findings[1].id)
        assert safe['technical_false_positive'] and safe['reminder_suppressed']
        assert not risky['technical_false_positive']
        assert not risky['reminder_suppressed']
        summary = SecuritySummaryService(ReadOnlySQLiteStore(store.path)).get(root, details=True)
        assert summary['risk_handling']['pending_finding_count'] == 1
        assert summary['risk_handling']['excluded_by_agent'] == 1


def _remove_snapshot_table(store):
    # A DB created before this feature has no occurrence snapshot table.
    with sqlite3.connect(store.path) as database:
        database.execute('DROP TABLE finding_scope_snapshots')


@pytest.mark.parametrize('explicit', [False, True], ids=['latest', 'explicit-scan'])
def test_legacy_same_snapshot_falls_back_read_only_to_exact_bound_observation(experience, tmp_path, explicit):
    root, store, scan = _review_and_defer(experience, tmp_path)
    second = scan()
    _remove_snapshot_table(store)
    (root/'fp_case.js').write_text('// comment added after both scans\n' + SOURCE, encoding='utf-8')
    _assert_handling_without_scan(root, store, second, explicit=explicit)


def test_legacy_changed_snapshot_with_saved_choices_is_explicitly_unavailable(experience, tmp_path):
    root, store, scan = _review_and_defer(experience, tmp_path)
    path = root/'fp_case.js'
    # The finding locations remain identical, but their detector snapshots differ.
    path.write_text(SOURCE + '\nexport function health() { return "ok"; }\n', encoding='utf-8')
    second = scan()
    _remove_snapshot_table(store)
    path.write_text('// later source shift\n' + path.read_text(encoding='utf-8'), encoding='utf-8')
    with _unchanged_files_and_scan(store, root, second):
        reader = ReadOnlySQLiteStore(store.path)
        for finding in second.findings:
            references = reader.equivalent_finding_references(root, asdict(finding))
            assert {scan_id for scan_id, _ in references} == {second.scan_id}
        # Neither "still excluded" nor "pending again" can be proved from this
        # old database. Preserve the choice and report the association gap.
        feedback = FindingFeedbackService(reader, root)
        with pytest.raises(DispositionUnavailable):
            feedback.presentations(second.scan_id)
        with pytest.raises(DispositionUnavailable):
            SecuritySummaryService(reader).get(root, details=True)


def test_legacy_identical_other_workspace_observation_cannot_borrow_decisions(experience, tmp_path):
    root, store, scan = _review_and_defer(experience, tmp_path)
    first = scan()
    other = tmp_path/'other-project'
    other.mkdir()
    (other/'fp_case.js').write_text(SOURCE, encoding='utf-8')
    second = replace(first, scan_id=uuid.uuid4().hex,
        target_profile=replace(first.target_profile, path=str(other)))
    store.save(second)
    _remove_snapshot_table(store)
    (other/'fp_case.js').write_text('// source moved in the other workspace\n' + SOURCE, encoding='utf-8')
    with _unchanged_files_and_scan(store, other, second):
        reader = ReadOnlySQLiteStore(store.path)
        for finding in second.findings:
            references = reader.equivalent_finding_references(other, asdict(finding))
            assert {scan_id for scan_id, _ in references} == {second.scan_id}
        states = FindingFeedbackService(reader, other).presentations(second.scan_id)
        assert all(not state['reminder_suppressed'] for state in states.values())
        assert all(not state['technical_false_positive'] for state in states.values())
        summary = SecuritySummaryService(reader).get(other, details=True)
        assert summary['risk_handling']['pending_finding_count'] == 2
        assert summary['risk_handling']['excluded_by_agent'] == 0
        assert summary['risk_handling']['deferred'] == 0


def test_legacy_source_change_without_any_saved_handling_remains_pending(experience):
    root, store, scan = experience
    first = scan()
    _remove_snapshot_table(store)
    (root/'fp_case.js').write_text('// source moved with no saved choices\n' + SOURCE, encoding='utf-8')
    with _unchanged_files_and_scan(store, root, first):
        reader = ReadOnlySQLiteStore(store.path)
        states = FindingFeedbackService(reader, root).presentations(first.scan_id)
        assert all(not state['reminder_suppressed'] for state in states.values())
        assert all(not state['technical_false_positive'] for state in states.values())
        summary = SecuritySummaryService(reader).get(root, details=True)
        assert summary['risk_handling']['pending_finding_count'] == 2
        assert summary['risk_handling']['excluded_by_agent'] == 0
        assert summary['risk_handling']['deferred'] == 0


def test_invalid_source_locator_skips_binding_without_discarding_scan(experience):
    _, store, scan = experience
    first = scan()
    outside = replace(first.findings[0], file_path='../outside.js')
    result = replace(first, scan_id=uuid.uuid4().hex,
        findings=[outside, first.findings[1]])
    # The detector's original hash remains present. An unsafe locator still
    # cannot authorize reading outside the workspace or invalidate raw storage.
    assert outside.technical_details['evidence_locator']['file_sha256']
    store.save(result)
    assert store.get_scan(result.scan_id) == json.loads(json.dumps(result.to_dict()))
    assert store.finding_scope_snapshot(result.scan_id, outside.id) is None
    assert store.finding_scope_snapshot(result.scan_id, first.findings[1].id)


def test_direct_alias_does_not_depend_on_available_scan_snapshot(experience, tmp_path, monkeypatch):
    root, store, _ = _review_and_defer(experience, tmp_path)
    scan = store.latest_scan(root)
    attempted_reads = []

    def unavailable_snapshot(*args):
        attempted_reads.append(args)
        raise OSError('Snapshot storage temporarily unavailable')

    monkeypatch.setattr(ReadOnlySQLiteStore, 'finding_scope_snapshot', unavailable_snapshot)
    with _unchanged_files_and_scan(store, root, SimpleNamespace(scan_id=scan['scan_id'])):
        reader = ReadOnlySQLiteStore(store.path)
        feedback = FindingFeedbackService(reader, root)
        safe = feedback.status(scan['scan_id'], scan['findings'][0]['id'])
        risky = feedback.status(scan['scan_id'], scan['findings'][1]['id'])
        assert safe['technical_false_positive'] and safe['reminder_suppressed']
        assert risky['disposition']['active']
        assert risky['disposition']['disposition'] == 'DEFER'
        summary = SecuritySummaryService(reader).get(root, details=True)
        assert summary['risk_handling']['pending_finding_count'] == 0
        assert summary['risk_handling']['excluded_by_agent'] == 1
        assert summary['risk_handling']['deferred'] == 1
        assert attempted_reads == []
