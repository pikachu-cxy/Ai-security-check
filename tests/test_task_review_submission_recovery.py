"""Malformed evidence objects can be corrected on the original real task.

The temporary project mirrors the three B modules. The scanner is a recording
fixture; these tests never execute the sample project or an installed scanner.
"""
import copy
import hashlib
import json
import subprocess

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.task_ownership import TaskOwnershipError, session_owner
from security_runtime.task_review_contract import TaskReviewInputError
from security_runtime.task_risk_ledger import TaskRiskLedger
from security_runtime.task_security import TaskSecurityService
from test_task_security import LedgerRuntime


ORIGINAL_FILES = {
    'documents.py': (
        'def read_document(user_id, document_id, repository):\n'
        '    document = repository.get(document_id)\n'
        '    return {"id": document["id"], "body": document["body"]}\n'
    ),
    'permissions.py': (
        'def can_read(user_id, document):\n'
        '    return (\n'
        '        user_id == document["owner_id"]\n'
        '        or user_id in document["member_ids"]\n'
        '    )\n'
    ),
    'sharing.py': (
        'from permissions import can_read\n\n\n'
        'def shared_document_ids(user_id, repository):\n'
        '    return [\n'
        '        document["id"]\n'
        '        for document in repository.list_all()\n'
        '        if can_read(user_id, document)\n'
        '    ]\n'
    ),
}
DOWNLOAD = (
    'from documents import read_document\n\n\n'
    'def download_document(user_id, document_id, repository):\n'
    '    return read_document(user_id, document_id, repository)\n'
)


def source_hashes(root):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.glob('*.py'))}


def complete_plan(tasks, root, ref, packet):
    """Read every issued version/window before acknowledging its unit."""
    session, page = packet['review_session'], packet['plan']
    visited = []
    while True:
        sources = {item['source_ref']: item for item in page.get('sources', [])}
        for unit in page['units']:
            for window in unit['required_windows']:
                binding = sources[window['source_ref']] if 'source_ref' in window else window
                version = ('BEFORE_TASK' if binding['location_version'] in
                           {'BEFORE_TASK', 'BEFORE_DELETION'} else 'CURRENT')
                low, high = window['start_line'], window['end_line'] or 2_147_483_647
                while True:
                    read = tasks.read(root, ref, session, binding['path'], low, high,
                                      source_version=version)
                    assert len(read.get('lines', read.get('numbered_lines', []))) <= 80
                    if 'next_range' in read:
                        low, high = read['next_range']
                    elif read.get('has_more'):
                        following = read['next_read']
                        assert following['source_version'] == version
                        low, high = following['start_line'], following['end_line']
                    else:
                        break
            batch = tasks.submit_batch(root, ref, session, [unit['unit_id']], 'REVIEWED', [])
            assert batch['status'] == 'BATCH_RECORDED'
            assert batch['coverage'] == 'REVIEWED' and batch['scanner_run'] is False
            visited.append(unit['path'])
        if page['next_cursor'] is None:
            return visited
        page = tasks.review_plan(root, ref, session, page['next_cursor'], limit=5)


@pytest.fixture(params=[2, 3], ids=['protocol-2', 'protocol-3'])
def review_case(tmp_path, request):
    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    for name, content in ORIGINAL_FILES.items():
        (root / name).write_text(content, encoding='utf-8')
    original_hashes = source_hashes(root)
    runtime = LedgerRuntime()
    hooks = HookStateStore(tmp_path / 'private-state')
    owner = session_owner('codex', 'original-download-development')
    tasks = TaskSecurityService(runtime, hooks, owner=owner)
    ref = tasks.begin(root, 'add-download-forwarder')['task_ref']
    baseline = copy.deepcopy(tasks.load(root, ref)['baseline'])
    assert baseline['hashes'] == original_hashes
    assert 'download.py' not in baseline['hashes']
    (root / 'download.py').write_text(DOWNLOAD, encoding='utf-8')
    packet = tasks.prepare(root, ref, protocol_version=request.param)
    assert packet['status'] == 'REVIEW_REQUIRED'
    session = packet['review_session']
    # Match the B submission's actual task evidence at download.py:4-5, while
    # still reading every plan window and submitting every plan batch below.
    download = tasks.read(root, ref, session, 'download.py', 4, 5)
    assert download['evidence_id']
    assert complete_plan(tasks, root, ref, packet) == ['download.py']
    evidence = {'download.py': download['evidence_id']}
    for name, content in ORIGINAL_FILES.items():
        read = tasks.read(root, ref, session, name, 1, len(content.splitlines()))
        evidence[name] = read['evidence_id']
    # Related reads add real plan obligations. Navigate and acknowledge those
    # units too; reading their source alone must never satisfy a full review.
    expanded = dict(review_session=session, plan=tasks.review_plan(root, ref, session))
    assert set(complete_plan(tasks, root, ref, expanded)) == {*ORIGINAL_FILES, 'download.py'}
    record = tasks.load(root, ref)
    assert record['phase'] == 'REVIEWING'
    assert record['baseline'] == baseline
    assert record['changes'] == [dict(path='download.py', change='ADDED')]
    assert set(record['related_files']) == set(ORIGINAL_FILES)
    assert runtime.calls == [('download.py',)]
    return dict(root=root, tasks=tasks, hooks=hooks, runtime=runtime, owner=owner,
                ref=ref, session=session, evidence=evidence)


def candidate(case):
    evidence = case['evidence']
    return dict(
        title='Document reads do not enforce the shared access policy',
        category='authorization', severity='MEDIUM', risk_scope='RELATED_EXISTING',
        primary_evidence=evidence['documents.py'], task_evidence=evidence['download.py'],
        evidence_refs=list(evidence.values()),
        impact='A caller able to choose a document identifier may read another user document.',
        preconditions=['The download entry is reachable with an arbitrary document identifier.'],
        unknowns=['External routing or middleware ownership checks have not been confirmed.'],
        counterevidence=['The sharing list uses can_read, but the forwarded read does not.'],
        current_protections=['can_read permits owners and shared members; sharing uses that policy.'],
        fix_advice='Enforce can_read before returning the body while preserving member access.',
    )


def observed_state(case):
    return dict(
        record=copy.deepcopy(case['tasks'].load(case['root'], case['ref'])),
        ledger=copy.deepcopy(TaskRiskLedger(case['hooks'], case['root']).read()),
        source_hashes=source_hashes(case['root']),
        scans=copy.deepcopy(case['runtime'].calls),
    )


def submit(case, findings):
    return case['tasks'].submit(case['root'], case['ref'], case['session'],
                                findings, 'REVIEWED', [])


def test_object_evidence_rejection_can_be_corrected_without_restarting_task(review_case):
    case = review_case
    valid = candidate(case)
    before = observed_state(case)
    assert before['ledger'] == {}

    # B first submitted file_path objects, then renamed that key to file. Both
    # are invalid: Runtime must neither unwrap objects nor discard the task.
    for path_key in ('file_path', 'file'):
        def evidence_object(identifier):
            location = before['record']['evidence'][identifier]
            return dict(evidence_id=identifier, **{path_key: location['path']},
                        start_line=location['start_line'], end_line=location['end_line'])

        malformed = copy.deepcopy(valid)
        malformed['primary_evidence'] = evidence_object(valid['primary_evidence'])
        malformed['task_evidence'] = evidence_object(valid['task_evidence'])
        malformed['evidence_refs'] = [evidence_object(ref) for ref in valid['evidence_refs']]
        with pytest.raises(ValueError) as rejected:
            submit(case, [malformed])
        assert isinstance(rejected.value, TaskReviewInputError)
        response = rejected.value.response()
        assert response['reason_code'] == 'TASK_REVIEW_INPUT_INVALID'
        assert response['review_state_changed'] is False
        assert response['scanner_run'] is False and response['repair_authorized'] is False
        errors = response['field_errors']
        assert 1 <= len(errors) <= 6
        assert {row['field'] for row in errors} >= {
            'findings[0].primary_evidence', 'findings[0].task_evidence',
            'findings[0].evidence_refs[0]',
        }
        assert all(row['expected_type'] == 'string' for row in errors)
        encoded = json.dumps(response)
        assert 'documents.py' not in encoded and valid['primary_evidence'] not in encoded
        assert observed_state(case) == before
        assert case['tasks'].load(case['root'], case['ref'])['phase'] == 'REVIEWING'

    result = submit(case, [valid])
    assert result['status'] == 'COMPLETE' and result['task_ref'] == case['ref']
    record = case['tasks'].load(case['root'], case['ref'])
    assert record['baseline'] == before['record']['baseline']
    assert record['review_session'] == case['session']
    assert record['review']['coverage'] == 'REVIEWED'
    assert len(record['review']['findings']) == 1
    finding = record['review']['findings'][0]
    assert finding['source'] == 'HOST_TASK_REVIEW'
    assert finding['risk_scope'] == 'RELATED_EXISTING'
    assert finding['file_path'] == 'documents.py'
    assert finding['task_evidence'] == case['evidence']['download.py']
    history = case['tasks'].get(case['root'], case['ref'])
    assert history['host_review']['finding_count'] == 1
    rows = TaskRiskLedger(case['hooks'], case['root']).read()
    assert len(rows) == 1 and next(iter(rows.values()))['origin_task_ref'] == case['ref']
    completed = observed_state(case)
    submit(case, [valid])
    assert observed_state(case) == completed
    assert completed['scans'] == before['scans'] == [('download.py',)]
    assert completed['source_hashes'] == before['source_hashes']


def test_incomplete_task_cannot_be_reopened_by_correcting_submission(review_case):
    case = review_case
    result = case['tasks'].skip(case['root'], case['ref'], 'Host ended with a disclosed review gap.')
    assert result['status'] == 'INCOMPLETE'
    before = observed_state(case)
    with pytest.raises(ValueError):
        submit(case, [candidate(case)])
    assert observed_state(case) == before
    assert before['record']['phase'] == 'INCOMPLETE'
    assert before['ledger'] == {} and before['scans'] == [('download.py',)]


def test_submission_recovery_does_not_transfer_task_ownership(review_case):
    case = review_case
    foreign = TaskSecurityService(case['runtime'], case['hooks'],
                                  owner=session_owner('codex', 'another-chat'))
    before = observed_state(case)
    with pytest.raises(TaskOwnershipError) as rejected:
        foreign.submit(case['root'], case['ref'], case['session'],
                       [candidate(case)], 'REVIEWED', [])
    assert rejected.value.reason_code == 'TASK_SESSION_SCOPE_MISMATCH'
    assert observed_state(case) == before
    assert before['record']['task_owner'] == case['owner']


def test_submission_recovery_keeps_source_version_freshness_gate(review_case):
    case = review_case
    (case['root'] / 'documents.py').write_text(
        ORIGINAL_FILES['documents.py'].replace('repository.get(document_id)',
                                              'repository.get_unchecked(document_id)'),
        encoding='utf-8',
    )
    before = observed_state(case)
    with pytest.raises(ValueError, match='stale|changed'):
        submit(case, [candidate(case)])
    assert observed_state(case) == before
    assert before['record']['phase'] == 'REVIEWING'
    assert before['record']['end']['hashes']['documents.py'] != before['source_hashes']['documents.py']
    assert before['ledger'] == {} and before['scans'] == [('download.py',)]
