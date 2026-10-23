"""Real task/MCP handlers must retain hidden changes without exporting proofs.

Only the scanner is a deterministic fixture. Baselines, private preimages,
planning, source delivery, submission and signed persistence use real services.
"""
import asyncio
import json
import sqlite3

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.mcp_server import create_server
from test_task_security import service  # noqa: F401
from task_review_helpers import read_plan, read_window


PRIVATE_VALUE = 'acceptance-private-credential-473b8e69'


def _call(server, name, **arguments):
    result = asyncio.run(server._tool_manager.call_tool(name, arguments, convert_result=True))
    if hasattr(result, 'structuredContent'):
        assert not result.isError
        return result.structuredContent
    return json.loads(result[0].text)


def _source(role='old', operation='allow', comment='before comment'):
    lines = ['def choose(user):', f"    role_token = '{role}'", f"    credential = '{PRIVATE_VALUE}'"]
    lines.extend(f'    value_{i} = {i}' for i in range(3, 140))
    lines[45] = '# ' + comment
    lines[123] = f'    permitted = policy.{operation}(user)'
    return '\n'.join(lines) + '\n'


def _prepare(sample, *, hidden=False, visible=True, comment=False, missing_old_proof=False):
    tasks, root, runtime = sample
    path = root / 'mixed.py'
    path.write_text(_source(), encoding='utf-8')
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, tasks.hooks), global_mode=False)
    base = dict(workspace_path=str(root))
    ref = _call(server, 'begin_security_task', **base, task_key='redacted-changes')['task_ref']
    baseline = tasks.load(root, ref)['baseline']
    private = tasks.preimages(root)
    before = private.read_semantic_proof(ref, 'mixed.py', baseline['hashes']['mixed.py'],
                                        baseline['preimages']['mixed.py'])
    assert before['complete']
    path.write_text(_source(role='new' if hidden else 'old', operation='enforce' if visible else 'allow',
                            comment='after comment' if comment else 'before comment'), encoding='utf-8')
    after = private.semantic_proof(ref, 'mixed.py', path.read_bytes())
    assert after['complete']
    commitments = set(before['semantic_lines'].values()) | set(after['semantic_lines'].values())
    assert commitments
    if missing_old_proof:
        with sqlite3.connect(private.path) as connection:
            connection.execute('DELETE FROM task_preimage_semantics WHERE task_ref=? AND path=?', (ref, 'mixed.py'))
        unavailable = private.read_semantic_proof(ref, 'mixed.py', baseline['hashes']['mixed.py'],
                                                  baseline['preimages']['mixed.py'])
        assert unavailable['complete'] is False
    packet = _call(server, 'prepare_task_security_review', **base, task_ref=ref, protocol_version=3)
    assert packet['status'] == 'REVIEW_REQUIRED' and packet['protocol_version'] == 3
    return server, tasks, root, runtime, ref, packet, commitments


class _ReviewTransport:
    """Keep the shared traversal helper on the real MCP ingress boundary."""
    def __init__(self, server):
        self.server = server

    def review_plan(self, root, ref, session, cursor=0, limit=5):
        return _call(self.server, 'get_task_review_plan', workspace_path=str(root), task_ref=ref,
                     review_session=session, cursor=cursor, limit=limit)

    def read(self, root, ref, session, path, low, high, source_version='CURRENT'):
        return _call(self.server, 'read_task_review_context', workspace_path=str(root), task_ref=ref,
                     review_session=session, file_path=path, start_line=low, end_line=high,
                     source_version=source_version)


def _windows(server, root, ref, packet):
    units, _ = read_plan(_ReviewTransport(server), root, ref, packet)
    return {unit['unit_id']:unit for unit in units}, [
        window for unit in units for window in unit['required_windows']]


def _covers(requirements, version, line):
    return any(item['path'] == 'mixed.py' and item['location_version'] == version
               and item['start_line'] <= line <= (item['end_line'] or 2_147_483_647)
               for item in requirements)


def _private_absent(value, commitments):
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if PRIVATE_VALUE in serialized or "role_token = 'old'" in serialized or "role_token = 'new'" in serialized:
        pytest.fail('Original hidden source escaped the public/control boundary.')
    if any(item in serialized for item in commitments):
        pytest.fail('A private semantic commitment escaped the sidecar boundary.')
    def check_keys(item):
        if isinstance(item, dict):
            if {'semantic_lines', 'semantic_proofs'} & item.keys():
                pytest.fail('Planning-only semantic metadata escaped into public/control state.')
            for child in item.values():
                check_keys(child)
        elif isinstance(item, list):
            for child in item:
                check_keys(child)
    check_keys(value)


def _database_private_absent(tasks, root, ref, commitments):
    with sqlite3.connect(tasks.store(root).path) as connection:
        row = connection.execute('SELECT data FROM security_tasks WHERE ref=?', (ref,)).fetchone()
    assert row
    _private_absent(json.loads(row[0]), commitments)
    # The private semantic table is the sole permitted location for semantic
    # HMACs. The ordinary preimage body and its existing reference stay sanitized.
    with sqlite3.connect(tasks.preimages(root).path) as connection:
        rows = connection.execute('SELECT r.metadata,CASE WHEN length(r.body)>0 THEN r.body ELSE b.body END '
            'FROM task_preimages r LEFT JOIN task_preimage_blobs b '
            "ON b.sha256=json_extract(r.metadata,'$.body_sha256') WHERE r.task_ref=?", (ref,)).fetchall()
        private_rows = connection.execute('SELECT body FROM task_preimage_semantics WHERE task_ref=?', (ref,)).fetchall()
    for metadata, body in rows:
        _private_absent(dict(metadata=json.loads(metadata), body=json.loads(body)), commitments)
    for body, in private_rows:
        serialized = body.decode('utf-8') if isinstance(body, bytes) else body
        if PRIVATE_VALUE in serialized or "role_token = 'old'" in serialized or "role_token = 'new'" in serialized:
            pytest.fail('Private proof storage retained original hidden source.')


def _complete(prepared):
    server, tasks, root, runtime, ref, packet, commitments = prepared
    units, requirements = _windows(server, root, ref, packet)
    delivered = []
    for item in requirements:
        for evidence in read_window(_ReviewTransport(server), root, ref, packet['review_session'], item):
            _private_absent(evidence, commitments)
            delivered.append(evidence)
    _private_absent(packet, commitments)
    _private_absent(tasks.load(root, ref), commitments)
    _database_private_absent(tasks, root, ref, commitments)
    batch = _call(server, 'submit_task_review_batch', workspace_path=str(root), task_ref=ref,
        review_session=packet['review_session'], unit_ids=list(units), coverage='REVIEWED', limitations=[])
    _private_absent(batch, commitments)
    finished = _call(server, 'submit_task_security_review', workspace_path=str(root), task_ref=ref,
        review_session=packet['review_session'], findings=[], coverage='REVIEWED', limitations=[])
    assert finished['status'] == 'COMPLETE' and finished['result_saved']
    history = _call(server, 'get_task_security_review', workspace_path=str(root), task_ref=ref)
    _private_absent(history, commitments)
    _private_absent(tasks.load(root, ref), commitments)
    assert len(runtime.calls) == 1
    return batch, history, requirements, delivered


def test_mixed_hidden_and_visible_changes_require_both_versions_and_keep_semantic_gap(service):
    prepared = _prepare(service, hidden=True)
    server, tasks, root, _, ref, packet, _ = prepared
    _, requirements = _windows(server, root, ref, packet)
    for version in ('BEFORE_TASK', 'CURRENT_TASK_END'):
        assert _covers(requirements, version, 2), 'Hidden semantic change line was omitted.'
        assert _covers(requirements, version, 124), 'Distant visible change line was omitted.'
    record = tasks.load(root, ref)
    assert any(unit['evidence_gaps'] for unit in record['review_plan']['units'])
    batch, history, requirements, delivered = _complete(prepared)
    assert delivered and batch['coverage'] == 'PARTIAL'
    assert history['host_review']['coverage'] == 'PARTIAL'
    assert history['context_read_coverage']['plan_gap_count'] > 0
    notes = json.dumps(history['host_review']['limitations'], ensure_ascii=False)
    assert 'mixed.py' in notes and '脱敏' in notes


@pytest.mark.parametrize('case', ['visible_only', 'comment_only'])
def test_unchanged_hidden_literal_and_comment_edit_do_not_permanently_block_review(service, case):
    prepared = _prepare(service, hidden=False, visible=case == 'visible_only', comment=case == 'comment_only')
    batch, history, _, _ = _complete(prepared)
    assert batch['coverage'] == 'REVIEWED'
    assert history['host_review']['coverage'] == 'REVIEWED'
    assert history['context_read_coverage']['plan_gap_count'] == 0


def test_missing_old_private_proof_never_uses_visible_hunk_as_complete_semantic_coverage(service):
    prepared = _prepare(service, hidden=True, missing_old_proof=True)
    batch, history, requirements, _ = _complete(prepared)
    for version in ('BEFORE_TASK', 'CURRENT_TASK_END'):
        assert _covers(requirements, version, 2)
        assert _covers(requirements, version, 124)
    assert batch['coverage'] == 'PARTIAL'
    assert history['host_review']['coverage'] == 'PARTIAL'
    assert history['context_read_coverage']['plan_gap_count'] > 0
    notes = json.dumps(history['host_review']['limitations'], ensure_ascii=False)
    assert 'mixed.py' in notes and '定位' in notes


def _prepare_credential_change(sample, name, current_literal, *, comment_only=False):
    tasks, root, runtime = sample
    path = root / 'demo.ts'
    source = f"export const {name} = '{PRIVATE_VALUE}';\n// before comment\n"
    path.write_text(source, encoding='utf-8')
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, tasks.hooks), global_mode=False)
    base = dict(workspace_path=str(root))
    ref = _call(server, 'begin_security_task', **base, task_key='credential-clear')['task_ref']
    baseline = tasks.load(root, ref)['baseline']
    private = tasks.preimages(root)
    before = private.read_semantic_proof(ref, 'demo.ts', baseline['hashes']['demo.ts'],
                                        baseline['preimages']['demo.ts'])
    current = (source.replace('before comment', 'after comment') if comment_only else
               f'export const {name} = {current_literal};\n// before comment\n')
    path.write_text(current, encoding='utf-8')
    after = private.semantic_proof(ref, 'demo.ts', path.read_bytes())
    assert before['complete'] and after['complete']
    commitments = set(before['semantic_lines'].values()) | set(after['semantic_lines'].values())
    packet = _call(server, 'prepare_task_security_review', **base, task_ref=ref, protocol_version=3)
    return server, tasks, root, runtime, ref, packet, commitments


@pytest.mark.parametrize('name', ['demoToken', 'token', 'api_key'])
@pytest.mark.parametrize('empty', ["''", '""', '``'])
def test_v3_cleared_credential_has_readable_empty_value_and_no_hidden_change_gap(service, name, empty):
    prepared = _prepare_credential_change(service, name, empty)
    batch, history, requirements, delivered = _complete(prepared)
    assert batch['coverage'] == 'REVIEWED'
    assert history['host_review']['coverage'] == 'REVIEWED'
    assert history['context_read_coverage']['plan_gap_count'] == 0
    versions = {item['source_ref']: item['location_version'] for item in requirements}
    current = [item for item in delivered if versions[item['source_ref']] == 'CURRENT_TASK_END']
    before = [item for item in delivered if versions[item['source_ref']] == 'BEFORE_TASK']
    assert current and before
    assert f'export const {name} = {empty};' in '\n'.join(
        line for item in current for line in item['lines'])
    assert PRIVATE_VALUE not in json.dumps(delivered)


@pytest.mark.parametrize('name', ['demoToken', 'token'])
def test_v3_different_hidden_credential_still_forces_partial(service, name):
    prepared = _prepare_credential_change(service, name, f"'{PRIVATE_VALUE}-replacement'")
    batch, history, _, _ = _complete(prepared)
    assert batch['coverage'] == 'PARTIAL'
    assert history['host_review']['coverage'] == 'PARTIAL'
    assert history['context_read_coverage']['plan_gap_count'] > 0


def test_v3_unchanged_hidden_credential_and_comment_edit_remains_reviewable(service):
    prepared = _prepare_credential_change(service, 'demoToken', None, comment_only=True)
    batch, history, _, _ = _complete(prepared)
    assert batch['coverage'] == 'REVIEWED'
    assert history['host_review']['coverage'] == 'REVIEWED'
    assert history['context_read_coverage']['plan_gap_count'] == 0
