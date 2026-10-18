"""Private semantic comparison does not expose or replace immutable source."""
import hashlib
import json
import sqlite3

import pytest

from security_runtime.local_evidence import safe_source
from security_runtime import task_preimage_fingerprints as fingerprints
from security_runtime import task_preimages as preimages
from security_runtime.task_preimages import TaskPreimageUnavailable
from test_task_preimages import sample, FIRST, SECOND  # noqa: F401


def captured(store, raw, path='routes.py', task=FIRST):
    with store.writer(task) as writer:
        reference = writer.put(path, raw, safe_source(raw.decode('utf-8-sig'), source_path=path))
    return reference


def proof(store, reference):
    return store.read_semantic_proof(reference['task_ref'], reference['path'], reference['raw_sha256'], reference)


def test_proof_is_sparse_private_and_old_reference_contract_is_unchanged(sample):
    store, _ = sample
    raw = b"def route(user):\n    password = 'leaf-private-secret'\n    return auth.check(user)\n"
    reference = captured(store, raw)
    result = proof(store, reference)
    assert result['complete'] is True and result['line_count'] == 3
    assert set(result['semantic_lines']) == {2}
    assert set(reference) == preimages.REFERENCE_FIELDS | {'mac'}
    assert store.read(FIRST, 'routes.py', reference['raw_sha256'], reference) == safe_source(raw.decode(), source_path='routes.py')
    assert b'leaf-private-secret' not in store.path.read_bytes()
    for value in result['semantic_lines'].values():
        assert value not in json.dumps(reference)
    assert result == store.semantic_proof(FIRST, 'routes.py', raw)


def test_tokens_preserve_hash_slashes_inside_string_and_ignore_real_comment_changes(sample):
    store, _ = sample
    old = b'value = "https://host/#fragment" # first private comment\n'
    changed_comment = b'value = "https://host/#fragment" # changed private comment\n'
    changed_literal = b'value = "https://host/#different" # first private comment\n'
    first = store.semantic_proof(FIRST, 'a.py', old)
    assert first['complete'] and set(first['semantic_lines']) == {1}
    assert first == store.semantic_proof(FIRST, 'a.py', changed_comment)
    assert first['semantic_lines'] != store.semantic_proof(FIRST, 'a.py', changed_literal)['semantic_lines']
    comment_only = store.semantic_proof(FIRST, 'a.py', b'# no semantic source\nallowed = guard.check(user)\n')
    assert comment_only['complete'] and comment_only['semantic_lines'] == {}


def test_private_key_ownership_precedes_comment_tokenizer(sample):
    store, _ = sample
    first = b'-----BEGIN PRIVATE KEY-----\nAAAA//first-hidden-part\n-----END PRIVATE KEY-----\n'
    second = first.replace(b'first-hidden-part', b'other-hidden-part')
    old = store.semantic_proof(FIRST, 'key.py', first)
    new = store.semantic_proof(FIRST, 'key.py', second)
    assert old['complete'] and new['complete']
    assert old['semantic_lines'][2] != new['semantic_lines'][2]


def test_fingerprints_align_after_insertion_but_are_task_and_path_bound(sample):
    store, _ = sample
    raw = b'value = "private-literal"\n'
    first = store.semantic_proof(FIRST, 'a.py', raw)['semantic_lines'][1]
    shifted = store.semantic_proof(FIRST, 'a.py', b'allowed = guard.check(user)\n' + raw)
    assert shifted['semantic_lines'][2] == first
    assert store.semantic_proof(SECOND, 'a.py', raw)['semantic_lines'][1] != first
    assert store.semantic_proof(FIRST, 'b.py', raw)['semantic_lines'][1] != first


def test_truncated_semantic_suffix_has_private_comparison_without_persisting_suffix(sample):
    store, _ = sample
    raw = ('result = ' + 'value + ' * 120 + 'first\n').encode()
    changed = raw.replace(b'first\n', b'other\n')
    old = store.semantic_proof(FIRST, 'a.py', raw)
    new = store.semantic_proof(FIRST, 'a.py', changed)
    assert old['complete'] and set(old['semantic_lines']) == {1}
    assert old['semantic_lines'] != new['semantic_lines']


@pytest.mark.parametrize('missing', ['row', 'table'])
def test_legacy_missing_proof_is_explicitly_incomplete_and_original_body_still_valid(sample, missing):
    store, _ = sample
    reference = captured(store, b'value = "private"\n')
    with sqlite3.connect(store.path) as db:
        db.execute('DELETE FROM task_preimage_semantics' if missing == 'row' else 'DROP TABLE task_preimage_semantics')
    result = proof(store, reference)
    assert result == dict(version=1, complete=False, line_count=1, semantic_lines={})
    assert store.read(FIRST, 'routes.py', reference['raw_sha256'], reference)


@pytest.mark.parametrize('column,value', [('body', b'{}'), ('metadata', '{}'), ('mac', '0' * 64),
    ('created', 1), ('expires', 999999)])
def test_tampered_private_proof_is_rejected_without_affecting_original_body(sample, column, value):
    store, _ = sample
    reference = captured(store, b'value = "private"\n')
    with sqlite3.connect(store.path) as db:
        db.execute(f'UPDATE task_preimage_semantics SET {column}=?', (value,))
    with pytest.raises(TaskPreimageUnavailable) as rejected:
        proof(store, reference)
    assert rejected.value.reason_code == 'TASK_PREIMAGE_SEMANTICS_UNVERIFIED'
    assert store.read(FIRST, 'routes.py', reference['raw_sha256'], reference)


@pytest.mark.parametrize('task,path,expected', [(SECOND, 'routes.py', None),
    (FIRST, 'different.py', None), (FIRST, 'routes.py', '0' * 64)])
def test_original_reference_task_path_and_hash_are_verified_before_proof(sample, task, path, expected):
    store, _ = sample
    reference = captured(store, b'value = "private"\n')
    with pytest.raises(TaskPreimageUnavailable) as rejected:
        store.read_semantic_proof(task, path, expected or reference['raw_sha256'], reference)
    assert rejected.value.reason_code == 'TASK_PREIMAGE_REFERENCE_UNVERIFIED'


@pytest.mark.parametrize('limit', ['MAX_FILE_PROOF_BYTES', 'MAX_TASK_PROOF_BYTES', 'MAX_WORKSPACE_PROOF_BYTES'])
def test_optional_fingerprint_budget_retains_original_body_and_reference(sample, monkeypatch, limit):
    store, _ = sample
    monkeypatch.setattr(fingerprints, limit, 1)
    raw = b'value = "private"\n'
    reference = captured(store, raw)
    assert store.read(FIRST, 'routes.py', reference['raw_sha256'], reference) == safe_source(raw.decode(), source_path='routes.py')
    assert proof(store, reference)['complete'] is False
    assert reference['raw_sha256'] == hashlib.sha256(raw).hexdigest()


def test_expiry_cleanup_and_discard_apply_to_the_same_private_proof_task(sample):
    store, clock = sample
    first = captured(store, b'value = "private-one"\n')
    clock[0] += preimages.TTL
    with pytest.raises(TaskPreimageUnavailable) as rejected:
        proof(store, first)
    assert rejected.value.reason_code == 'TASK_PREIMAGE_EXPIRED'
    second = captured(store, b'value = "private-two"\n', task=SECOND)
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT task_ref FROM task_preimage_semantics').fetchall() == [(SECOND,)]
    store.discard(SECOND)
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT task_ref FROM task_preimage_semantics').fetchall() == []
    with pytest.raises(TaskPreimageUnavailable):
        proof(store, second)


def test_writer_rolls_back_source_and_private_proof_together(sample):
    store, _ = sample
    with pytest.raises(RuntimeError):
        with store.writer(FIRST) as writer:
            raw = b'value = "private"\n'
            reference = writer.put('routes.py', raw, safe_source(raw.decode(), source_path='routes.py'))
            raise RuntimeError('fixture transaction abort')
    with pytest.raises(TaskPreimageUnavailable) as rejected:
        proof(store, reference)
    assert rejected.value.reason_code == 'TASK_PREIMAGE_SOURCE_UNAVAILABLE'


@pytest.mark.parametrize('path,first,second', [
    ('main.go', '//go:build debug', '//go:build production'),
    ('main.go', '// +build debug', '// +build production'),
    ('main.go', '//go:embed before.txt', '//go:embed after.txt'),
    ('app.py', '# coding: utf-8', '# coding: latin-1'),
    ('app.py', '# noqa: F401', '# noqa: E501'),
    ('app.py', '# nosec B301', '# nosec B302'),
    ('app.py', '# nosemgrep: before', '# nosemgrep: after'),
    ('app.py', '# gitleaks:allow before', '# gitleaks:allow after'),
    ('app.py', '# type: ignore[before]', '# type: ignore[after]'),
    ('app.ts', '// @ts-ignore before', '// @ts-ignore after'),
    ('app.ts', '/// <reference path="before.ts" />', '/// <reference path="after.ts" />'),
    ('app.js', '/* webpackChunkName: "before" */', '/* webpackChunkName: "after" */'),
    ('app.js', '//# sourceMappingURL=before.js.map', '//# sourceMappingURL=after.js.map'),
    ('app.c', '/* pragma warning before */', '/* pragma warning after */'),
])
def test_directive_only_change_is_private_semantic_evidence_and_partial_after_all_reads(sample, path, first, second):
    from security_runtime import task_review_plan as plans
    store, _ = sample
    old, new = (first + '\nallowed = guard.check(user)\n').encode(), (second + '\nallowed = guard.check(user)\n').encode()
    before = dict(hashes={path: hashlib.sha256(old).hexdigest()}, texts={path: safe_source(old.decode(), source_path=path)},
        semantic_proofs={path: store.semantic_proof(FIRST, path, old)})
    after = dict(hashes={path: hashlib.sha256(new).hexdigest()}, texts={path: safe_source(new.decode(), source_path=path)},
        semantic_proofs={path: store.semantic_proof(FIRST, path, new)})
    assert before['texts'] == after['texts']
    assert 1 in before['semantic_proofs'][path]['semantic_lines']
    assert before['semantic_proofs'] != after['semantic_proofs']
    record = dict(task_ref=FIRST, review_protocol=3, baseline=before, end=after, changes=[dict(path=path, change='MODIFIED')], static_attempts=1)
    unit = plans.build_plan(record, now=1, protocol_version=3)['units'][0]
    assert any(gap['reason'] == 'SANITIZED_CHANGE_UNOBSERVABLE' and gap['start_line'] == 1
               for gap in unit['evidence_gaps'])
    for index, window in enumerate(unit['required_windows']):
        plans.record_read(record, dict(window, evidence_id=f'private-directive-{index}', total_lines=2), now=2)
    assert plans.submit_units(record, [unit['unit_id']], 'REVIEWED', [], now=3)['coverage'] == 'PARTIAL'


def test_complete_ordinary_comment_proof_still_allows_full_review_and_legacy_is_conservative(sample):
    from security_runtime.task_review_windows import adaptive_windows
    store, _ = sample
    path = 'app.py'
    old, new = b'# first ordinary explanation\nallowed = guard.check(user)\n', b'# another ordinary explanation\nallowed = guard.check(user)\n'
    record = dict(task_ref=FIRST,
        baseline=dict(hashes={path: hashlib.sha256(old).hexdigest()}, texts={path: safe_source(old.decode(), source_path=path)},
                      semantic_proofs={path: store.semantic_proof(FIRST, path, old)}),
        end=dict(hashes={path: hashlib.sha256(new).hexdigest()}, texts={path: safe_source(new.decode(), source_path=path)},
                 semantic_proofs={path: store.semantic_proof(FIRST, path, new)}))
    assert adaptive_windows(record, dict(path=path, change='MODIFIED')) == ([], [])
    record['baseline'].pop('semantic_proofs')
    windows, gaps = adaptive_windows(record, dict(path=path, change='MODIFIED'))
    assert windows and any(gap['reason'] == 'SEMANTIC_LINE_PROOF_UNAVAILABLE' for gap in gaps)


@pytest.mark.parametrize('path', ['app.js', 'app.ts'])
def test_uncertain_javascript_regex_comment_tokens_remain_private_opaque_semantics(sample, path):
    store, _ = sample
    old = b'const pattern = /[//]first/;\n'
    new = b'const pattern = /[//]other/;\n'
    assert safe_source(old.decode(), source_path=path) == safe_source(new.decode(), source_path=path)
    before, after = store.semantic_proof(FIRST, path, old), store.semantic_proof(FIRST, path, new)
    assert before['complete'] and after['complete']
    assert before['semantic_lines'].keys() == {1}
    assert before['semantic_lines'] != after['semantic_lines']
    assert store.semantic_proof(FIRST, path, b'const checked = guard.check(user); // ordinary explanation\n')['semantic_lines'] == {}


@pytest.mark.parametrize('limit', ['MAX_FILE_PROOF_BYTES', 'MAX_TASK_PROOF_BYTES', 'MAX_WORKSPACE_PROOF_BYTES'])
def test_small_proof_long_metadata_is_counted_against_optional_budget(sample, monkeypatch, limit):
    store, _ = sample
    path = ('private_scope_segment/' * 15) + 'routes.py'
    raw = b'checked = guard.check(user)\n'
    assert len(fingerprints.encode_proof(store.semantic_proof(FIRST, path, raw))) < 300
    monkeypatch.setattr(fingerprints, limit, 300)
    reference = captured(store, raw, path)
    assert store.read(FIRST, path, reference['raw_sha256'], reference)
    assert proof(store, reference)['complete'] is False
    with sqlite3.connect(store.path) as db:
        assert db.execute('SELECT count(*) FROM task_preimage_semantics').fetchone()[0] == 0
