"""Adaptive plans keep every change while bounding ambiguous diff work."""
import copy
import hashlib
import random
import json

import pytest

from security_runtime.task_review import windows as windows
from security_runtime.local_evidence import MAX_LINE_CHARS, safe_source
from security_runtime.tasks.preimage_fingerprints import make_proof


def record(old, new, kind='MODIFIED'):
    def snapshot(lines):
        return dict(hashes={'main.py': hashlib.sha256('\n'.join(lines).encode()).hexdigest()},
                    texts={'main.py': lines}, line_counts={'main.py': len(lines)})
    return dict(baseline={} if kind == 'ADDED' else snapshot(old),
                end={} if kind == 'DELETED' else snapshot(new)), dict(path='main.py', change=kind)


def selected(windows_, version, line):
    return any(item['location_version'] == version
               and item['start_line'] <= line <= item['end_line'] for item in windows_)


def assert_exact_partition(old, new):
    """Every omitted segment must be identical in order in both versions."""
    a = b = 0
    for x, y, z, w in windows._changed_ranges(old, new):
        assert a <= x <= y <= len(old) and b <= z <= w <= len(new)
        assert old[a:x] == new[b:z]
        a, b = y, w
    assert old[a:] == new[b:]


def test_large_file_keeps_separate_beginning_middle_and_end_changes():
    old = [f'line_{i} = original_{i}' for i in range(20_001)]
    new = old.copy()
    positions = [0, 4_001, 10_000, 19_999, 20_000]
    for index in positions:
        new[index] = f'changed_{index}'
    source, change = record(old, new)
    original = copy.deepcopy(source)
    result, gaps = windows.adaptive_windows(source, change)
    assert not gaps and source == original
    assert sum(item['end_line'] - item['start_line'] + 1 for item in result) < 80
    for version in ('BEFORE_TASK', 'CURRENT_TASK_END'):
        assert all(selected(result, version, index + 1) for index in positions)
        assert not selected(result, version, 8_000)
    assert_exact_partition(old, new)


def test_large_insertions_and_deletions_keep_all_changed_lines_and_offsets():
    old = [f'line_{i}' for i in range(15_000)]
    new = ['new_start', *old[:4_000], *old[4_015:10_000], 'new_middle', *old[10_000:], 'new_end']
    source, change = record(old, new)
    result, gaps = windows.adaptive_windows(source, change)
    assert not gaps
    assert all(selected(result, 'BEFORE_TASK', i + 1) for i in range(4_000, 4_015))
    assert selected(result, 'CURRENT_TASK_END', 1)
    assert selected(result, 'CURRENT_TASK_END', new.index('new_middle') + 1)
    assert selected(result, 'CURRENT_TASK_END', len(new))
    assert_exact_partition(old, new)


def test_repeated_lines_with_unique_landmarks_do_not_require_whole_file():
    old = [line for i in range(15) for line in (['repeat'] * 1_000 + [f'anchor_{i}'])]
    new = old.copy()
    positions = [9, 6_050, 14_100]
    for index in positions:
        new[index] = f'changed_{index}'
    result, gaps = windows.adaptive_windows(*record(old, new))
    assert not gaps
    assert sum(item['end_line'] - item['start_line'] + 1 for item in result) < 100
    for version in ('BEFORE_TASK', 'CURRENT_TASK_END'):
        assert all(selected(result, version, index + 1) for index in positions)
    assert_exact_partition(old, new)


def test_large_ambiguous_repeated_gap_is_kept_in_full_without_quadratic_matcher(monkeypatch):
    old = ['repeat'] * 40_000
    new = old.copy()
    new[0], new[20_000], new[-1] = 'start', 'middle', 'end'
    def forbidden(*args, **kwargs):
        pytest.fail('A large repeated gap must not invoke SequenceMatcher')
    monkeypatch.setattr(windows, 'SequenceMatcher', forbidden)
    result, gaps = windows.adaptive_windows(*record(old, new))
    assert not gaps
    assert len(result) == 2
    assert all(item['start_line'] == 1 and item['end_line'] == len(old) for item in result)
    assert_exact_partition(old, new)


@pytest.mark.parametrize('kind,version', [('ADDED', 'CURRENT_TASK_END'), ('DELETED', 'BEFORE_DELETION')])
def test_added_and_deleted_bodies_are_never_compressed(kind, version):
    body = [f'line_{i}' for i in range(20_000)]
    result, gaps = windows.adaptive_windows(*record(body, body, kind))
    assert not gaps
    assert result == [dict(path='main.py', file_sha256=hashlib.sha256('\n'.join(body).encode()).hexdigest(),
                           location_version=version, start_line=1, end_line=len(body))]


def test_hash_only_masked_change_keeps_both_full_versions_and_unknown():
    body = ['before', 'credential = [REDACTED_SECRET]', 'after']
    source, change = record(body, body.copy())
    source['end']['hashes']['main.py'] = 'b' * 64
    result, gaps = windows.adaptive_windows(source, change)
    assert len(gaps) == 2 and all(item['reason'] == 'SEMANTIC_LINE_PROOF_UNAVAILABLE' for item in gaps)
    assert all(item['start_line'] == item['end_line'] == 2 for item in gaps)
    assert {item['location_version'] for item in result} == {'BEFORE_TASK', 'CURRENT_TASK_END'}
    assert all(item['start_line'] == 1 and item['end_line'] == len(body) for item in result)


def test_nearby_context_is_merged_but_distant_changes_remain_separate():
    old = [f'line_{i}' for i in range(100)]
    new = old.copy()
    for index in (10, 18, 70):
        new[index] = f'changed_{index}'
    result, gaps = windows.adaptive_windows(*record(old, new))
    assert not gaps
    assert len(result) == 4
    assert all(not selected(result, version, 45) for version in ('BEFORE_TASK', 'CURRENT_TASK_END'))


def test_small_gap_matcher_has_per_gap_and_cumulative_work_caps(monkeypatch):
    old, new = [], []
    for i in range(240):
        old.extend(['repeat'] * 100 + [f'anchor_{i}'])
        new.extend(['changed', *(['repeat'] * 98), 'changed', f'anchor_{i}'])
    original = windows.SequenceMatcher
    work = []
    def bounded(*args, **kwargs):
        left, right = args[1:3]
        work.append(len(left) * len(right))
        assert len(left) + len(right) <= windows.LOCAL_MAX_LINES
        assert work[-1] <= windows.LOCAL_PAIR_BUDGET
        assert sum(work) <= windows.TOTAL_PAIR_BUDGET
        return original(*args, **kwargs)
    monkeypatch.setattr(windows, 'SequenceMatcher', bounded)
    assert_exact_partition(old, new)
    assert 0 < len(work) < 240  # Later gaps are kept intact after the work cap.


def test_reordered_unique_anchors_keep_all_moved_ranges():
    old = [f'line_{i}' for i in range(16_000)]
    new = old[:100] + old[12_000:13_000] + old[100:12_000] + old[13_000:]
    result, gaps = windows.adaptive_windows(*record(old, new))
    assert not gaps
    assert all(selected(result, 'CURRENT_TASK_END', i + 1) for i in range(100, 1_100))
    assert all(selected(result, 'BEFORE_TASK', i + 1) for i in range(12_000, 13_000))
    assert_exact_partition(old, new)


def test_random_repeated_inputs_never_omit_a_different_segment():
    rng = random.Random(412_703)
    for length in (0, 1, 4, 45, 300, 1_200, 8_000):
        for _ in range(8):
            old = [rng.choice(('repeat_a', 'repeat_b', 'repeat_c')) for _ in range(length)]
            new = old.copy()
            for i in range(12):
                at = rng.randrange(len(new) + 1)
                new[at:at + rng.randrange(4)] = [f'new_{i}'] * rng.randrange(4)
            assert_exact_partition(old, new)


def test_missing_text_keeps_unresolved_full_range_and_missing_hash_is_explicit():
    source, change = record(['before'], ['after'])
    del source['baseline']['texts']
    del source['baseline']['line_counts']
    result, gaps = windows.adaptive_windows(source, change)
    assert not gaps
    assert result[0]['start_line'] == 1 and result[0]['end_line'] is None
    del source['baseline']['hashes']['main.py']
    result, gaps = windows.adaptive_windows(source, change)
    assert gaps == [dict(reason='SOURCE_VERSION_UNAVAILABLE', path='main.py', location_version='BEFORE_TASK')]
    assert all(item['location_version'] == 'CURRENT_TASK_END' for item in result)


def private_record(old, new):
    """Real sanitizer and native private proof, with synthetic source only."""
    def snapshot(lines):
        raw = ('\n'.join(lines)+'\n').encode()
        truncated = []
        sanitized = safe_source(raw.decode(), source_path='main.py', truncation_lines=truncated)
        return dict(hashes={'main.py': hashlib.sha256(raw).hexdigest()}, texts={'main.py': sanitized},
            text_truncations={'main.py': dict(lines=truncated)} if truncated else {},
            semantic_proofs={'main.py': make_proof(b'fixture-key-for-line-proof-only!!', 'fixture-workspace',
                'ts1-'+'f'*32, 'main.py', raw, sanitized_lines=sanitized)})
    return dict(baseline=snapshot(old), end=snapshot(new)), dict(path='main.py', change='MODIFIED')


def mixed_source():
    return ['def access_policy(user):', '    role_token = "fixture-reader-role"', '    return user.role == role_token',
        *[f'padding_{index} = helper_{index}(value_{index})' for index in range(60)],
        'def entry(user):', '    return policy.allow(user)']


def test_native_private_proof_locates_hidden_and_visible_changes_in_the_same_file():
    old = mixed_source()
    new = old.copy()
    new[1] = '    role_token = "fixture-admin-role"'
    new[-1] = '    return policy.enforce(user)'
    source, change = private_record(old, new)
    original = copy.deepcopy(source)
    result, gaps = windows.adaptive_windows(source, change)
    for version in ('BEFORE_TASK', 'CURRENT_TASK_END'):
        assert selected(result, version, 2) and selected(result, version, len(old))
        assert any(item['reason'] == 'SANITIZED_CHANGE_UNOBSERVABLE'
                   and item['location_version'] == version and item['start_line'] == item['end_line'] == 2
                   for item in gaps)
    assert source == original
    encoded = json.dumps(dict(windows=result, gaps=gaps))
    for snapshot in ('baseline', 'end'):
        for value in source[snapshot]['semantic_proofs']['main.py']['semantic_lines'].values():
            assert value not in encoded


def test_ordinary_visible_change_does_not_make_unchanged_opaque_lines_partial():
    old = mixed_source()
    new = old.copy()
    new[-1] = '    return policy.enforce(user)'
    result, gaps = windows.adaptive_windows(*private_record(old, new))
    assert not gaps
    for version in ('BEFORE_TASK', 'CURRENT_TASK_END'):
        assert selected(result, version, len(old))
        assert not selected(result, version, 2)


def test_native_proof_excludes_comment_only_changes_from_hidden_uncertainty():
    old = mixed_source()+['# previous explanatory note']
    new = old[:-1]+['# updated explanatory note with another length']
    result, gaps = windows.adaptive_windows(*private_record(old, new))
    assert not gaps and result
    assert selected(result, 'BEFORE_TASK', len(old))
    assert selected(result, 'CURRENT_TASK_END', len(new))


def test_an_inserted_line_moves_unchanged_private_fingerprints_without_a_false_hidden_gap():
    old = mixed_source()
    new = ['import policy', *old]
    result, gaps = windows.adaptive_windows(*private_record(old, new))
    assert not gaps
    assert selected(result, 'CURRENT_TASK_END', 1)
    assert not selected(result, 'CURRENT_TASK_END', len(new))


def test_new_log_string_is_visible_new_code_rather_than_a_blanket_hidden_change_gap():
    old = mixed_source()
    new = old[:-1]+['    logger.info("fixture-starting-request")', old[-1]]
    result, gaps = windows.adaptive_windows(*private_record(old, new))
    assert not gaps and selected(result, 'CURRENT_TASK_END', len(new)-1)


def test_visible_edit_on_same_line_cannot_hide_a_simultaneous_credential_edit():
    old = ['client(password="synthetic-old", endpoint="before")']
    new = ['client(password="synthetic-new", endpoint="after")']
    result, gaps = windows.adaptive_windows(*private_record(old, new))
    assert {item['location_version'] for item in gaps
            if item['reason'] == 'SANITIZED_CHANGE_UNOBSERVABLE'} == {'BEFORE_TASK', 'CURRENT_TASK_END'}
    assert selected(result, 'BEFORE_TASK', 1) and selected(result, 'CURRENT_TASK_END', 1)


@pytest.mark.parametrize('bad_proof', ['missing', 'incomplete', 'missing-marker-line'])
def test_legacy_or_unverifiable_before_proof_keeps_all_potential_hidden_ranges(bad_proof):
    old = mixed_source()
    new = old.copy()
    new[1], new[-1] = '    role_token = "fixture-admin-role"', '    return policy.enforce(user)'
    source, change = private_record(old, new)
    if bad_proof == 'missing':
        source['baseline'].pop('semantic_proofs')
    elif bad_proof == 'incomplete':
        source['baseline']['semantic_proofs']['main.py']['complete'] = False
    else:
        source['baseline']['semantic_proofs']['main.py']['semantic_lines'] = {}
    result, gaps = windows.adaptive_windows(source, change)
    assert all(selected(result, version, 2) and selected(result, version, len(old))
               for version in ('BEFORE_TASK', 'CURRENT_TASK_END'))
    assert any(item['reason'] == 'SEMANTIC_LINE_PROOF_UNAVAILABLE'
               and item['start_line'] == item['end_line'] == 2 for item in gaps)


@pytest.mark.parametrize('before_proof', [True, False])
def test_truncated_semantic_tail_is_not_hidden_by_a_distant_visible_change(before_proof):
    old = mixed_source()
    old[1] = 'policy = '+ ' + '.join(f'variable_{index}' for index in range(100))+' + previous_guard'
    new = old.copy()
    new[1] = old[1].replace('previous_guard', 'different_guard')
    new[-1] = '    return policy.enforce(user)'
    source, change = private_record(old, new)
    if not before_proof:
        source['baseline'].pop('semantic_proofs')
        source['baseline'].pop('text_truncations')  # Legacy max-length fallback.
    result, gaps = windows.adaptive_windows(source, change)
    assert all(selected(result, version, 2) for version in ('BEFORE_TASK', 'CURRENT_TASK_END'))
    reason = 'SANITIZED_CHANGE_UNOBSERVABLE' if before_proof else 'SEMANTIC_LINE_PROOF_UNAVAILABLE'
    assert any(item['reason'] == reason and item['start_line'] == 2 for item in gaps)


def test_existing_plan_without_semantic_method_marker_remains_partial_without_reset():
    from security_runtime.task_review.plan import build_plan, finalize_plan, record_read, submit_units
    from test_task_review_plan import task
    source = task({'main.py': ['old = policy.allow(user)']}, {'main.py': ['new = policy.enforce(user)']})
    plan = build_plan(source, protocol_version=3, now=1)
    for index, window in enumerate(plan['units'][0]['required_windows']):
        record_read(source, dict(window, evidence_id=f'issued-{index}', total_lines=1), now=2)
    submit_units(source, [plan['units'][0]['unit_id']], 'REVIEWED', [], now=3)
    assert finalize_plan(source, now=4)['coverage'] == 'REVIEWED'
    plan.pop('semantic_coverage_version')
    before = copy.deepcopy(source)
    result = finalize_plan(source, now=5)
    assert result['coverage'] == 'PARTIAL'
    assert any(item['reason'] == 'SEMANTIC_PLANNING_VERSION_UNAVAILABLE' for item in result['gaps'])
    assert source == before


def test_marker_literals_in_source_do_not_create_hidden_change_gaps():
    old = ['label = "[REDACTED_SECRET]"', 'allowed = old_policy(user)']
    new = ['label = "[REDACTED_LITERAL]"', 'allowed = new_policy(user)']
    source, change = private_record(old, new)
    result, gaps = windows.adaptive_windows(source, change)
    assert not gaps
    assert all(selected(result, version, 1) and selected(result, version, 2)
               for version in ('BEFORE_TASK', 'CURRENT_TASK_END'))


def test_legacy_marker_literals_without_provenance_remain_conservative():
    source, change = private_record(['label = "[REDACTED_SECRET]"'], ['label = "[REDACTED_LITERAL]"'])
    proof = source['baseline']['semantic_proofs']['main.py']
    proof['version'] = 1
    proof.pop('literal_marker_lines')
    _, gaps = windows.adaptive_windows(source, change)
    assert any(item['reason'] == 'SEMANTIC_LINE_PROOF_UNAVAILABLE' for item in gaps)


def test_marker_literal_beside_changed_credential_keeps_hidden_change_gap():
    old = ['label = "[REDACTED_SECRET]"; password = "private-before"']
    new = ['label = "[REDACTED_LITERAL]"; password = "private-after"']
    source, change = private_record(old, new)
    assert source['baseline']['semantic_proofs']['main.py']['literal_marker_lines'] == []
    _, gaps = windows.adaptive_windows(source, change)
    assert {item['location_version'] for item in gaps
            if item['reason'] == 'SANITIZED_CHANGE_UNOBSERVABLE'} == {'BEFORE_TASK', 'CURRENT_TASK_END'}
