"""Real-file acceptance for finite, hash-only product observations.

These checks do not establish atomic project snapshots, task preimages, scanner
coverage, or a desktop Host's trusted session identity.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
from pathlib import Path

import pytest
from security_runtime.product_epoch_capture import platform_supported

pytestmark = pytest.mark.skipif(not platform_supported(), reason="Historical product epochs require POSIX descriptor observations")

from security_runtime.hook_state import HookStateStore
from security_runtime.product_epoch_capture import StableHashReader
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security_state import CONTRACT, TaskSecurityStore


@pytest.fixture
def observation(tmp_path, monkeypatch):
    root = tmp_path.resolve() / 'project'
    root.mkdir()
    hooks = HookStateStore(tmp_path.resolve() / 'private-state')
    instant = [1_000_000.0]
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path.resolve() / 'runtime'))

    def forbid_scan(*args, **kwargs):
        pytest.fail('Product comparison observations must not run security scanners')

    monkeypatch.setattr('security_runtime.runtime.SecurityRuntime.scan', forbid_scan)
    return root, hooks, instant


def service(observation, **policy):
    root, hooks, instant = observation
    return ProductEpochService(hooks, root, now=lambda: instant[0], policy=policy or None)


def owner(index=0):
    return session_owner('codex', f'product-epoch-acceptance-{index}')


def finish(current, actor=None, *, maximum_steps=512):
    actor = owner() if actor is None else actor
    result = current.ensure(actor)
    ref = result['epoch_ref']
    for turns in range(maximum_steps):
        assert result['epoch_ref'] == ref
        if result['state'] == 'SEALED':
            return result, turns
        result = current.step(actor)
    pytest.fail(f'Finite observation did not seal in {maximum_steps} bounded steps')


def lookup(current, ref, names):
    found = {}
    for offset in range(0, len(names), 128):
        page = current.lookup(ref, names[offset:offset+128])
        assert page['epoch_ref'] == ref
        rows = page['results']
        requested = names[offset:offset+128]
        assert len(rows) == len(requested)
        assert {row['path'] for row in rows} == set(requested)
        found.update((row['path'], row) for row in rows)
    return found


def private_bytes(hooks):
    if not hooks.directory.exists():
        return {}
    return {path.relative_to(hooks.directory).as_posix(): path.read_bytes()
            for path in hooks.directory.rglob('*') if path.is_file()}


def assert_observation_contract(result):
    assert result['consistency'] == 'OBSERVED_ONLY'
    assert result['representation'] == 'HASH_ONLY'
    assert result['body_retained'] is False
    assert result['source_bodies_available'] is False
    assert result['strict_task_preimage_eligible'] is False
    assert result['project_inventory_complete'] is False
    assert 'task_ref' not in result
    assert 'task_owner' not in result


@pytest.mark.parametrize('count', [1001, 10_000])
def test_real_file_inventory_crosses_1000_and_10000_without_a_prefix(observation, count):
    root, hooks, _ = observation
    raw = b'value = 1\n'
    names = [f'source_{index:05d}.py' for index in range(count)]
    for name in names:
        (root/name).write_bytes(raw)
    current = service(observation)
    result, turns = finish(current, maximum_steps=math.ceil(count/128)*6+32)
    assert turns > 1
    assert result['scope_closed'] is True
    assert result['comparison_available'] is True
    assert result['counts']['members'] == result['counts']['observed'] == count
    assert result['counts']['pending_files'] == result['counts']['pending_directories'] == 0
    assert_observation_contract(result)
    rows = lookup(current, result['epoch_ref'], names)
    expected = hmac.new(hooks.key(root), b'hook-file-v1'+raw, hashlib.sha256).hexdigest()
    assert len(rows) == count
    assert all(row['status'] == 'OBSERVED' and row['hash'] == expected for row in rows.values())
    assert rows[names[-1]]['hash'] == expected


def test_continual_creation_has_a_finite_scope_and_does_not_chase_new_names(observation):
    root, _, instant = observation
    for index in range(80):
        (root/f'initial_{index:03d}.py').write_text('value = 1\n', encoding='utf-8')
    current = service(observation, scope_seconds=2.0, step_files=4)
    result = current.ensure(owner())
    ref = result['epoch_ref']
    sealed_members = None
    late_names = []
    for index in range(128):
        name = f'growing_{index:03d}.py'
        (root/name).write_text('value = 2\n', encoding='utf-8')
        if result['scope_closed']:
            late_names.append(name)
            if sealed_members is None:
                sealed_members = result['counts']['members']
        instant[0] += 0.25
        result = current.step(owner(index % 3))
        assert result['epoch_ref'] == ref
        if sealed_members is not None:
            assert result['counts']['members'] == sealed_members
        if result['state'] == 'SEALED':
            break
    else:
        pytest.fail('Continually growing live source did not leave capture in a bounded number of steps')
    assert result['scope_closed'] is True
    assert_observation_contract(result)
    # Create one definitely post-seal source even when one turn closed and
    # completed the observation together.
    late_name = 'created_after_epoch_seal.py'
    (root/late_name).write_text('value = 3\n', encoding='utf-8')
    late_names.append(late_name)
    retained = copy.deepcopy(result)
    assert current.ensure(owner(9))['epoch_ref'] == ref
    assert current.status()['counts'] == retained['counts']
    rows = lookup(current, ref, late_names)
    assert all(row['status'] == 'FIRST_OBSERVED_ORDER_UNKNOWN' for row in rows.values())
    assert all('hash' not in row for row in rows.values())


def test_sealed_hashes_never_change_when_live_files_are_edited_or_added(observation):
    root, hooks, _ = observation
    (root/'accepted.py').write_bytes(b'accepted = 1\n')
    current = service(observation)
    original, _ = finish(current)
    ref = original['epoch_ref']
    before = current.lookup(ref, ['accepted.py'])
    expected = hmac.new(hooks.key(root), b'hook-file-v1accepted = 1\n', hashlib.sha256).hexdigest()
    assert before['results'][0]['hash'] == expected
    private = private_bytes(hooks)
    for index in range(10):
        (root/'accepted.py').write_text(f'accepted = {index+2}\n', encoding='utf-8')
        (root/f'later_{index}.py').write_text('later = True\n', encoding='utf-8')
        assert current.ensure(owner(index % 3))['epoch_ref'] == ref
        assert current.step(owner(index % 3))['counts'] == original['counts']
        assert current.lookup(ref, ['accepted.py']) == before
    assert private_bytes(hooks) == private
    later = current.lookup(ref, ['later_9.py'])['results'][0]
    assert later['status'] == 'FIRST_OBSERVED_ORDER_UNKNOWN' and 'hash' not in later


def test_first_accepted_hash_remains_original_while_other_members_are_still_capturing(observation):
    root, _, _ = observation
    names = [f'member_{index}.py' for index in range(3)]
    for name in names:
        (root/name).write_bytes(b'value = 1\n')
    current = service(observation, step_files=1)
    result = current.ensure(owner())
    ref = result['epoch_ref']
    for _ in range(16):
        result = current.step(owner())
        if result['counts']['observed'] == 1:
            break
    else:
        pytest.fail('Could not witness the first immutable per-file observation')
    assert result['state'] != 'SEALED'
    rows = lookup(current, ref, names)
    accepted = next(row for row in rows.values() if row['status'] == 'OBSERVED')
    original = accepted['hash']
    (root/accepted['path']).write_bytes(b'value = edited_after_first_acceptance\n')
    sealed, _ = finish(current)
    assert sealed['epoch_ref'] == ref
    assert sealed['counts']['observed'] == 3
    assert_observation_contract(sealed)
    assert current.lookup(ref, [accepted['path']])['results'][0]['hash'] == original


def test_continual_editing_stops_retrying_one_path_without_discarding_stable_observations(observation):
    root, _, instant = observation
    (root/'editing.py').write_bytes(b'value = 1\n'*24)
    (root/'stable.py').write_bytes(b'stable = True\n')
    mutations = []

    class EditingReader(StableHashReader):
        def __init__(self, folder, key, path, *, expected_root_identity=None):
            super().__init__(folder, key, path, expected_root_identity=expected_root_identity)
            self.moving_source = Path(folder)/path

        def _read_chunk(self, size):
            raw = super()._read_chunk(size)
            if self.moving_source.name == 'editing.py':
                # Mutate the actual source between its bounded read and the
                # reader's stability check; this is not a simulated hash row.
                with self.moving_source.open('ab') as stream:
                    stream.write(b'# still editing\n')
                mutations.append(len(raw))
            return raw

    current = service(observation, scope_seconds=2.0, step_files=4, step_bytes=64)
    current._reader_factory = EditingReader
    result = current.ensure(owner())
    ref = result['epoch_ref']
    for _ in range(64):
        instant[0] += 0.125
        result = current.step(owner())
        assert result['epoch_ref'] == ref
        if result['state'] == 'SEALED':
            break
    else:
        pytest.fail('Continuously edited member caused unlimited capture retries')
    assert mutations and len(mutations) <= 12
    assert result['counts']['members'] == 2
    assert result['counts']['observed'] == 1
    assert result['counts']['gaps'] >= 1
    assert result['comparison_available'] is True
    assert_observation_contract(result)
    rows = lookup(current, ref, ['editing.py', 'stable.py'])
    assert rows['editing.py']['status'] == 'GAP'
    assert 'hash' not in rows['editing.py']
    assert rows['stable.py']['status'] == 'OBSERVED'


def test_three_sessions_share_product_epoch_without_mutating_their_task_bindings(observation):
    root, hooks, instant = observation
    (root/'source.py').write_text('value = 1\n', encoding='utf-8')
    hooks.key(root)
    tasks = TaskSecurityStore(hooks, root, now=lambda: instant[0])
    stored = []
    for index in range(3):
        # Valid isolated fixture records; no live Runtime task is created.
        baseline = dict(hashes={'source.py': hashlib.sha256(b'value = 1\n').hexdigest()},
            inventory=['source.py'], inventory_complete=True, texts={}, preimages={},
            read_limitations=[], limitations=[], line_counts={'source.py': 1},
            redaction_version=3, text_unavailable={}, text_truncations={})
        stored.append(tasks.save(dict(contract=CONTRACT, task_ref='ts1-'+f'{index+1:032x}',
            task_key=f'fixture-task-{index}', workspace=str(root), task_owner=owner(index),
            phase='ACTIVE', generation=0, created_at=instant[0], review_protocol=3,
            baseline=baseline), new=True))
    task_bytes = tasks.path.read_bytes()
    first = service(observation).ensure(owner(0))
    for index in (1, 2):
        joined = service(observation).ensure(owner(index))
        assert joined['epoch_ref'] == first['epoch_ref']
        assert joined['policy_digest'] == first['policy_digest']
    current = service(observation)
    result, _ = finish(current, owner(2))
    assert result['epoch_ref'] == first['epoch_ref']
    assert_observation_contract(result)
    assert tasks.path.read_bytes() == task_bytes
    for expected in stored:
        assert tasks.get(expected['task_ref']) == expected


def test_status_and_lookup_are_read_only_when_absent_and_after_sealing(observation):
    root, hooks, _ = observation
    (root/'source.py').write_text('value = 1\n', encoding='utf-8')
    current = service(observation)
    assert not hooks.directory.exists()
    empty = current.status()
    assert empty['comparison_available'] is False
    assert not hooks.directory.exists()
    with pytest.raises(ValueError):
        current.lookup('pe1-'+'a'*32, ['source.py'])
    assert not hooks.directory.exists()
    result, _ = finish(current)
    before = private_bytes(hooks)
    for _ in range(3):
        assert current.status()['epoch_ref'] == result['epoch_ref']
        current.lookup(result['epoch_ref'], ['source.py', 'unknown.py'])
    assert private_bytes(hooks) == before


def test_product_hash_observation_retains_no_source_body_or_task_evidence(observation):
    root, hooks, _ = observation
    sentinel = b'PRODUCT_EPOCH_SOURCE_BODY_MUST_NOT_BE_RETAINED_0a93b4c7'
    (root/'source.py').write_bytes(b'fixture = "'+sentinel+b'"\n')
    current = service(observation)
    result, _ = finish(current)
    packet = current.lookup(result['epoch_ref'], ['source.py'])
    assert packet['results'][0]['status'] == 'OBSERVED'
    assert_observation_contract(result)
    serialized = json.dumps([result, packet], sort_keys=True).encode()
    assert sentinel not in serialized
    assert b'"evidence_id"' not in serialized
    assert b'"task_ref"' not in serialized
    assert all(sentinel not in raw for raw in private_bytes(hooks).values())


def test_unknown_current_path_does_not_prove_added_after_the_observation(observation):
    root, _, _ = observation
    (root/'known.py').write_text('known = True\n', encoding='utf-8')
    current = service(observation)
    result, _ = finish(current)
    (root/'unknown.py').write_text('observed_later = True\n', encoding='utf-8')
    missing = current.lookup(result['epoch_ref'], ['unknown.py', 'never_seen.py'])['results']
    assert [row['status'] for row in missing] == ['FIRST_OBSERVED_ORDER_UNKNOWN']*2
    assert all('hash' not in row and 'evidence_id' not in row for row in missing)
    assert all(row.get('change') != 'ADDED' for row in missing)
