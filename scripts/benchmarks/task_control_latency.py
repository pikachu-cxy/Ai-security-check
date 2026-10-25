"""Compare offline control reads/acks; no MCP, model, scanner or host install.

Synthetic file maps live in a temporary private store. This measures storage
operations only, not live baseline capture or end-to-end development latency.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import statistics
import tempfile
import time

from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.projection import enqueue
from security_runtime.tasks.security_state import TaskSecurityStore
from security_runtime.tasks.snapshot_pages import GC_CONTRACT, GC_POLICY


def summary(values):
    return dict(median_ms=round(1000 * statistics.median(values), 3),
                max_ms=round(1000 * max(values), 3), samples=len(values))


def measure(function):
    started = time.perf_counter()
    result = function()
    return result, time.perf_counter() - started


def run(files=6000, repeats=10):
    if files < 1 or repeats < 1:
        raise ValueError('File and repeat counts must be positive')
    with tempfile.TemporaryDirectory(prefix='task-control-benchmark-') as temporary:
        base = Path(temporary).resolve()
        root = base / 'project'
        root.mkdir()
        previous = os.environ.get('SECURITY_RUNTIME_STATE_DIR')
        os.environ['SECURITY_RUNTIME_STATE_DIR'] = str(base / 'runtime')
        try:
            hooks = HookStateStore(base / 'state')
            hooks.key(root)
            state = TaskSecurityStore(hooks, root)
            names = [f'g{i // 100:03}/m{i:05}.py' for i in range(files)]
            snapshot = dict(hashes={name: hashlib.sha256(name.encode()).hexdigest() for name in names},
                texts={name: ['value = 1'] for name in names}, preimages={},
                inventory=names, read_priority=[], line_counts={name: 1 for name in names},
                text_truncations={}, text_unavailable={}, limitations=[],
                read_limitations=[], inventory_complete=True, redaction_version=3)
            record = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY,
                task_ref='ts1-' + 'a' * 32, task_key='offline-timing',
                workspace=str(root), task_owner=session_owner('codex', 'offline-timing'),
                check_policy=POLICY, phase='COMPLETE', generation=0, created_at=time.time(),
                review_protocol=3, baseline=snapshot, end=copy.deepcopy(snapshot),
                static={'findings': []}, review={'findings': [], 'coverage': 'REVIEWED'})
            _, setup_seconds = measure(lambda: state.save(enqueue(record), new=True))
            original = state.get(record['task_ref'])
            control_bytes = state.path.read_bytes()
            candidate = copy.deepcopy(original)
            projection = candidate['ledger_projection']
            projection['state'] = 'APPLIED'
            for key in ('host_updates', 'expected_versions'):
                projection.pop(key, None)
            timings = {name: [] for name in ('full_read', 'header_read', 'full_ack', 'control_ack')}
            for _ in range(repeats):
                full, elapsed = measure(lambda: state.get(record['task_ref']))
                timings['full_read'].append(elapsed)
                head, elapsed = measure(lambda: state.get(record['task_ref'], headers=True))
                timings['header_read'].append(elapsed)
                assert head['generation'] == full['generation']
                assert head['baseline']['paged_entries'] == full['baseline']['paged_entries']
                for name, operation in (('full_ack', state.save), ('control_ack', state.save_projection)):
                    # Restore only this isolated fixture's control transaction.
                    # The acknowledged update cannot change its sealed sources.
                    state.path.write_bytes(control_bytes)
                    saved, elapsed = measure(lambda: operation(copy.deepcopy(candidate)))
                    timings[name].append(elapsed)
                    assert saved['ledger_projection']['state'] == 'APPLIED'
                    assert saved['baseline'] == original['baseline']
                    assert saved['end'] == original['end']
                state.path.write_bytes(control_bytes)
            result = dict(scope='OFFLINE_SYNTHETIC_STORAGE_ONLY', files=files,
                          fixture_setup_ms=round(1000 * setup_seconds, 3),
                          operations={name: summary(values) for name, values in timings.items()})
            result['median_reduction_percent'] = {
                'header_read': round(100 * (1 - statistics.median(timings['header_read']) /
                                            statistics.median(timings['full_read'])), 2),
                'control_ack': round(100 * (1 - statistics.median(timings['control_ack']) /
                                            statistics.median(timings['full_ack'])), 2)}
            return result
        finally:
            if previous is None:
                os.environ.pop('SECURITY_RUNTIME_STATE_DIR', None)
            else:
                os.environ['SECURITY_RUNTIME_STATE_DIR'] = previous


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--files', type=int, default=6000)
    parser.add_argument('--repeats', type=int, default=10)
    arguments = parser.parse_args()
    print(json.dumps(run(arguments.files, arguments.repeats), ensure_ascii=False, indent=2))
