"""Measure the installed Codex Hook on isolated, signed synthetic task pages.

Both arms use the same build and complete return-boundary timer. The comparison
arm restores only the previous RECORDED_PENDING full-read branch, because the
unfixed Windows build cannot create these pages. This is a local Hook/storage
comparison, not a desktop, model, scanner, or whole-development benchmark.
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
from unittest.mock import patch

from security_runtime.build_identity import build_identity
import security_runtime.codex_mcp_hook as transport
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.tasks.activity import ActivityStore, POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security_state import TaskSecurityStore
from security_runtime.tasks.snapshot_pages import GC_CONTRACT, GC_POLICY


class NoScanner:
    def scan(self, *args, **kwargs):
        raise AssertionError('An edit under TASK_CLOSEOUT_V1 must not scan')


def summary(values):
    return dict(samples=len(values), median_ms=round(statistics.median(values), 3),
                max_ms=round(max(values), 3))


def run(files=6000, repeats=10):
    if files < 1 or repeats < 1:
        raise ValueError('Positive file and repeat counts required')
    with tempfile.TemporaryDirectory(prefix='hook-latency-') as temporary:
        base = Path(temporary).resolve()
        root = base / 'project'
        root.mkdir()
        previous = os.environ.get('SECURITY_RUNTIME_STATE_DIR')
        os.environ['SECURITY_RUNTIME_STATE_DIR'] = str(base / 'runtime')
        try:
            hooks = HookStateStore(base / 'state')
            hooks.key(root)
            state = TaskSecurityStore(hooks, root)
            names = [f'src/g{i // 100:03}/m{i:05}.py' for i in range(files)]
            snapshot = dict(hashes={name: hashlib.sha256(name.encode()).hexdigest() for name in names},
                texts={name: ['value = 1'] for name in names}, preimages={}, inventory=names,
                read_priority=[], line_counts={name: 1 for name in names}, text_truncations={},
                text_unavailable={}, limitations=[], read_limitations=[], inventory_complete=True,
                redaction_version=3)
            session = 'isolated-hook-benchmark'
            owner = session_owner('codex', session)
            record = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY,
                task_ref='ts1-' + 'a' * 32, task_key='isolated-hook-benchmark',
                workspace=str(root), task_owner=owner, check_policy=POLICY,
                phase='ACTIVE', generation=0, created_at=time.time(), review_protocol=3,
                baseline=snapshot, end=copy.deepcopy(snapshot))
            started = time.perf_counter()
            state.save(record, new=True)
            setup_ms = round(1000 * (time.perf_counter() - started), 3)
            activity = ActivityStore(hooks, root)
            activity.activate(owner, record['task_ref'], expected_generation=0,
                              created_at=record['created_at'])
            core = HookCoordinator(NoScanner(), hooks)
            binding = WorkspaceBinding.create(root, 'generic-mcp')
            task_bytes = state.path.read_bytes()
            original = transport._record_task_hook

            def old_record(hooks, root, result, decision):
                if result.get('status') == 'RECORDED_PENDING':
                    ref = result.get('security_task_ref')
                    return (TaskSecurityStore(hooks, root).get(ref) if ref else None), 'ACTIVITY_RECORDED'
                return original(hooks, root, result, decision)

            timings = {arm: {key: [] for key in ('wall', 'reported_total', 'task_recording', 'feedback')}
                       for arm in ('previous_full_read', 'current_header_read')}
            call_id = 0

            def sample(arm, *, warmup=False):
                nonlocal call_id
                call_id += 1
                function = old_record if arm == 'previous_full_read' else original
                with patch.object(transport, '_record_task_hook', function):
                    started = time.perf_counter()
                    result = transport.handle_codex_hook('PostToolUse', str(root), session, 'Edit',
                        {'file_path': names[0]}, binding=binding, coordinator=core,
                        turn_id='isolated-turn', tool_use_id=f'call-{call_id}')
                    wall = 1000 * (time.perf_counter() - started)
                assert result['status'] == 'RECORDED_PENDING', result.get('reason')
                assert not result['scanner_run'] and result['hook_check_recording'] == 'ACTIVITY_RECORDED'
                assert result['task_delivery']['task_pending']
                assert transport.codex_hook_output(result) == {}
                assert result['timing_ms']['hook_total'] <= wall + 1
                if not warmup:
                    values = (wall, result['timing_ms']['hook_total'],
                              result['timing_ms']['task_recording'], result['timing_ms']['feedback_processing'])
                    for key, value in zip(timings[arm], values):
                        timings[arm][key].append(value)

            for arm in timings:
                sample(arm, warmup=True)
            for index in range(repeats):
                order = list(timings) if index % 2 == 0 else list(reversed(timings))
                for arm in order:
                    sample(arm)
            assert state.path.read_bytes() == task_bytes
            assert activity.summary(record['task_ref'])['seq'] == call_id
            full = state.get(record['task_ref'])
            assert full['baseline']['hashes'] == snapshot['hashes']
            assert full['end']['hashes'] == snapshot['hashes']
            result = dict(scope='ISOLATED_REAL_HOOK_SYNTHETIC_TASK_PAGES',
                comparison='SAME_BUILD_PREVIOUS_FULL_READ_BRANCH_VS_CURRENT_HEADER_READ',
                build=build_identity(), files=files, repeats=repeats, fixture_setup_ms=setup_ms,
                operations={arm: {key: summary(values) for key, values in rows.items()}
                            for arm, rows in timings.items()}, scanner_calls=0,
                activity_events=call_id, source_maps_unchanged=True, task_control_unchanged=True)
            old = statistics.median(timings['previous_full_read']['wall'])
            new = statistics.median(timings['current_header_read']['wall'])
            result['hook_wall_median_reduction_percent'] = round(100 * (1 - new / old), 2)
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
    parser.add_argument('--output', type=Path)
    arguments = parser.parse_args()
    report = json.dumps(run(arguments.files, arguments.repeats), ensure_ascii=False, indent=2)
    if arguments.output:
        arguments.output.write_text(report + '\n', encoding='utf-8')
    print(report)
