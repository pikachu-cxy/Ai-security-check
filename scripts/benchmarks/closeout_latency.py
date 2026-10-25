"""Isolated capture/prepare timing; fixture detector, no MCP or installed scanners.

Run the same script against two PYTHONPATH source trees. All files and signed
stores are temporary. Samples measure controller/storage operations, not desktop
latency, model reasoning or actual scanning. Background worker launch is disabled.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time
import uuid

from security_runtime.hook_state import HookStateStore
from security_runtime.local_evidence import WorkspaceReader
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.queued_closeout import enqueue, execute_one, status
from security_runtime.tasks import queued_inputs
from security_runtime.tasks import queued_closeout


class FixtureDetector:
    """Only the provider result is simulated; original input guards still run."""

    def scan(self, root, mode, *, request, execution, **kwargs):
        from security_runtime.scan_input import capture_scan_input
        with capture_scan_input(request, private_parent=execution.private_parent,
                source_root=execution.source_root, on_created=execution.input_created,
                on_removed=execution.input_removed) as view:
            execution.input_ready(view)
            result = ScanResult('fixture-' + uuid.uuid4().hex, mode,
                TargetProfile(str(root), files=request.requested_files), 'SUCCESS', [],
                [ScannerRun('fixture-only', '0', 'SUCCESS', 0)], '', '', 0,
                coverage='SCOPED', capability_results={'code': 'SUCCESS'})
            execution.after_scan(view, result)
            return result


def measured(call):
    start = time.perf_counter()
    result = call()
    return result, round(1000*(time.perf_counter()-start), 3)


def sample(base, files):
    root = base/'project'
    root.mkdir(parents=True)
    subprocess.run(['git', 'init', '-q', str(root)], check=True, stdout=subprocess.DEVNULL)
    names = [f'src/g{i//100:03}/module_{i:05}.py' for i in range(files)]
    name_set = frozenset(names)
    for name in names:
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'value = 1\r\n')
    os.environ['SECURITY_RUNTIME_STATE_DIR'] = str(base/'runtime')
    task = TaskSecurityService(FixtureDetector(), HookStateStore(base/'state'),
        owner=session_owner('codex', 'isolated-benchmark'))
    beginning, baseline_ms = measured(lambda:task.begin(root, 'latency',
        check_policy=POLICY, background_closeout=True))
    ref = beginning['task_ref']
    (root/names[0]).write_bytes(b'value = 2\r\n')
    reads = Counter()
    source_read, raw_read = WorkspaceReader.read, queued_inputs._read_file
    capture, lock = queued_closeout.capture_end, task.hooks.lock
    phase = dict(capture_end_ms=0.0, workspace_lock_wait_ms=0.0,
                 workspace_lock_outer_hold_ms=0.0)
    lock_depth = 0

    def observed_read(reader, name, **kwargs):
        if name in name_set:
            reads[name] += 1
        return source_read(reader, name, **kwargs)

    def observed_raw(path, *args):
        if Path(path).is_relative_to(root):
            name = Path(path).relative_to(root).as_posix()
            if name in name_set:
                reads[name] += 1
        return raw_read(path, *args)

    def observed_capture(*args, **kwargs):
        value, elapsed = measured(lambda:capture(*args, **kwargs))
        phase['capture_end_ms'] += elapsed
        return value

    @contextmanager
    def observed_lock(*args, **kwargs):
        nonlocal lock_depth
        started = time.perf_counter()
        with lock(*args, **kwargs) as acquired:
            phase['workspace_lock_wait_ms'] += 1000*(time.perf_counter()-started)
            outer = acquired and lock_depth == 0
            held = time.perf_counter()
            if acquired:
                lock_depth += 1
            try:
                yield acquired
            finally:
                if acquired:
                    lock_depth -= 1
                if outer:
                    phase['workspace_lock_outer_hold_ms'] += 1000*(time.perf_counter()-held)

    WorkspaceReader.read, queued_inputs._read_file = observed_read, observed_raw
    queued_closeout.capture_end, task.hooks.lock = observed_capture, observed_lock
    try:
        _, enqueue_ms = measured(lambda:enqueue(task, root, ref, launch=False))
    finally:
        WorkspaceReader.read, queued_inputs._read_file = source_read, raw_read
        queued_closeout.capture_end, task.hooks.lock = capture, lock
    _, fixture_execution_ms = measured(lambda:execute_one(task, root, ref))
    assert status(task, root, ref)['status'] == 'READY_FOR_REVIEW'
    fresh, checks = task._fresh, []

    def observed_fresh(*args):
        checks.append(True)
        return fresh(*args)

    task._fresh = observed_fresh
    packet, prepare_ms = measured(lambda:task.prepare(root, ref))
    assert packet['status'] == 'REVIEW_REQUIRED'
    return dict(baseline_ms=baseline_ms, enqueue_ms=enqueue_ms, prepare_ms=prepare_ms,
        fixture_execution_ms=fixture_execution_ms, source_reads=sum(reads.values()),
        source_read_distribution=dict(Counter(reads.values())),
        enqueue_phases={name:round(value, 3) for name,value in phase.items()},
        preparation_full_freshness_checks=len(checks))


def run(files, repeats):
    if files < 1 or repeats < 1:
        raise ValueError('File and repeat counts must be positive')
    previous = os.environ.get('SECURITY_RUNTIME_STATE_DIR')
    try:
        with tempfile.TemporaryDirectory(prefix='closeout-latency-') as temporary:
            samples = [sample(Path(temporary).resolve()/str(i), files) for i in range(repeats)]
    finally:
        if previous is None:
            os.environ.pop('SECURITY_RUNTIME_STATE_DIR', None)
        else:
            os.environ['SECURITY_RUNTIME_STATE_DIR'] = previous
    fields = ('baseline_ms', 'enqueue_ms', 'prepare_ms', 'fixture_execution_ms')
    return dict(scope='ISOLATED_CAPTURE_AND_PREPARE_FIXTURE_DETECTOR',
        native_scanners=False, host_configuration_modified=False,
        files=files, repeats=repeats, samples=samples,
        timing={name:dict(median_ms=statistics.median(s[name] for s in samples),
            max_ms=max(s[name] for s in samples)) for name in fields})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--files', type=int, default=1001)
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    print(json.dumps(run(args.files, args.repeats), ensure_ascii=False, indent=2))
