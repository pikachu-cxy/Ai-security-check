from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import subprocess

import pytest

from security_runtime.scanners import baseline_sast_batches, sast_batches


def test_baseline_bigger_batches_preserve_exact_order_and_normal_default():
    names = [f'src/file_{i}.ts' for i in range(356)]
    assert [len(b) for b in sast_batches(names)] == [40] * 8 + [36]
    with baseline_sast_batches(True):
        groups = list(sast_batches(names))
        assert [len(b) for b in groups] == [128, 128, 100]
        assert [name for group in groups for name in group] == names
    assert len(next(sast_batches(names))) == 40


def test_quoted_unicode_paths_stay_within_command_budget():
    names = [('folder space/中文' * 60) + str(i) + '.ts' for i in range(80)]
    with baseline_sast_batches(True):
        groups = list(sast_batches(names))
    assert [name for group in groups for name in group] == names
    assert all(sum(len(subprocess.list2cmdline([n]).encode('utf-16-le')) // 2 + 1 for n in b) <= 16000 for b in groups)


def test_baseline_budget_propagates_to_worker_and_resets_after_error():
    names = [f'{i}.ts' for i in range(129)]
    with pytest.raises(RuntimeError):
        with baseline_sast_batches(True):
            with ThreadPoolExecutor(max_workers=1) as worker:
                assert worker.submit(copy_context().run, lambda: len(next(sast_batches(names)))).result() == 128
            raise RuntimeError('synthetic')
    assert len(next(sast_batches(names))) == 40


def test_single_oversized_argument_and_empty_scope():
    assert list(sast_batches([])) == []
    with pytest.raises(ValueError, match='argument budget'):
        list(sast_batches(['x' * 16001]))
