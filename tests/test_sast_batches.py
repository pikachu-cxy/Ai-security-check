import subprocess

import pytest

from security_runtime.scanners import sast_batches


@pytest.mark.parametrize('count', [1, 128, 500])
def test_short_paths_scan_together_without_a_file_count_limit(count):
    names = [f'src/file_{i}.ts' for i in range(count)]
    assert list(sast_batches(names)) == [tuple(names)]


def test_quoted_unicode_paths_stay_within_command_budget():
    names = [('folder space/中文' * 60) + str(i) + '.ts' for i in range(80)]
    groups = list(sast_batches(names))
    assert len(groups) > 1
    assert [name for group in groups for name in group] == names
    assert all(sum(len(subprocess.list2cmdline([n]).encode('utf-16-le')) // 2 + 1 for n in b) <= 16000 for b in groups)


def test_command_budget_boundary_keeps_every_target():
    # Each name plus its argument separator is exactly half the target budget.
    names = ['a' * 7999, 'b' * 7999, 'c.py']
    assert list(sast_batches(names)) == [tuple(names[:2]), ('c.py',)]


def test_single_oversized_argument_and_empty_scope():
    assert list(sast_batches([])) == []
    with pytest.raises(ValueError, match='argument budget'):
        list(sast_batches(['x' * 16001]))
