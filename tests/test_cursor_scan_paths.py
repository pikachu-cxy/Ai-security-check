"""Cursor private input paths and Windows path-length diagnostics."""
import errno
import os
from pathlib import Path
import shutil

import pytest

from security_runtime.development_check_worker import failure_diagnostic
from security_runtime.hook_state import native_io_path
from security_runtime.scan_input import _write


def test_path_length_diagnostic_does_not_expose_paths():
    error = FileNotFoundError('private source path')
    error.winerror = 206
    expected = dict(stage='SCAN_EXECUTION', exception_type='FileNotFoundError',
                    reason_code='SCAN_INPUT_PATH_TOO_LONG')
    assert failure_diagnostic(error, 'SCAN_EXECUTION') == expected
    assert failure_diagnostic(OSError(errno.ENAMETOOLONG, 'secret'))['reason_code'] == 'SCAN_INPUT_PATH_TOO_LONG'
    assert failure_diagnostic(FileNotFoundError('missing'))['reason_code'] == 'UNKNOWN'


@pytest.mark.skipif(os.name != 'nt', reason='Windows extended-path IO')
def test_nested_rule_parent_uses_extended_windows_path(tmp_path, monkeypatch):
    root = tmp_path/'private'
    root.mkdir()
    name = '/'.join(['nested-rule-directory']*12 + ['rule.yaml'])
    assert len(str((root/name).parent)) > 260
    mkdir = Path.mkdir

    def legacy_limit(path, *args, **kwargs):
        if len(str(path)) > 259 and not str(path).startswith('\\\\?\\'):
            raise FileNotFoundError('simulated Win32 path limit')
        return mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'mkdir', legacy_limit)
    try:
        _write(root, name, b'rules: []\n', readonly=False)
        assert native_io_path(root/name).read_bytes() == b'rules: []\n'
    finally:
        assert root.parent == tmp_path
        shutil.rmtree(native_io_path(root))
