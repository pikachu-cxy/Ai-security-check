import subprocess
from types import SimpleNamespace

import pytest

from security_runtime import build_identity as module


def test_development_provenance_does_not_inherit_stdio_protocol_or_write_index(tmp_path, monkeypatch):
    def run(arguments, **kwargs):
        assert '--no-optional-locks' in arguments and 'core.fsmonitor=false' in arguments
        assert kwargs['stdin'] == subprocess.DEVNULL and kwargs['stderr'] == subprocess.DEVNULL
        assert kwargs['stdout'] != subprocess.PIPE and kwargs['timeout'] == 5
        kwargs['stdout'].write(b'fixture-result\n')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(module.subprocess, 'run', run)
    assert module.git_provenance(tmp_path, 'rev-parse', 'HEAD') == 'fixture-result'


@pytest.mark.parametrize('content', [b'null', b'[]', b'{"build_id":"bad"}'])
def test_unverifiable_frozen_identity_remains_unknown(tmp_path, monkeypatch, content):
    (tmp_path / 'version.json').write_bytes(content)
    monkeypatch.setattr(module.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(module.sys, 'executable', str(tmp_path / 'security-check.exe'))
    assert module.build_identity()['status'] == 'UNVERIFIABLE_LEGACY_BUNDLE'
