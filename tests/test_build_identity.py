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


@pytest.mark.skipif(module.os.name != 'posix', reason='POSIX editable-source verification')
def test_stop_digest_reuse_and_source_invalidation(tmp_path, monkeypatch):
    import os
    from unittest.mock import patch

    source = tmp_path / 'src' / 'security_runtime'
    rules = source / 'rules'
    rules.mkdir(parents=True)
    module_path = source / 'sample.py'
    rule_path = rules / 'sample.yaml'
    module_path.write_text('x = 1')
    rule_path.write_text('id: a')
    monkeypatch.setattr(module, '__file__', str(source / 'build_identity.py'))

    def identity():
        return module.build_identity()['build_id']

    original = identity()
    with patch.object(module, '_verified_source_digest', wraps=module._verified_source_digest) as verifier:
        with module.stop_identity_session():
            assert identity() == identity() == original
            assert verifier.call_count == 1
            previous = original
            for path, content in [(module_path, 'x = 2'), (rule_path, 'id: b')]:
                info = path.stat()
                path.write_text(content)
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
                current = identity()
                assert previous != current == identity()
                previous = current
            assert verifier.call_count == 3
            rule_path.rename(rules / 'moved.yaml')
            renamed = identity()
            assert renamed != previous
            (rules / 'moved.yaml').unlink()
            assert identity() != renamed
        with module.stop_identity_session():
            count = verifier.call_count
            assert identity() == module._source_digest(source)
            assert verifier.call_count == count + 1
