"""Readiness failures never skip the real host gate or relax target budgets."""
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest
import yaml

from scripts import node_host_preflight as host


@pytest.fixture
def node_file(tmp_path):
    path=tmp_path/'node.exe'; path.write_bytes(b'controlled executable identity fixture')
    return str(path)


@pytest.fixture(params=['native', 'cp1252'])
def source_default_encoding(request, monkeypatch):
    if request.param == 'cp1252':
        original_read_text = Path.read_text
        def cp1252_read_text(path, encoding=None, errors=None):
            return original_read_text(path, encoding=encoding or 'cp1252', errors=errors)
        # Override only omitted read_text encodings, even when Python UTF-8 mode is enabled.
        monkeypatch.setattr(Path, 'read_text', cp1252_read_text)
        # Verify the simulated default reproduces the exact former decoding failure.
        source=Path(__file__).parents[1]/'src/security_runtime/arithmetic_regression.py'
        with pytest.raises(UnicodeDecodeError) as caught:
            source.read_text()
        assert caught.value.encoding == 'charmap'
        assert caught.value.object[caught.value.start] == 0x8d
    return request.param


def test_timeout_remains_failure_without_retry(node_file,monkeypatch):
    run=Mock(side_effect=subprocess.TimeoutExpired([node_file,'--version'],host.PROBE_TIMEOUT_SECONDS))
    monkeypatch.setattr(host.subprocess,'run',run)
    with pytest.raises(subprocess.TimeoutExpired): host.probe_node(executable=node_file)
    assert run.call_count == 1
    assert run.call_args.kwargs['timeout'] == 30


@pytest.mark.parametrize('version',['v22.23.3','v25.0.0','v24.16.0-pre','not a version',''])
def test_unsupported_or_invalid_version_is_failure(node_file,monkeypatch,version):
    monkeypatch.setattr(host.subprocess,'run',Mock(return_value=subprocess.CompletedProcess([],0,version,'')))
    with pytest.raises(RuntimeError,match='UNSUPPORTED'): host.probe_node(executable=node_file)


def test_missing_node_fails_instead_of_skip(monkeypatch):
    monkeypatch.setattr(host.shutil,'which',lambda value:None)
    with pytest.raises(RuntimeError,match='NODE_HOST_REQUIRED'): host.probe_node()


def test_exact_ci_version_and_per_process_environment(node_file,monkeypatch):
    monkeypatch.setenv('NODE_OPTIONS','do not inherit')
    monkeypatch.setenv('NODE_PATH','do not inherit')
    run=Mock(return_value=subprocess.CompletedProcess([],0,'v24.16.0\n',''))
    monkeypatch.setattr(host.subprocess,'run',run)
    record=host.probe_node(executable=node_file,expected_version='24.16.0')
    assert record['status']=='NODE_HOST_READY' and record['attempts']==1
    assert record['target_executed'] is False and len(record['executable_sha256'])==64
    assert 'NODE_OPTIONS' not in run.call_args.kwargs['env'] and 'NODE_PATH' not in run.call_args.kwargs['env']
    with pytest.raises(RuntimeError,match='VERSION_MISMATCH'):
        host.probe_node(executable=node_file,expected_version='24.15.0')


def test_nonzero_probe_fails(node_file,monkeypatch):
    run=Mock(side_effect=subprocess.CalledProcessError(1,[node_file,'--version']))
    monkeypatch.setattr(host.subprocess,'run',run)
    with pytest.raises(subprocess.CalledProcessError): host.probe_node(executable=node_file)


def test_ci_pins_node_and_records_preflight_before_full_tests(source_default_encoding):
    root=Path(__file__).parents[1]
    workflow=yaml.safe_load((root/'.github/workflows/tests.yml').read_text(encoding='utf-8'))
    job=workflow['jobs']['tests']
    assert job['env']['SECURITY_RUNTIME_CI_NODE_VERSION']=='24.16.0'
    steps=job['steps']; setup=next(i for i,s in enumerate(steps) if s.get('uses')=='actions/setup-node@v4')
    assert steps[setup]['with']['node-version']=='24.16.0'
    preflight=next(i for i,s in enumerate(steps) if 'node_host_preflight.py' in s.get('run',''))
    tests=next(i for i,s in enumerate(steps) if s.get('name')=='Run Runtime tests')
    assert setup < preflight < tests
    # runner context is allowed in step env, not jobs.<job_id>.env.
    assert all('runner.' not in str(value) for value in job['env'].values())
    assert 'SECURITY_RUNTIME_HOST_REPORT_DIR' not in job['env']
    assert steps[tests]['env']['SECURITY_RUNTIME_HOST_REPORT_DIR']=='${{ runner.temp }}/arithmetic-host-evidence'
    assert all(not s.get('continue-on-error',False) for s in steps)
    artifact=next(s for s in steps if s.get('with',{}).get('name')=='arithmetic-host-evidence-${{ matrix.os }}')
    assert artifact['with']['if-no-files-found']=='error'
    source=(root/'tests/test_arithmetic_regression.py').read_text(encoding='utf-8')
    assert "@pytest.fixture(scope='session')" in source and 'pytest.skip' not in source


def test_probe_does_not_modify_product_host_or_worker_budgets(source_default_encoding):
    root=Path(__file__).parents[1]
    runtime=(root/'src/security_runtime/arithmetic_regression.py').read_text(encoding='utf-8')
    template=(root/'src/security_runtime/assets/arithmetic_regression.mjs').read_text(encoding='utf-8')
    assert "'timeout_seconds': 30" in runtime and "'worker_timeout_seconds': 10" in runtime
    assert 'timeout: 10000' in template


def test_cli_requires_current_success_receipt(tmp_path):
    output=tmp_path/'old.json'; output.write_text('{}',encoding='utf-8')
    result=subprocess.run([sys.executable,str(Path(host.__file__)), '--expected-version','24.16.0',
        '--output',str(output)],capture_output=True,timeout=10)
    assert result.returncode != 0 and output.read_text(encoding='utf-8')=='{}'
