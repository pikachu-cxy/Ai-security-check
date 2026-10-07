"""Leading UTF-8 BOM compatibility uses only bounded, temporary source copies."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess

import pytest

from security_runtime.functional_verification import snapshot
from security_runtime.hook_state import identity
from test_functional_host import host, prepare, report

BOM = b'\xef\xbb\xbf'


@pytest.mark.parametrize('bom', [False, True])
@pytest.mark.parametrize('broken', [False, True])
def test_host_compile_bom_preserves_source_and_security(host, bom, broken):
    root, receipt, service, name = host
    original = b'package demo; public class TlsService { ' + (
        b'MissingType value;' if broken else b'public int value() { return 1; }') + b' }\r\n'
    if bom:
        original = BOM + original
    (root / name).write_bytes(original)
    (root / 'Other.java').write_bytes(BOM + b'class Other { MissingType value; }')
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    planned = prepare(host)
    mode = 'TEMPORARY_BOM_NORMALIZATION' if bom else 'ORIGINAL'
    plan = planned['plan']
    step = plan['steps'][0]
    row = service.plans[planned['functional_ref']]
    artifact = row['artifact_directory']
    assert plan['source_handling'] == step['source_handling'] == mode
    assert planned['functional_verification']['source_handling'] == mode
    assert plan['source_modified'] is False and step['source_modified'] is False
    assert step['target_files'] == [name] and step['argv'][-1] == name
    assert plan['normalized_target_files'] == ([name] if bom else [])
    working = Path(step['working_directory'])
    assert (working != root) == bom
    if bom:
        assert working.is_relative_to(artifact) and not working.is_relative_to(root)
        assert (working / name).read_bytes() == original[3:]
        assert not (working / 'Other.java').exists()
    output = Path(step['argv'][step['argv'].index('-d') + 1])
    assert output.is_relative_to(artifact) and not output.is_relative_to(root)
    env = dict(os.environ, **step['environment'])
    for key in step['unset_environment']:
        env.pop(key, None)
    # Native Host simulated by this driver; Runtime never launches javac.
    compiled = subprocess.run(step['argv'], cwd=working, env=env, shell=False,
                              capture_output=True, timeout=step['timeout_seconds'])
    assert (compiled.returncode != 0) == broken
    if not broken:
        assert (output / 'demo/TlsService.class').exists()
    values = report(planned, compiled.returncode)
    # No raw source/diagnostic content submitted or persisted.
    final = service.run(planned['functional_ref'], execution_result=values, bound_workspace=root)
    functional = final['functional_verification']
    assert final['status'] == ('FUNCTIONAL_FAILED' if broken else 'FUNCTIONAL_VERIFIED')
    assert functional['source_handling'] == mode and functional['source_modified'] is False
    assert functional['steps'][0]['source_handling'] == mode
    assert functional['coverage'] == ('NONE' if broken else 'COMPILE_ONLY')
    assert functional['baseline'] == 'UNKNOWN' and functional['regression_attribution'] == 'NOT_PROVEN'
    assert final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert final['overall_status'] == ('SECURITY_VERIFIED_FUNCTION_FAILED' if broken else 'SECURITY_AND_FUNCTIONALLY_VERIFIED')
    assert functional['cleanup_complete'] and not artifact.exists()
    assert before == {p.relative_to(root): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    assert not list(root.rglob('*.class'))
    state = b''.join(p.read_bytes() for p in receipt.state.directory.rglob('*') if p.is_file())
    assert original not in state
    cached = service.prepare('grant', 'task', root, bound_workspace=root)
    assert cached['functional_verification']['source_handling'] == mode
    assert cached['functional_verification']['reused']
    checked = service.finalize('grant', 'task', root, {'verification_status': 'SCANNER_VERIFIED_RESOLVED'})
    assert checked['functional_verification']['source_handling'] == mode
    assert checked['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'


@pytest.mark.parametrize('data', [b'\xff\xfej\x00', BOM + b'\xff', BOM + BOM + b'class A {}', b'class A {\x00}'])
def test_unsupported_encoding_is_inconclusive_without_source_changes(host, data):
    root, _, service, name = host
    (root / name).write_bytes(data)
    out = service.prepare('grant', 'task', root, bound_workspace=root)
    assert out['status'] == 'FUNCTIONAL_INCONCLUSIVE'
    assert out['functional_verification']['reason_code'] == 'JAVAC_SOURCE_ENCODING_UNSUPPORTED'
    assert out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert (root / name).read_bytes() == data and not service.plans


def test_mixed_targets_copied_without_scope_expansion(host, monkeypatch):
    root, receipt, service, name = host
    original = (root / name).read_bytes()
    (root / name).write_bytes(BOM + original)
    second = 'src/main/java/demo/Second.java'
    (root / second).write_bytes(b'package demo; class Second {}')
    read = receipt.functional_receipt
    monkeypatch.setattr(receipt, 'functional_receipt', lambda *args: dict(read(*args), target_files=(name, second)))
    monkeypatch.setattr('subprocess.Popen', lambda *a, **k: pytest.fail('Runtime launched a command'))
    out = prepare(host)
    working = Path(out['plan']['steps'][0]['working_directory'])
    assert sorted(p.relative_to(working).as_posix() for p in working.rglob('*.java')) == sorted([name, second])
    assert (working / name).read_bytes() == original
    assert (working / second).read_bytes() == (root / second).read_bytes()
    assert out['plan']['normalized_target_files'] == [name]
    final = service.run(out['functional_ref'], execution_result=report(out), bound_workspace=root)
    assert final['functional_verification']['coverage'] == 'COMPILE_ONLY'
    assert not working.exists() and (root / name).read_bytes() == BOM + original


def test_normalized_copy_tamper_is_rejected_and_cleaned(host):
    root, _, service, name = host
    original = BOM + (root / name).read_bytes()
    (root / name).write_bytes(original)
    out = prepare(host)
    working = Path(out['plan']['steps'][0]['working_directory'])
    (working / name).write_bytes(b'package demo; public class TlsService {}')
    final = service.run(out['functional_ref'], execution_result=report(out), bound_workspace=root)
    assert final['functional_verification']['reason_code'] == 'HOST_MODIFIED_VERIFIER_INPUT'
    assert final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert not working.exists() and (root / name).read_bytes() == original


@pytest.mark.parametrize('expired', [False, True])
def test_bom_projection_cleans_on_host_cancellation_or_expiry(host, expired):
    root, _, service, name = host
    (root / name).write_bytes(BOM + (root / name).read_bytes())
    out = prepare(host)
    row = service.plans[out['functional_ref']]
    directory = row['artifact_directory']
    value = report(out)
    value['steps'][0].update(execution_status='CANCELLED', exit_code=None)
    if expired:
        row['created'] -= 901
    final = service.run(out['functional_ref'], execution_result=value, bound_workspace=root)
    assert final['status'] == 'FUNCTIONAL_INCONCLUSIVE'
    assert not directory.exists()
    assert (root / name).read_bytes().startswith(BOM)


def test_pre_normalization_cache_cannot_hide_new_bom_plan(host):
    root, receipt, service, name = host
    (root / name).write_bytes(BOM + (root / name).read_bytes())
    key = b'k' * 32
    before = snapshot(root, key)
    steps = service.registry.detect(root, target_files=(name,))
    base = service.registry.plan(root, steps, key)
    old_id = identity(json.dumps([str(root), before, base['config_hash'], 'a' * 64,
                                 'host-native-functional-v1'], sort_keys=True))
    cache = {old_id: {'result': service._host_result('FAILED')}}
    encoded = json.dumps(cache, sort_keys=True, separators=(',', ':')).encode()
    path = receipt.state.workspace_directory(root) / 'functional-cache'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'records': cache, 'mac': hmac.new(key, encoded, hashlib.sha256).hexdigest()}))
    out = prepare(host)
    assert out['plan']['source_handling'] == 'TEMPORARY_BOM_NORMALIZATION'
    assert not out['functional_verification']['reused']
    service._cleanup_rows(service.plans)
