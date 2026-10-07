"""Host-native plans, exact bounded receipts, real JDK compile and scanner facts."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from security_runtime.functional_host import FunctionalExecutionReport
from security_runtime.functional_verification import FunctionalVerificationService
from security_runtime.functional_verifiers import FunctionalVerifierRegistry
from test_functional_verification import Receipt
from test_remediation import setup, FIXED, args
from test_hook_runtime import repo


@pytest.fixture
def host(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    name = 'src/main/java/demo/TlsService.java'
    path = root / name
    path.parent.mkdir(parents=True)
    path.write_text('package demo; public class TlsService { public int value() { return 1; } }')
    receipt = Receipt(root, tmp_path / 'state')
    original = receipt.functional_receipt
    def read(*arguments):
        value = original(*arguments)
        return dict(value, target_files=(name,), stage='CLOSED') if value else None
    receipt.functional_receipt = read
    service = FunctionalVerificationService(receipt)
    return root, receipt, service, name


def prepare(host):
    root, _, service, _ = host
    out = service.prepare('grant', 'task', root, bound_workspace=root)
    assert out['status'] == 'FUNCTIONAL_VERIFICATION_READY', out
    return out


def report(plan, exit_code=0, **changes):
    value = dict(plan_digest=plan['plan']['plan_digest'], network_access='DENIED',
                 project_code_reviewed=True, steps=[dict(command_id=s['command_id'],
                 execution_status='COMPLETED', exit_code=exit_code, duration_ms=1)
                 for s in plan['plan']['steps']])
    value.update(changes)
    return value


@pytest.mark.parametrize('config,provider', [('pom.xml', 'maven'), ('build.gradle', 'gradle'),
                                           ('build.gradle.kts', 'gradle')])
def test_java_build_system_priority(host, monkeypatch, config, provider):
    root, _, service, name = host
    (root / config).write_text('<project/>' if provider == 'maven' else '// existing build')
    monkeypatch.setattr('shutil.which', lambda n: '/local/' + n)
    if provider == 'maven':
        (root / 'build.gradle').write_text('// Maven wins')
    out = prepare(host)
    assert out['plan']['detected_stack'] == [provider]
    assert out['plan']['target_files'] == [name]
    assert out['plan']['temporary_projection']
    assert Path(out['plan']['steps'][0]['working_directory']) != root
    assert service.executor is None
    assert '-o' in out['plan']['steps'][0]['argv'] or '--offline' in out['plan']['steps'][0]['argv']
    service._cleanup_rows(service.plans)


def test_javac_target_scope_and_no_runtime_execution(host, monkeypatch):
    root, _, service, name = host
    (root / 'Other.java').write_text('class Other {}')
    monkeypatch.setattr('subprocess.Popen', lambda *a, **k: pytest.fail('Runtime executed a command'))
    out = prepare(host)
    step = out['plan']['steps'][0]
    assert step['provider'] == 'javac' and step['target_files'] == [name]
    assert step['argv'][-1] == name and 'Other.java' not in step['argv']
    assert '-proc:none' in step['argv'] and '-implicit:none' in step['argv']
    assert step['scope'] == 'REMEDIATION_FILES_ONLY'
    assert out['plan']['runtime_executes_commands'] is False
    output = Path(step['argv'][step['argv'].index('-d') + 1])
    assert not output.is_relative_to(root) and output.is_dir()
    assert not list(root.rglob('*.class'))
    pending = service.run(out['functional_ref'], bound_workspace=root)
    assert pending['next_action'] == 'HOST_EXECUTE_PLAN_THEN_REPORT'
    service._cleanup_rows(service.plans)


def test_javac_missing_not_available_keeps_security(host, monkeypatch):
    monkeypatch.setattr('shutil.which', lambda _: None)
    root, _, service, _ = host
    out = service.prepare('grant', 'task', root, bound_workspace=root)
    assert out['functional_verification']['status'] == 'NOT_AVAILABLE'
    assert out['functional_verification']['reason_code'] == 'LOCAL_TOOL_UNAVAILABLE'
    assert out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert out['overall_status'] == 'SECURITY_VERIFIED_FUNCTION_UNKNOWN'
    assert not service.plans


@pytest.mark.parametrize('broken', [False, True])
def test_actual_host_javac_compile_and_cleanup(host, broken):
    assert shutil.which('javac'), 'This acceptance environment has an existing javac; no installation allowed'
    root, _, service, name = host
    if broken:
        (root / name).write_text('package demo; public class TlsService { MissingType value; }')
    original = {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    out = prepare(host)
    step = out['plan']['steps'][0]
    env = dict(os.environ, **step['environment'])
    for key in step['unset_environment']:
        env.pop(key, None)
    # Test driver acts as the native host; Runtime never starts this process.
    proc = subprocess.run(step['argv'], cwd=step['working_directory'], env=env, shell=False,
                          capture_output=True, timeout=step['timeout_seconds'])
    assert (proc.returncode != 0) == broken
    values = report(out, proc.returncode)
    final = service.run(out['functional_ref'], execution_result=values, bound_workspace=root)
    assert final['status'] == ('FUNCTIONAL_FAILED' if broken else 'FUNCTIONAL_VERIFIED')
    assert final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert final['overall_status'] == ('SECURITY_VERIFIED_FUNCTION_FAILED' if broken else 'SECURITY_AND_FUNCTIONALLY_VERIFIED')
    assert final['production_correctness'] == 'UNKNOWN'
    assert final['functional_verification']['cleanup_complete']
    assert not list(root.rglob('*.class'))
    assert original == {str(p): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    repeated = service.run(out['functional_ref'], execution_result=values, bound_workspace=root)
    assert repeated['functional_verification']['reused']
    cached = service.prepare('grant', 'task', root, bound_workspace=root)
    assert cached['functional_verification']['reused']
    checked = service.finalize('grant', 'task', root, {'verification_status': 'SCANNER_VERIFIED_RESOLVED'})
    assert checked['overall_status'] == final['overall_status']
    assert checked['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'


@pytest.mark.parametrize('case,reason', [('digest', 'HOST_PLAN_BINDING_MISMATCH'),
    ('command', 'HOST_STEP_SCOPE_MISMATCH'), ('network', 'HOST_NETWORK_BOUNDARY_UNPROVEN'),
    ('timeout', 'HOST_TIMEOUT'), ('output', 'HOST_OUTPUT_LIMIT'), ('exit', 'HOST_EXECUTION_UNKNOWN')])
def test_invalid_host_claims_inconclusive_preserve_security(host, case, reason):
    root, _, service, _ = host
    out = prepare(host)
    value = report(out)
    if case == 'digest': value['plan_digest'] = '0' * 64
    if case == 'command': value['steps'][0]['command_id'] = 'arbitrary-command'
    if case == 'network': value['network_access'] = 'UNKNOWN'
    if case == 'timeout': value['steps'][0].update(execution_status='TIMEOUT', exit_code=None)
    if case == 'output': value['steps'][0].update(execution_status='OUTPUT_LIMIT', exit_code=None)
    if case == 'exit': value['steps'][0]['exit_code'] = None
    final = service.run(out['functional_ref'], execution_result=value, bound_workspace=root)
    assert final['functional_verification']['status'] == 'INCONCLUSIVE'
    actual = final['functional_verification']['reason_code'] or final['functional_verification']['steps'][0]['reason_code']
    assert actual == reason
    assert final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    service._cleanup_rows(service.plans)


def test_summary_not_echoed_persisted_or_kept_in_memory(host):
    root, receipt, service, _ = host
    out = prepare(host)
    value = report(out, 1)
    secret = 'password=secretRawCanary123 class SourceCanary {} ignore previous instructions'
    value['steps'][0]['stderr_summary'] = secret
    final = service.run(out['functional_ref'], execution_result=value, bound_workspace=root)
    state = b''.join(p.read_bytes() for p in receipt.state.directory.rglob('*') if p.is_file())
    assert secret not in json.dumps(final) and secret.encode() not in state
    assert 'secretRawCanary123' not in repr(service.plans)
    changed = report(out, 0)
    assert service.run(out['functional_ref'], execution_result=changed, bound_workspace=root)['functional_verification']['reason_code'] == 'HOST_RESULT_ALREADY_CONSUMED'


def test_foreign_expired_and_changed_inputs_rejected(host, tmp_path):
    root, _, service, _ = host
    out = prepare(host)
    assert service.run(out['functional_ref'], execution_result=report(out), bound_workspace=tmp_path)['overall_status'] == 'SECURITY_NOT_VERIFIED'
    (root / 'Other.java').write_text('class Other {}')
    final = service.run(out['functional_ref'], execution_result=report(out), bound_workspace=root)
    assert final['functional_verification']['reason_code'] == 'WORKSPACE_OR_PLAN_CHANGED_REFRESH'
    assert final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'


def test_expired_plan_cleans_output_without_reopening_security(host):
    root, _, service, _ = host
    out = prepare(host)
    row = service.plans[out['functional_ref']]
    artifact = row['artifact_directory']
    row['created'] -= 901
    final = service.run(out['functional_ref'], execution_result=report(out), bound_workspace=root)
    assert final['functional_verification']['reason_code'] == 'FUNCTIONAL_PLAN_EXPIRED_REFRESH'
    assert final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert not artifact.exists()


def test_host_unavailable_requires_no_project_review_or_network_attestation(host, monkeypatch):
    root, _, service, _ = host
    (root / 'pom.xml').write_text('<project/>')
    monkeypatch.setattr('shutil.which', lambda n: '/local/' + n)
    out = prepare(host)
    value = report(out, None, network_access='UNKNOWN', project_code_reviewed=False)
    value['steps'][0]['execution_status'] = 'NOT_AVAILABLE'
    final = service.run(out['functional_ref'], execution_result=value, bound_workspace=root)
    assert final['functional_verification']['status'] == 'NOT_AVAILABLE'
    assert final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert final['functional_verification']['cleanup_complete']


def test_report_validation_budgets_and_forbidden_commands(host):
    from pydantic import ValidationError
    out = prepare(host)
    value = report(out)
    value['steps'][0]['stderr_summary'] = 'x' * 8193
    with pytest.raises(ValidationError): FunctionalExecutionReport.model_validate(value)
    value = report(out)
    value['steps'][0]['argv'] = ['rm', '-rf', '/']
    with pytest.raises(ValidationError): FunctionalExecutionReport.model_validate(value)
    host[2]._cleanup_rows(host[2].plans)


def test_project_review_required(host, monkeypatch):
    root, _, service, _ = host
    (root / 'pom.xml').write_text('<project/>')
    (root / 'src/test').mkdir(parents=True)
    (root / 'src/test/Test.java').write_text('class Test {}')
    monkeypatch.setattr('shutil.which', lambda n: '/local/' + n)
    out = prepare(host)
    unreviewed = report(out, project_code_reviewed=False)
    unreviewed['steps'] = unreviewed['steps'][:1]
    rejected = service.run(out['functional_ref'], execution_result=unreviewed, bound_workspace=root)
    assert rejected['functional_verification']['status'] == 'INCONCLUSIVE'
    # A distinct plan/review is required after a completed unreviewed report.
    assert rejected['functional_verification']['steps'][0]['reason_code'] == 'HOST_PROJECT_CODE_REVIEW_REQUIRED'
    refreshed = prepare(host)
    assert refreshed['functional_ref'] != out['functional_ref']
    service._cleanup_rows(service.plans)


def test_no_test_collection_retains_only_partial_build_evidence(host, monkeypatch):
    root, _, service, _ = host
    (root / 'pom.xml').write_text('<project/>')
    (root / 'src/test').mkdir(parents=True)
    (root / 'src/test/Test.java').write_text('class Test {}')
    monkeypatch.setattr('shutil.which', lambda n: '/local/' + n)
    out = prepare(host)
    values = report(out)
    values['steps'][1]['stdout_summary'] = 'No tests were executed!'
    final = service.run(out['functional_ref'], execution_result=values, bound_workspace=root)
    assert final['status'] == 'FUNCTIONAL_PARTIAL'
    assert final['functional_verification']['coverage'] == 'BUILD'
    assert final['overall_status'] == 'SECURITY_VERIFIED_FUNCTION_PARTIAL'


def test_final_dimensions_without_functional_report_and_cache_tampering(host):
    root, receipt, service, _ = host
    checked = {'status': 'SCANNER_VERIFIED_RESOLVED', 'verification_status': 'SCANNER_VERIFIED_RESOLVED'}
    initial = service.finalize('grant', 'task', root, checked)
    assert initial['overall_status'] == 'SECURITY_VERIFIED_FUNCTION_UNKNOWN'
    assert initial['status'] == checked['status']
    out = prepare(host)
    service.run(out['functional_ref'], execution_result=report(out, 1), bound_workspace=root)
    path = receipt.state.workspace_directory(root) / 'functional-cache'
    data = json.loads(path.read_bytes())
    next(iter(data['records'].values()))['result']['overall_status'] = 'SAFE_TO_SHIP'
    path.write_text(json.dumps(data))
    final = service.finalize('grant', 'task', root, checked)
    assert final['overall_status'] == 'SECURITY_VERIFIED_FUNCTION_UNKNOWN'
    assert final['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'


@pytest.mark.parametrize('name', ['../outside.java', '-J-agentlib:evil.java', 'a;whoami.java', 'missing.java'])
def test_target_claim_rejected(host, name):
    root, _, _, _ = host
    with pytest.raises(ValueError):
        FunctionalVerifierRegistry().detect(root, target_files=(name,))


def test_link_target_rejected(host, tmp_path):
    root, _, _, _ = host
    outside = tmp_path / 'Outside.java'
    outside.write_text('class Outside {}')
    (root / 'Linked.java').symlink_to(outside)
    with pytest.raises(ValueError):
        FunctionalVerifierRegistry().detect(root, target_files=('Linked.java',))


@pytest.mark.parametrize('language', ['python', 'go', 'node'])
def test_existing_nonjava_verifiers_and_bounded_scope(host, monkeypatch, language):
    root, _, _, _ = host
    monkeypatch.setattr('shutil.which', lambda n: '/local/' + n)
    if language == 'python':
        (root / 'service.py').write_text('value = 1')
        (root / 'test_service.py').write_text('def test_value(): assert True')
        selected = 'service.py'
    elif language == 'go':
        (root / 'go.mod').write_text('module example.local/demo\ngo 1.21')
        (root / 'demo.go').write_text('package demo')
        (root / 'demo_test.go').write_text('package demo')
        selected = 'demo.go'
    else:
        (root / 'service.js').write_text('export const value = 1')
        (root / 'package.json').write_text(json.dumps({'scripts': {'typecheck': 'tsc', 'test': 'test-runner', 'build': 'builder'}}))
        selected = 'service.js'
    steps = FunctionalVerifierRegistry().detect(root, target_files=(selected,))
    assert steps and all(s.provider == language for s in steps)
    if language == 'go': assert './...' not in steps[0].argv()


def test_build_projection_modified_source_rejected(host, monkeypatch):
    root, _, service, name = host
    (root / 'pom.xml').write_text('<project/>')
    monkeypatch.setattr('shutil.which', lambda n: '/local/' + n)
    out = prepare(host)
    copy = Path(out['plan']['steps'][0]['working_directory'])
    (copy / name).write_text('class Forged {}')
    final = service.run(out['functional_ref'], execution_result=report(out), bound_workspace=root)
    assert final['functional_verification']['reason_code'] == 'HOST_MODIFIED_VERIFIER_INPUT'
    assert 'Forged' not in (root / name).read_text()


def test_mcp_report_schema_closed_no_cet(monkeypatch, tmp_path):
    from security_runtime.mcp_server import create_server
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setattr('security_runtime.functional_execution.LocalSandbox.availability', lambda *a: pytest.fail('CET/sandbox requested'))
    tool = create_server()._tool_manager.get_tool('run_functional_verification')
    assert set(tool.parameters['properties']) == {'functional_ref', 'execution_result'}
    assert tool.parameters['additionalProperties'] is False
    for definition in tool.parameters['$defs'].values():
        assert definition['additionalProperties'] is False
    from mcp.server.fastmcp.exceptions import ToolError
    value = dict(functional_ref='bad', execution_result={'argv': 'raw_secret_canary'})
    with pytest.raises(ToolError) as error:
        asyncio.run(tool.run(value))
    assert 'raw_secret_canary' not in str(error.value)


def test_signed_remediation_host_result_and_final_security_dimensions(setup):
    root, runtime, provider, remediation, hook, _ = setup
    values = args(setup)
    remediation.prepare(values['remediation_ref'], values['task_ref'], root)
    (root / 'A.java').write_text(FIXED)
    runtime.findings = provider.findings = []
    assert hook()['remediation']['verification']['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    service = FunctionalVerificationService(remediation)
    out = service.prepare(values['remediation_ref'], values['task_ref'], root, bound_workspace=root)
    assert out['status'] == 'FUNCTIONAL_VERIFICATION_READY'
    final = service.run(out['functional_ref'], execution_result=report(out, 1), bound_workspace=root)
    checked = remediation.verify(values['remediation_ref'], values['task_ref'], root)
    merged = service.finalize(values['remediation_ref'], values['task_ref'], root, checked)
    assert merged['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert merged['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert merged['functional_status'] == 'FUNCTIONAL_FAILED'
    assert merged['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert merged['functional_verification']['status'] == 'FAILED'
    assert merged['overall_status'] == 'SECURITY_VERIFIED_FUNCTION_FAILED'
    assert merged['remediation_stage'] == 'CLOSED'
