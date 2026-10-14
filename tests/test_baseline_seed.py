"""First effective Hook must compare to setup, not absorb an unobserved edit."""
import copy
import hashlib
import hmac
import json
import subprocess

import pytest

from test_hook_runtime import repo, row
from test_codex_integration import adapter, call, config
from test_codex_mcp_hook import binding as workspace_binding
from test_remediation import SavedRuntime, UNSAFE, FIXED
from test_task_fix import LocalProvider
from security_runtime.baseline_seed import encode
from security_runtime.codex_integration import product_hooks
from security_runtime.codex_mcp_hook import handle_codex_hook
from security_runtime.hook_runtime import HookCoordinator, validate_state
from security_runtime.hook_state import HookStateStore
from security_runtime.remediation import RemediationService
from security_runtime.remediation_policy import RULE
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.integration_lifecycle import render_integration


def finding(root, file='A.java'):
    f = row(root, 6, RULE, category='trust-all-tls', file=file)
    f.technical_details.update(rule_pack='ai-security-core', rule_pack_checksum='a'*64,
        rule_pack_version='0.1', engine='semgrep')
    return f


def sign(adapter, root, value):
    key = adapter.store.key(root)
    value.pop('signature', None)
    adapter.baselines.path(root).write_bytes(encode({**value,
        'signature': hmac.new(key, encode(value), hashlib.sha256).hexdigest()}))


def hook(core, service, root, session='first'):
    return handle_codex_hook('PostToolUse', str(root), session, 'apply_patch',
        binding=workspace_binding(root), coordinator=core, remediation=service)


def services(adapter, repo, tmp_path):
    store = SQLiteStore(tmp_path / 'db/scans.db'); runtime = SavedRuntime(store)
    core = HookCoordinator(runtime, adapter.baselines.coordinator.store, cooldown_ms=0, seeds=adapter.baselines)
    service = RemediationService(store, hooks=core.store, registry=ScannerRegistry([LocalProvider()]))
    return runtime, core, service


def test_setup_clean_signed_projection_no_session_no_remediation(adapter, repo):
    result = call(adapter, repo)
    assert result['baseline']['status'] == 'READY'
    assert result['hook_trust'] == 'HOST_MANAGED_UNKNOWN'
    snapshot, status = adapter.baselines.load(repo)
    assert status == 'READY' and not snapshot['families']
    assert snapshot['last_result']['status'] == 'PRE_EXISTING_BASELINE'
    validate_state(snapshot)
    assert len(adapter.baselines.coordinator.runtime.calls) == 1
    assert not list(adapter.baselines.coordinator.store.workspace_directory(repo).glob('*.json'))
    assert not (adapter.store.directory.parent / 'remediation.json').exists()
    assert str(repo) not in adapter.baselines.path(repo).read_text()


@pytest.mark.parametrize('skip_safe_edit', [False, True])
def test_missing_first_hook_new_untracked_file_requires_confirmation(adapter, repo, tmp_path, skip_safe_edit):
    assert call(adapter, repo)['baseline']['status'] == 'READY'
    runtime, core, service = services(adapter, repo, tmp_path)
    source = repo / 'NewService.java'
    assert not source.exists()
    source.write_text(FIXED)
    if not skip_safe_edit:
        safe = hook(core, service, repo)
        assert safe['baseline_source'] == 'SETUP_SEED' and safe['new_families'] == 0
    # When skipped, this dangerous edit is the first-ever effective event.
    source.write_text(UNSAFE)
    runtime.findings = [finding(repo, 'NewService.java')]
    result = hook(core, service, repo)
    assert result['baseline_source'] == ('SETUP_SEED' if skip_safe_edit else 'SESSION')
    assert result['baseline_available'] and result['scanner_run'] and result['new_families'] == 1
    assert result['status'] != 'BASELINE_ESTABLISHED'
    pending = result['remediation']
    assert pending['action'] == 'CONFIRM_REQUIRED' and pending['status'] == 'PENDING_CONFIRMATION'
    assert not {'prepare', 'verify', 'remediation_ref'} & pending.keys()
    assert not service.authorized and not service.prepared
    assert source.read_text() == UNSAFE
    approved = service.confirm(pending['confirmation_ref'], pending['task_ref'], repo, approve=True)
    assert approved['status'] == 'AUTHORIZED' and approved['action'] == 'AUTO_FIX'
    assert approved['authorization_kind'] == 'USER_CONFIRMED'
    assert source.read_text() == UNSAFE


def test_preexisting_tracked_finding_persists_not_new(adapter, repo, tmp_path):
    (repo / 'A.java').write_text(UNSAFE)
    subprocess.run(['git', '-C', str(repo), 'add', 'A.java'], check=True)
    subprocess.run(['git', '-C', str(repo), 'commit', '-m', 'preexisting'], check=True, capture_output=True)
    seed_runtime = adapter.baselines.coordinator.runtime
    seed_runtime.findings = [finding(repo)]
    call(adapter, repo)
    snapshot, _ = adapter.baselines.load(repo)
    assert len(snapshot['families']) == 1
    runtime, core, service = services(adapter, repo, tmp_path)
    runtime.findings = [finding(repo)]
    (repo / 'A.java').write_text(UNSAFE + '// ordinary edit\n')
    result = hook(core, service, repo)
    assert result['persisting_families'] == 1 and result['new_families'] == 0
    assert result['remediation']['action'] == 'NONE'


def test_preexisting_clean_file_other_file_edit_retains_candidate_scope(adapter, repo, tmp_path):
    (repo / 'A.java').write_text(UNSAFE)
    subprocess.run(['git', '-C', str(repo), 'add', 'A.java'], check=True)
    subprocess.run(['git', '-C', str(repo), 'commit', '-m', 'preexisting'], check=True, capture_output=True)
    adapter.baselines.coordinator.runtime.findings = [finding(repo)]
    call(adapter, repo); runtime, core, service = services(adapter, repo, tmp_path)
    runtime.findings = [finding(repo)]
    (repo / 'New.java').write_text('class New {}')
    result = hook(core, service, repo)
    assert result['persisting_families'] == 1 and not result['new_families']
    assert 'A.java' in runtime.calls[-1] and result['remediation']['action'] == 'NONE'
    (repo / 'New.java').write_text('class New { int count; }')
    assert hook(core, service, repo)['persisting_families'] == 1


def test_session_becomes_authoritative_seed_not_reread(adapter, repo, tmp_path, monkeypatch):
    call(adapter, repo); runtime, core, service = services(adapter, repo, tmp_path)
    (repo / 'A.java').write_text(FIXED); hook(core, service, repo)
    monkeypatch.setattr(adapter.baselines, 'load', lambda *a: pytest.fail('seed overwrote session'))
    (repo / 'A.java').write_text(UNSAFE); runtime.findings = [finding(repo)]
    assert hook(core, service, repo)['new_families'] == 1


@pytest.mark.parametrize('mutation', ['tamper', 'workspace', 'runtime', 'rules', 'schema', 'unknown', 'oversize', 'future', 'providers'])
def test_seed_rejects_tampered_foreign_incompatible_bounded_metadata(adapter, repo, mutation):
    call(adapter, repo); path = adapter.baselines.path(repo)
    value = json.loads(path.read_bytes())
    if mutation == 'oversize':
        path.write_bytes(b'x' * 2_000_001)
    elif mutation == 'tamper':
        value['created_at'] = 1; path.write_bytes(encode(value))
    else:
        if mutation == 'workspace': value['binding']['workspace_id'] = 'a'*64
        elif mutation == 'runtime': value['binding']['runtime_version'] = 'old'
        elif mutation == 'rules': value['binding']['rule_pack'] = 'b'*64
        elif mutation == 'schema': value['schema'] = 'old'
        elif mutation == 'unknown': value['snapshot']['raw_secret'] = 'CANARY_DO_NOT_ECHO'
        elif mutation == 'future': value['created_at'] = 10**12
        elif mutation == 'providers': value['binding']['scanner_versions']['semgrep'] = 'old'
        sign(adapter, repo, value)
    assert adapter.baselines.load(repo) == (None, 'STALE')
    assert call(adapter, repo, 'status')['overall'] == 'DEGRADED'
    assert 'CANARY_DO_NOT_ECHO' not in json.dumps(call(adapter, repo, 'status'))


def test_source_change_does_not_stale_seed(adapter, repo):
    call(adapter, repo); path = adapter.baselines.path(repo); original = path.read_bytes()
    (repo / 'New.java').write_text(UNSAFE)
    assert adapter.baselines.load(repo)[1] == 'READY' and path.read_bytes() == original
    assert call(adapter, repo)['baseline']['operation'] == 'BASELINE_READY'
    assert len(adapter.baselines.coordinator.runtime.calls) == 1


def test_lifecycle_no_scan_healthy_repair_missing_seed_remove_reinstall(adapter, repo):
    call(adapter, repo); path = adapter.baselines.path(repo)
    calls = adapter.baselines.coordinator.runtime.calls
    before = path.read_bytes(), path.stat().st_mtime_ns
    for action in ('setup', 'repair', 'status'):
        assert call(adapter, repo, action)['baseline']['status'] == 'READY'
    assert len(calls) == 1 and before == (path.read_bytes(), path.stat().st_mtime_ns)
    path.unlink()
    repaired = call(adapter, repo, 'repair')
    assert repaired['baseline']['status'] == 'READY' and len(calls) == 2
    assert repaired['baseline']['operation'] == 'BASELINE_REESTABLISHED'
    assert call(adapter, repo, 'remove')['overall'] == 'NOT_INSTALLED' and not path.exists()
    assert (repo / 'A.java').exists()
    assert call(adapter, repo)['baseline']['status'] == 'READY' and len(calls) == 3


@pytest.mark.parametrize('status', ['FAILED', 'UNAVAILABLE', 'TIMEOUT'])
def test_setup_failure_configured_but_not_baseline_ready(adapter, repo, status):
    adapter.baselines.coordinator.runtime.status = status
    value = call(adapter, repo)
    assert value['installation'] == 'CONFIGURED' and value['overall'] == 'DEGRADED'
    assert value['baseline']['status'] == 'INCONCLUSIVE'
    assert adapter.baselines.load(repo) == (None, 'INCONCLUSIVE')


def test_workspace_budget_fail_closed_before_scanner(adapter, repo):
    (repo / 'large.java').write_bytes(b'x' * 1_000_001)
    value = call(adapter, repo)
    assert value['baseline']['status'] == 'INCONCLUSIVE'
    assert not adapter.baselines.coordinator.runtime.calls


@pytest.mark.parametrize('cause', ['coverage', 'scope-change', 'deadline'])
def test_incomplete_moving_or_cancelled_scan_cannot_seed(adapter, repo, cause):
    runtime = adapter.baselines.coordinator.runtime
    scan = runtime.scan
    def broken(*a, **k):
        if cause == 'deadline':
            k['progress'].started -= 61
            k['progress'].checkpoint()
        result = scan(*a, **k)
        if cause == 'coverage':
            result.coverage = 'PARTIAL'; result.capability_results['CODE_SAST'] = 'PARTIAL'
        else:
            (repo / 'New.java').write_text('class New {}')
        return result
    runtime.scan = broken
    value = call(adapter, repo)
    assert value['baseline']['status'] == 'INCONCLUSIVE' and value['overall'] == 'DEGRADED'
    assert adapter.baselines.load(repo) == (None, 'INCONCLUSIVE')


def test_seed_stale_repair_reestablish_explicit_diagnostic(adapter, repo):
    call(adapter, repo)
    value = json.loads(adapter.baselines.path(repo).read_bytes())
    value['binding']['rule_pack'] = 'b'*64; sign(adapter, repo, value)
    assert call(adapter, repo, 'status')['baseline']['reason'] == 'BASELINE_SEED_STALE'
    assert call(adapter, repo, 'repair')['baseline']['operation'] == 'BASELINE_REESTABLISHED'


def test_no_findings_without_seed_remains_quiet(adapter, repo, tmp_path):
    runtime, core, service = services(adapter, repo, tmp_path)
    (repo / 'A.java').write_text(FIXED)
    result = hook(core, service, repo)
    assert result['new_families'] == 0 and not result.get('systemMessage') and 'reason' not in result


def test_seed_state_link_rejected_without_target_write(adapter, repo, tmp_path):
    call(adapter, repo); path = adapter.baselines.path(repo); path.unlink()
    target = tmp_path / 'foreign'; target.write_text('DO_NOT_TOUCH')
    try: path.symlink_to(target)
    except OSError: pytest.skip('symlink privilege unavailable')
    assert adapter.baselines.load(repo) == (None, 'STALE')
    assert call(adapter, repo, 'repair')['baseline']['status'] == 'INCONCLUSIVE'
    assert target.read_text() == 'DO_NOT_TOUCH'


def test_seed_secret_source_not_persisted(adapter, repo):
    canary = 'fixture_private_credential_do_not_store'
    (repo / 'A.java').write_text(canary)
    adapter.baselines.coordinator.runtime.findings = [row(repo, category='secret', evidence=canary)]
    call(adapter, repo)
    raw = adapter.baselines.path(repo).read_text()
    assert canary not in raw and hashlib.sha256(canary.encode()).hexdigest() not in raw
    assert 'UNTRUSTED_CODE' not in raw and str(repo) not in raw


@pytest.mark.parametrize('bad_seed', [False, True])
def test_no_seed_high_risk_explicit_diagnostic_no_auto_fix(adapter, repo, tmp_path, bad_seed):
    if bad_seed:
        call(adapter, repo); adapter.baselines.path(repo).write_text('CORRUPT_DO_NOT_ECHO')
    runtime, core, service = services(adapter, repo, tmp_path)
    runtime.findings = [finding(repo)]; (repo / 'A.java').write_text(UNSAFE)
    result = hook(core, service, repo)
    assert result['status'] == 'BASELINE_ESTABLISHED' and not result['baseline_available']
    assert result['new_families'] == 0 and result['remediation']['action'] == 'NONE'
    assert result['reason'] == 'FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT'
    assert '无法确认是否由本次改动引入' in result['systemMessage']
    assert 'FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT' not in result['systemMessage']
    assert 'CORRUPT_DO_NOT_ECHO' not in json.dumps(result)


def test_trust_ux_and_free_v1_exact_hook_abi(adapter, repo):
    value = call(adapter, repo)
    text = render_integration(value)
    assert 'review and allow' in text and 'HOST_MANAGED_UNKNOWN' in text
    assert 'not proof' in text and 'warm-up' in text
    # Freeze the complete generated definition, not merely tool names.
    expected = json.loads((__import__('pathlib').Path(__file__).parents[1] / 'docs/continuation-hooks-example.json').read_text(encoding='utf-8'))
    assert product_hooks() == expected
