"""Unsupported formats must not block supported comparisons or invent proof."""
import subprocess
from dataclasses import replace

import pytest

from security_runtime.baseline_coverage import comparison_usable
from security_runtime.global_workspace import source_snapshot
from security_runtime.hook_runtime import capture_snapshot, covered
from security_runtime.models import ScannerRun
from security_runtime.rule_coverage import plan_rules
from security_runtime.rulepacks import RulePackManager
from security_runtime.target import DiscoveryLimitError
from test_hook_runtime import repo
from test_codex_integration import adapter, call
from test_hook_runtime import FakeRuntime


@pytest.mark.parametrize('snapshot', [capture_snapshot, source_snapshot])
def test_large_binary_document_excluded_but_conversion_to_text_is_observed(repo, snapshot):
    path = repo / 'document.docx'
    path.write_bytes(b'PK\x03\x04' + b'x' * 1_100_000)
    subprocess.run(['git', '-C', str(repo), 'add', 'document.docx'], check=True)
    subprocess.run(['git', '-C', str(repo), 'commit', '-qm', 'document'], check=True)
    before = snapshot(repo, b'k' * 32)
    assert 'document.docx' not in before.file_digests
    assert before.target_selection['excluded_count'] == 1
    path.write_text('plain text credential input must remain eligible\n')
    after = snapshot(repo, b'k' * 32)
    assert 'document.docx' in after.file_digests
    assert after.file_digests != before.file_digests
    assert after.target_selection['excluded_count'] == 0


@pytest.mark.parametrize('snapshot', [capture_snapshot, source_snapshot])
@pytest.mark.parametrize('name', ['document.docx', 'large.ts', '.env', 'package-lock.json'])
def test_oversized_relevant_text_still_rejected(repo, snapshot, name):
    (repo / name).write_bytes(b'x' * 1_000_001)
    with pytest.raises(DiscoveryLimitError):
        snapshot(repo, b'k' * 32)


def partial_plan(files=('app.ts', 'Component.vue')):
    plan = plan_rules(RulePackManager().resolve(), list(files))
    # Model a provider plan with an unsupported-format gap. The current bundled
    # pack also supports Vue, so do not infer this fixture from its live catalog.
    plan.files = tuple(name for name in plan.files if not name.endswith('.vue'))
    if not plan.files:
        plan.rules = ()
    plan.observe({'time': {'rules': [r.rule_id for r in plan.rules]},
                  'paths': {'scanned': list(plan.files)}}, plan.files)
    run = ScannerRun('semgrep', '1.178.0', 'SUCCESS' if plan.rules else 'NOT_COVERED', 1,
                     provider='semgrep')
    result = {'status': 'PARTIAL', 'coverage': 'PARTIAL',
              'capabilities': {'CODE_SAST': plan.coverage('SUCCESS')['status'], 'SECRET_SCAN': 'EXECUTED'}}
    return result, {'plans': {'semgrep': plan}, 'runs': [run]}


@pytest.mark.parametrize('files', [('app.ts', 'Component.vue'), ('Component.vue',)])
def test_planned_vue_gap_keeps_partial_coverage_but_allows_comparison(files):
    result, observation = partial_plan(files)
    before = result.copy()
    assert comparison_usable(result, observation)
    assert result == before and result['capabilities']['CODE_SAST'] != 'EXECUTED'
    plan = observation['plans']['semgrep']
    family = {'scanner_sources': ['semgrep'], 'file_path': 'Component.vue', 'rule_id': 'fixture', 'proof': {}}
    assert not covered(family, observation['runs'], observation['plans'])
    assert 'Component.vue' not in plan.scanned_files


@pytest.mark.parametrize('cause', ['rules', 'files', 'parser', 'unscoped', 'skip', 'timeout', 'contract', 'secrets', 'unknown-plan'])
def test_vue_gap_never_excuses_missing_or_failed_engine_evidence(cause):
    result, observation = partial_plan()
    plan = observation['plans']['semgrep']
    if cause == 'rules': plan.confirmed_rules.clear()
    elif cause == 'files': plan.scanned_files.clear()
    elif cause == 'parser': plan.errored_files.update(plan.files)  # no supported file has proof
    elif cause == 'unscoped': plan.unscoped_error = True
    elif cause == 'skip': plan.skipped_files['app.ts'] = 'too_big'
    elif cause == 'timeout': observation['runs'][0].status = 'TIMEOUT'
    elif cause == 'contract': observation['runs'][0].coverage_contract = 'PARTIAL'
    elif cause == 'secrets': result['capabilities']['SECRET_SCAN'] = 'FAILED'
    elif cause == 'unknown-plan': observation['plans'].clear()
    assert not comparison_usable(result, observation)


def test_local_parser_gap_allows_other_files_but_remains_unproven():
    from security_runtime.baseline_coverage import unproven_files
    result, observation = partial_plan(('good.ts', 'broken.ts', 'Component.vue'))
    plan = observation['plans']['semgrep']
    plan.errored_files.add('broken.ts')
    assert comparison_usable(result, observation)
    assert unproven_files(observation) == ['Component.vue', 'broken.ts']
    assert plan.coverage('SUCCESS')['status'] == 'PARTIAL'


def test_new_risk_in_preedit_parser_gap_is_unattributed(adapter, repo):
    from security_runtime.hook_runtime import HookCoordinator
    from test_hook_runtime import row
    (repo / 'good.ts').write_text('export const value = 1;\n')
    runtime = adapter.baselines.coordinator.runtime
    original = runtime.scan
    def partial_scan(*args, **kwargs):
        result = original(*args, **kwargs)
        partial, observation = partial_plan(('A.java', 'good.ts'))
        observation['plans']['semgrep'].errored_files.add('A.java')
        partial['capabilities']['CODE_SAST'] = observation['plans']['semgrep'].coverage('SUCCESS')['status']
        kwargs['observer']([], observation['runs'], observation['plans'])
        return replace(result, status='PARTIAL', coverage='PARTIAL', execution_state='EXECUTED',
                       capability_results=partial['capabilities'], scanner_runs=observation['runs'])
    runtime.scan = partial_scan
    assert call(adapter, repo)['baseline']['status'] == 'READY'
    seed, _ = adapter.baselines.load(repo)
    assert seed['unproven_sast_files'] == ['A.java']
    runtime.scan = original
    runtime.findings = [row(repo)]
    (repo / 'A.java').write_text('class A { int edited; }\n')
    core = HookCoordinator(runtime, adapter.baselines.coordinator.store, seeds=adapter.baselines, cooldown_ms=0)
    value = core.handle('FILE_CHANGED', repo, 'codex', 'scope-gap')
    assert value['delta']['new'] == 0 and value['delta']['additional_occurrences'] == 0
    assert value['delta']['families'][0]['status'] == 'UNATTRIBUTED_FAMILY'
    assert value['last_check_status'] == 'PARTIAL' and value['unattributed_code_risk_count'] == 1
    state, _ = core.store.load(core.store.path(repo, 'codex', 'scope-gap'))
    assert state['unproven_sast_files'] == ['A.java']
    runtime.findings.append(row(repo, file='good.ts'))
    (repo / 'good.ts').write_text('export const value = 2;\n')
    assert core.handle('FILE_CHANGED', repo, 'codex', 'scope-gap')['delta']['new'] == 1


def test_large_document_setup_baseline_and_dirty_capture_share_selection(adapter, repo):
    (repo / 'document.docx').write_bytes(b'PK\x03\x04' + b'x' * 1_100_000)
    result = call(adapter, repo)
    assert result['baseline']['status'] == 'READY'
    state, _ = adapter.baselines.load(repo)
    assert 'document.docx' not in state['file_digests']
    assert 'document.docx' not in adapter.baselines.coordinator.runtime.calls[0]


def test_partial_seed_preserves_gap_and_reloads_as_comparison(adapter, repo):
    (repo / 'app.ts').write_text('export const value = 1;\n')
    (repo / 'Component.vue').write_text('<template><div>fixture</div></template>\n')
    runtime = adapter.baselines.coordinator.runtime
    original = runtime.scan
    def scan(*args, **kwargs):
        result = original(*args, **kwargs)
        partial, observation = partial_plan(('A.java', 'app.ts', 'Component.vue'))
        kwargs['observer']([], observation['runs'], observation['plans'])
        return replace(result, status='PARTIAL', coverage='PARTIAL', execution_state='EXECUTED',
                       capability_results=partial['capabilities'], scanner_runs=observation['runs'])
    runtime.scan = scan
    assert call(adapter, repo)['baseline']['status'] == 'READY'
    state, status = adapter.baselines.load(repo)
    assert status == 'READY'
    assert state['last_result']['coverage'] == 'PARTIAL'
    assert state['last_result']['capabilities']['CODE_SAST'] == 'PARTIAL'


@pytest.mark.parametrize('failure', [False, True])
def test_non_git_partial_baseline_readiness_and_reconnect(tmp_path, failure):
    from security_runtime.global_mcp import GlobalWorkspaces
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.hook_state import HookStateStore
    root = tmp_path / 'source'; root.mkdir()
    (root / 'app.ts').write_text('export const value = 1;\n')
    (root / 'Component.vue').write_text('<template><div>fixture</div></template>\n')
    (root / 'document.docx').write_bytes(b'PK\x03\x04' + b'x' * 1_100_000)
    runtime = FakeRuntime()
    original = runtime.scan
    def scan(*args, **kwargs):
        result = original(*args, **kwargs)
        partial, observation = partial_plan()
        if failure:
            observation['plans']['semgrep'].confirmed_rules.clear()
        kwargs['observer']([], observation['runs'], observation['plans'])
        return replace(result, status='PARTIAL', coverage='PARTIAL', execution_state='EXECUTED',
                       capability_results=partial['capabilities'], scanner_runs=observation['runs'])
    runtime.scan = scan
    core = HookCoordinator(runtime, HookStateStore(tmp_path / 'state/hooks'),
                           workspace_resolver=lambda _: root, snapshot_capture=source_snapshot)
    pool = GlobalWorkspaces(base=tmp_path / 'state/workspaces', integration=object())
    try:
        first = pool._initialize(root, 'fixture-session', core)
        repeated = pool._initialize(root, 'fixture-session', core)
        for value in (first, repeated):
            assert value['status'] == 'READY'
            assert value['initial_scope'] == 'SESSION_COMPARISON_ONLY'
            assert value['project_scan_status'] == 'NOT_REQUESTED'
            assert value['scanner_run'] is False
            assert value['security_proof'] is False
        assert len(runtime.calls) == 0
        (root / 'app.ts').write_text('export const value = 2;\n')
        core.cooldown_ms = 0
        core.handle('FILE_CHANGED', root, 'codex', 'fixture-session')
        after_edit = pool._initialize(root, 'fixture-session', core)
        assert after_edit['status'] == 'READY'
        assert after_edit['security_proof'] is False
    finally:
        pool.close()
