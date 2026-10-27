"""Owned lifecycle, malformed/untrusted config, readiness and verification protocol."""
import asyncio
import copy
import json
import os
import time
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from test_hook_runtime import repo
from test_remediation import setup, prepare, args, FIXED
from test_codex_mcp_hook import binding as workspace_binding
from security_runtime.codex_integration import (CodexIntegrationAdapter, REQUIRED_TOOLS, MAX_CONFIG,
    check_capabilities, current_runtime, fingerprint, product_hooks, validated_workspace)
from security_runtime.integration_lifecycle import IntegrationDiagnostic, IntegrationManager, render_integration
from security_runtime.integration_readiness import handle_readiness
from security_runtime.guidance.host_guidance import runtime_info, HOST_INSTRUCTIONS


@pytest.fixture
def adapter(repo, tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    from test_hook_runtime import FakeRuntime
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.hook_state import HookStateStore
    runtime = FakeRuntime()
    original = runtime.scan
    def complete(*a, **k):
        result = original(*a, **k); result.coverage = 'FULL'; return result
    runtime.scan = complete
    return CodexIntegrationAdapter(directory=tmp_path / 'state/codex-integrations',
        probe=lambda *a: check_capabilities(runtime_info(), REQUIRED_TOOLS),
        baseline_coordinator=HookCoordinator(runtime, HookStateStore(tmp_path / 'state/hooks')))


def config(root):
    return root / '.codex/config.toml', root / '.codex/hooks.json'


def write(root, toml=b'', hooks=None):
    a, b = config(root); a.parent.mkdir(exist_ok=True)
    a.write_bytes(toml)
    if hooks is not None:
        b.write_text(json.dumps(hooks), encoding='utf-8')


def call(adapter, root, action='setup'):
    return IntegrationManager(adapter).execute(action, 'codex', str(root))


def observe(adapter, root, session='fresh-session'):
    return handle_readiness('SessionStart', str(root), session, binding=workspace_binding(root),
                            tools=REQUIRED_TOOLS, adapter=adapter)


def test_setup_idempotent_preserves_all_unrelated_bytes_and_mode(adapter, repo):
    unrelated = b'# user comment\nmodel = "test"\n[mcp_servers.other]\ncommand = "other"\n'
    hook = {'type': 'command', 'command': 'echo keep', 'timeout': 4}
    original = {'note': 'keep', 'hooks': {'PostToolUse': [{'matcher': 'Read', 'hooks': [hook]}],
                                       'Stop': [{'hooks': [hook]}]}}
    write(repo, unrelated, original)
    assert call(adapter, repo)['operation'] == 'CONFIGURED'
    a, b = config(repo)
    assert a.read_bytes().startswith(unrelated)
    parsed = tomllib.loads(a.read_text())['mcp_servers']
    assert parsed['other'] == {'command': 'other'}
    entry = parsed['ai_security_runtime']
    assert entry['required'] is True and entry['enabled'] is True
    assert entry['args'][-1] == 'mcp' and '-I' in entry['args']
    assert entry['env']['SECURITY_RUNTIME_WORKSPACE'] == str(repo)
    assert not (Path(os.environ['SECURITY_RUNTIME_STATE_DIR']) / 'remediation.json').exists()
    snapshots = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (a, b, adapter._state_path(repo, 'ownership.json'))}
    for _ in range(2):
        assert call(adapter, repo)['operation'] == 'ALREADY_CONFIGURED'
        assert snapshots == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in snapshots}
    value = json.loads(b.read_bytes())
    assert value['note'] == 'keep' and value['hooks']['Stop'][0] == original['hooks']['Stop'][0]
    assert value['hooks']['Stop'][1] == product_hooks()['hooks']['Stop'][0]
    assert value['hooks']['PostToolUse'][0] == original['hooks']['PostToolUse'][0]
    assert len(value['hooks']['SessionStart']) == 1


@pytest.mark.parametrize('mode', ['smart_auto', 'ask_before_fix', 'report_only'])
def test_setup_never_resets_mode(adapter, repo, mode):
    from security_runtime.remediation_policy import RemediationConfig
    preferences = RemediationConfig(); preferences.write(mode)
    before = preferences.path.read_bytes()
    assert call(adapter, repo)['mode'] == ('ask_before_fix' if mode == 'smart_auto' else mode)
    assert preferences.path.read_bytes() == before


def test_status_readonly_missing_configured_observed_stale(adapter, repo):
    assert call(adapter, repo, 'status')['overall'] == 'NOT_INSTALLED'
    assert not adapter.store.directory.exists()
    assert call(adapter, repo)['overall'] == 'CONFIGURED'
    assert observe(adapter, repo)['status'] == 'CONNECTED'
    output = call(adapter, repo, 'status')
    assert output['overall'] == 'READY' and output['live_connection'] == 'UNKNOWN'
    assert output['cold_start_host_trial'] == 'PENDING_ACTUAL_DESKTOP'
    raw = json.dumps(output)
    assert str(repo) not in raw and str(adapter.store.directory) not in raw
    observed = observe(adapter, repo)
    assert observed['systemMessage'] == observed['message']
    assert observed['startup_comparison_baseline']['required'] is False
    assert observed['scan_preparation']['verified_now'] is False
    assert '通过安全检查' not in observed['systemMessage']
    assert observed['status'] == 'CONNECTED' and observed['readiness'] == 'READINESS_OBSERVED'
    assert observed['execution'] == {'scan': False, 'scanner_run': False, 'model': False,
                                     'source_modified': False, 'target_build': False,
                                     'network': False, 'remediation': False}
    assert observed['security_proof'] is False and 'scan_id' not in observed
    adapter.now = lambda: time.time() + 901
    assert call(adapter, repo, 'status')['readiness']['status'] == 'READINESS_STALE'


def test_readiness_bounded_idempotent_no_source_scan_build_model(adapter, repo, monkeypatch):
    call(adapter, repo)
    from security_runtime.hook_runtime import HookCoordinator
    monkeypatch.setattr(HookCoordinator, 'handle', lambda *a: pytest.fail('readiness invoked scanner'))
    before = (repo / 'A.java').read_bytes()
    result = observe(adapter, repo, 'session-with-secret-canary')
    assert result['status'] == 'CONNECTED' and not any(result['execution'].values())
    path = adapter._state_path(repo, 'readiness.json')
    raw = path.read_bytes(); modified = path.stat().st_mtime_ns
    assert len(raw) < 4096 and b'session-with-secret-canary' not in raw
    assert str(repo).encode() not in raw and b'safe' not in raw
    assert (repo / 'A.java').read_bytes() == before
    assert observe(adapter, repo, 'session-with-secret-canary')['status'] == 'CONNECTED'
    assert (raw, modified) == (path.read_bytes(), path.stat().st_mtime_ns)
    assert not (Path(os.environ['SECURITY_RUNTIME_STATE_DIR']) / 'scans.db').exists()


@pytest.mark.parametrize('bad', [b'{malformed', b'x' * 4097], ids=['malformed', 'oversize'])
def test_bad_readiness_cannot_claim_ready_and_new_bound_event_recovers(adapter, repo, bad):
    call(adapter, repo)
    path = adapter._state_path(repo, 'readiness.json'); path.write_bytes(bad)
    assert call(adapter, repo, 'status')['readiness']['status'] == 'READINESS_STALE'
    assert observe(adapter, repo)['status'] == 'CONNECTED'
    assert len(path.read_bytes()) <= 4096
    assert call(adapter, repo, 'status')['overall'] == 'READY'


@pytest.mark.parametrize('event,path,session', [('Stop', None, 'x'), ('SessionStart', '../outside', 'x'),
    ('SessionStart', '//host/share', 'x'), ('SessionStart', None, ''), ('SessionStart', None, '${session_id}'),
    ('SessionStart', None, 'x' * 501), ('SessionStart', None, 'x\nsecret'), ('SessionStart', None, 10)])
def test_readiness_host_claims_fail_closed(adapter, repo, event, path, session):
    call(adapter, repo)
    result = handle_readiness(event, path or str(repo), session, binding=workspace_binding(repo), tools=REQUIRED_TOOLS, adapter=adapter)
    assert result['status'] == 'INCONCLUSIVE' and not any(result['execution'].values())
    assert not adapter._state_path(repo, 'readiness.json').exists()


def test_unbound_foreign_and_missing_capability_readiness(adapter, repo, tmp_path):
    call(adapter, repo)
    for binding, path, tools in [(None, repo, REQUIRED_TOOLS), (workspace_binding(repo), tmp_path, REQUIRED_TOOLS),
                                (workspace_binding(repo), repo, REQUIRED_TOOLS - {'handle_hook_event'})]:
        result = handle_readiness('SessionStart', str(path), 's', binding=binding, tools=tools, adapter=adapter)
        assert result['status'] == 'INCONCLUSIVE'


@pytest.mark.parametrize('bad', [b'{"hooks":', b'{"hooks":[]}', b'{"hooks":{"PostToolUse":{}}}',
    b'{"hooks":{"PostToolUse":[{"hooks":[{"type":"unknown"}]}]}}', b'{"hooks":{},"hooks":{}}', b' ' * (MAX_CONFIG + 1)], ids=['malformed', 'array', 'group-type', 'handler-type', 'duplicates', 'oversize'])
def test_malformed_json_unchanged(adapter, repo, bad):
    write(repo); _, b = config(repo); b.write_bytes(bad)
    assert call(adapter, repo)['diagnostics'] == ['CONFIG_INVALID']
    assert b.read_bytes() == bad and config(repo)[0].read_bytes() == b''


@pytest.mark.parametrize('bad', [b'[mcp_servers', b'mcp_servers=[]', b'features=[]', b'hooks=[]', b'x="\xff"', b'#' * (MAX_CONFIG + 1)], ids=['malformed', 'servers-type', 'features-type', 'hooks-type', 'encoding', 'oversize'])
def test_malformed_toml_unchanged(adapter, repo, bad):
    write(repo, bad)
    assert call(adapter, repo)['diagnostics'] == ['CONFIG_INVALID']
    assert config(repo)[0].read_bytes() == bad


@pytest.mark.parametrize('action', ['setup', 'repair', 'remove'])
def test_unowned_same_name_conflict_never_overwritten(adapter, repo, action):
    raw = b'[mcp_servers.ai_security_runtime]\ncommand="user-owned"\n'
    write(repo, raw)
    assert call(adapter, repo, action)['diagnostics'] == ['MCP_CONFIGURATION_CONFLICT']
    assert config(repo)[0].read_bytes() == raw


def test_signed_manifest_and_marker_are_both_required(adapter, repo):
    call(adapter, repo); a, _ = config(repo)
    raw = a.read_bytes().replace(b'required = true', b'required = false')
    a.write_bytes(raw)
    assert call(adapter, repo, 'repair')['diagnostics'] == ['MCP_CONFIGURATION_CONFLICT']
    assert a.read_bytes() == raw


def test_manifest_tampering_rejected(adapter, repo):
    call(adapter, repo)
    path = adapter._state_path(repo, 'ownership.json')
    value = json.loads(path.read_bytes()); value['workspace_hash'] = 'a' * 64
    path.write_text(json.dumps(value))
    assert call(adapter, repo, 'status')['diagnostics'] == ['OWNERSHIP_INVALID']


def test_missing_owned_parts_restore_only_owned(adapter, repo):
    call(adapter, repo); a, b = config(repo)
    a.write_bytes(b'# user config retained\nmodel="keep"\n')
    b.write_text('{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"keep"}]}]}}')
    assert call(adapter, repo, 'status')['overall'] == 'DEGRADED'
    assert call(adapter, repo, 'repair')['operation'] == 'REPAIRED'
    assert a.read_bytes().startswith(b'# user config retained\nmodel="keep"\n')
    assert json.loads(b.read_bytes())['hooks']['Stop'][0]['hooks'][0]['command'] == 'keep'


def test_missing_readiness_hook_does_not_misreport_posttool_status(adapter, repo):
    call(adapter, repo); observe(adapter, repo)
    _, path = config(repo); value = json.loads(path.read_bytes())
    del value['hooks']['SessionStart']; path.write_text(json.dumps(value))
    status = call(adapter, repo, 'status')
    assert status['overall'] == 'DEGRADED'
    assert status['post_tool_hook']['status'] == 'CONFIGURED'
    assert status['readiness']['hook_status'] == 'HOOK_MISSING'
    assert status['readiness']['status'] == 'READINESS_STALE'


def test_owned_stale_runtime_repair_invalidates_readiness(adapter, repo, tmp_path):
    call(adapter, repo); observe(adapter, repo)
    previous = adapter.discover()
    newer = tmp_path / 'new executable.exe'; newer.write_bytes(b'fixture')
    adapter.discover = lambda: {**previous, 'command': str(newer)}
    assert 'RUNTIME_STALE' in call(adapter, repo, 'status')['diagnostics']
    assert call(adapter, repo, 'repair')['operation'] == 'REPAIRED'
    assert call(adapter, repo, 'status')['readiness']['status'] == 'READINESS_STALE'
    assert tomllib.loads(config(repo)[0].read_text())['mcp_servers']['ai_security_runtime']['command'] == str(newer)


@pytest.mark.parametrize('diagnostic', ['RUNTIME_MISSING', 'RUNTIME_STALE', 'CAPABILITY_MISMATCH'])
def test_bad_own_runtime_not_configured(adapter, repo, diagnostic):
    adapter.probe = lambda *a: (_ for _ in ()).throw(IntegrationDiagnostic(diagnostic))
    assert call(adapter, repo)['diagnostics'] == [diagnostic]
    assert not config(repo)[0].exists()


def test_capability_subset_accepts_extras_rejects_stale_and_missing():
    assert check_capabilities(runtime_info(), REQUIRED_TOOLS | {'future_tool'})['status'] == 'OK'
    for info, tools, code in [(dict(runtime_info(), version='0.0.1'), REQUIRED_TOOLS, 'RUNTIME_STALE'),
                             (runtime_info(), REQUIRED_TOOLS - {'handle_readiness_event'}, 'CAPABILITY_MISMATCH'),
                             (dict(runtime_info(), features={}), REQUIRED_TOOLS, 'CAPABILITY_MISMATCH')]:
        with pytest.raises(IntegrationDiagnostic, match=code):
            check_capabilities(info, tools)


def test_current_runtime_ignores_path_and_distinguishes_frozen(monkeypatch):
    monkeypatch.setenv('PATH', 'untrusted-old-runtime')
    value = current_runtime()
    assert value['command'] == str(Path(os.sys.executable).absolute())
    assert value['prefix'] == ['-I', '-m', 'security_runtime.cli']
    monkeypatch.setattr(os.sys, 'frozen', True, raising=False)
    assert current_runtime()['kind'] == 'FROZEN' and current_runtime()['prefix'] == []


@pytest.mark.parametrize('raw', ['\\\\server\\share', '//server/share', 'C:relative', 'x\nsecret', 'x' * 4097])
def test_workspace_claims_rejected_without_scan(raw):
    with pytest.raises(IntegrationDiagnostic):
        validated_workspace(raw)


@pytest.mark.parametrize('where', ['config', 'hooks', 'directory'])
def test_symlink_configuration_rejected(adapter, repo, tmp_path, where):
    outside = tmp_path / 'outside'; outside.mkdir(); (outside / 'file').write_text('{}')
    if where == 'directory':
        destination = repo / '.codex'; target = outside; directory = True
    else:
        (repo / '.codex').mkdir(); destination = config(repo)[where == 'hooks']; target = outside / 'file'; directory = False
    try:
        destination.symlink_to(target, target_is_directory=directory)
    except OSError:
        pytest.skip('OS symlink privilege unavailable; junction exercised by native driver')
    assert call(adapter, repo)['overall'] == 'BROKEN'
    assert (outside / 'file').read_text() == '{}'


def test_concurrent_setup_has_one_server_and_hook(adapter, repo):
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: call(adapter, repo), range(2)))
    assert sorted(r['operation'] for r in results) == ['ALREADY_CONFIGURED', 'CONFIGURED']
    assert len(json.loads(config(repo)[1].read_bytes())['hooks']['PostToolUse']) == 1


def test_atomic_failure_rolls_back_and_repair_recovers(adapter, repo, monkeypatch):
    import security_runtime.codex_integration as module
    original = module.atomic_bytes
    write(repo, b'# original\n', {'hooks': {}})
    before = {p: p.read_bytes() for p in config(repo)}
    def fail(path, value):
        if path == config(repo)[1] and value != before[path]:
            raise OSError('do not disclose secret error')
        original(path, value)
    monkeypatch.setattr(module, 'atomic_bytes', fail)
    assert call(adapter, repo)['overall'] == 'BROKEN'
    assert before == {p: p.read_bytes() for p in before}
    monkeypatch.setattr(module, 'atomic_bytes', original)
    assert call(adapter, repo, 'repair')['operation'] == 'REPAIRED'


def test_duplicate_owned_hook_repair_and_remove_preserves_mixed_group(adapter, repo):
    call(adapter, repo); a, b = config(repo)
    a.write_bytes(b'# user\nmodel="keep"\n' + a.read_bytes())
    document = json.loads(b.read_bytes()); group = document['hooks']['PostToolUse'][0]
    document['hooks']['PostToolUse'].append(copy.deepcopy(group))
    extra = {'type': 'command', 'command': 'user keep'}
    group['hooks'].append(extra)
    b.write_text(json.dumps(document))
    assert 'HOOK_DUPLICATE' in call(adapter, repo, 'status')['diagnostics']
    assert call(adapter, repo, 'repair')['operation'] == 'REPAIRED'
    assert call(adapter, repo, 'remove')['overall'] == 'NOT_INSTALLED'
    assert a.read_bytes() == b'# user\nmodel="keep"\n'
    assert json.loads(b.read_bytes())['hooks']['PostToolUse'] == [{'matcher': group['matcher'], 'hooks': [extra]}]
    assert not adapter._state_path(repo, 'ownership.json').exists()
    assert call(adapter, repo)['operation'] == 'CONFIGURED'


def test_exact_legacy_generator_plus_provenance_migrates(adapter, repo):
    from security_runtime.hook_adapters import CodexHookAdapter
    from security_runtime.integration_config import IntegrationConfigStore
    write(repo, hooks={'hooks': CodexHookAdapter().config(repo)})
    IntegrationConfigStore(repo, '.codex/hooks.json')._local_exclude(add=True)
    assert 'LEGACY_HOOK_PRESENT' in call(adapter, repo, 'status')['diagnostics']
    assert call(adapter, repo)['operation'] == 'CONFIGURED'
    value = json.loads(config(repo)[1].read_bytes())
    assert all(h['type'] == 'mcp_tool' for groups in value['hooks'].values() for g in groups for h in g['hooks'])
    assert value['hooks']['Stop'] == product_hooks()['hooks']['Stop']


def test_unowned_similar_command_and_manual_poc_retained(adapter, repo):
    from security_runtime.hook_adapters import CodexHookAdapter
    for document in ({'hooks': CodexHookAdapter().config(repo)}, product_hooks()):
        write(repo, hooks=document); before = config(repo)[1].read_bytes()
        assert call(adapter, repo)['diagnostics'] == ['POTENTIAL_DUPLICATE_HOOK']
        assert config(repo)[1].read_bytes() == before


def test_disabled_local_hooks_status_degraded_no_global_edit(adapter, repo):
    write(repo, b'[features]\nhooks=false\n')
    result = call(adapter, repo)
    assert result['overall'] == 'DEGRADED' and 'HOST_HOOKS_DISABLED' in result['diagnostics']
    assert config(repo)[0].read_bytes().startswith(b'[features]\nhooks=false\n')


def test_mcp_readiness_tool_registered_closed_input(monkeypatch, tmp_path):
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE', raising=False)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    from security_runtime.mcp_server import create_server
    server = create_server()
    tools = asyncio.run(server.list_tools())
    tool = next(t for t in tools if t.name == 'handle_readiness_event')
    assert tool.inputSchema['additionalProperties'] is False
    assert set(tool.inputSchema['properties']) == {'event', 'workspace_path', 'session_id', 'permission_mode'}
    implementation = server._tool_manager.get_tool('handle_readiness_event')
    with pytest.raises(ValueError):
        implementation.fn_metadata.arg_model.model_validate({'event': 'SessionStart', 'workspace_path': 'x', 'session_id': 's', 'prompt': 'secret-canary'})


@pytest.mark.parametrize('javac_available', [True, False])
def test_hook_closed_receipt_direct_functional_without_second_verify(setup, monkeypatch, javac_available):
    from security_runtime.functional_verification import FunctionalVerificationService
    root, runtime, provider, remediation, hook, grant = setup
    original = args(setup); prepare(setup)
    (root / 'A.java').write_text(FIXED); runtime.findings = provider.findings = []
    checked = hook(); receipt = checked['remediation']['security_verification']
    assert receipt == {'status': 'SCANNER_VERIFIED_RESOLVED', 'phase': 'CLOSED', 'task_ref': original['task_ref'],
                       'grant_id': grant['remediation']['grant_id'], 'explicit_verification_required': False}
    monkeypatch.setattr(remediation, 'verify', lambda *a, **kw: pytest.fail('duplicate explicit scanner verify'))
    assert remediation.functional_receipt(original['remediation_ref'], original['task_ref'], root)
    import shutil
    which = shutil.which
    monkeypatch.setattr(shutil, 'which', lambda name: ('/local/javac' if javac_available else None)
                        if name == 'javac' else which(name))
    service = FunctionalVerificationService(remediation)
    output = service.prepare(original['remediation_ref'], original['task_ref'], root, bound_workspace=root)
    if javac_available:
        assert output['status'] == 'FUNCTIONAL_VERIFICATION_READY'
        assert output['functional_verification']['status'] == 'PLANNED'
        assert output['functional_ref'] and output['handoff']
        assert output['plan']['steps'][0]['target_files'] == ['A.java']
        assert service.executor is None and not list(root.rglob('*.class'))
        service._cleanup_rows(service.plans)
    else:
        assert output['functional_verification']['status'] == 'NOT_AVAILABLE'
        assert not output.get('functional_ref') and not output.get('handoff')
    assert output['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    from security_runtime.guidance.host_guidance import REPAIR_IMPACT_GUIDANCE
    assert 'NOT_AVAILABLE without a handoff' in REPAIR_IMPACT_GUIDANCE


def test_inconclusive_does_not_offer_skip_or_functional_proof(setup):
    from security_runtime.functional_verification import FunctionalVerificationService
    root, runtime, provider, remediation, hook, _ = setup
    original = args(setup); prepare(setup)
    (root / 'A.java').write_text(FIXED); runtime.findings = provider.findings = []
    provider.status = 'FAILED'
    checked = hook()
    assert checked['remediation']['verification']['verification_status'] != 'SCANNER_VERIFIED_RESOLVED'
    assert 'security_verification' not in checked['remediation']
    assert callable(remediation.verify)
    assert remediation.functional_receipt(original['remediation_ref'], original['task_ref'], root) is None
    assert FunctionalVerificationService(remediation).prepare(original['remediation_ref'], original['task_ref'], root, bound_workspace=root)['overall_status'] == 'SECURITY_NOT_VERIFIED'
