"""Global install ownership, cwd admission, bootstrap and routing isolation."""
import asyncio
import copy
import json
import os
import subprocess
import threading
import time
import tomllib
from pathlib import Path

import pytest

from security_runtime.codex_integration import CodexIntegrationAdapter, product_hooks, REQUIRED_TOOLS, check_capabilities
from security_runtime.global_integration import GlobalCodexIntegration, GLOBAL, LEGACY
from security_runtime.global_workspace import resolve_workspace, source_snapshot, read_bootstrap, write_bootstrap, workspace_state
from security_runtime.global_mcp import GlobalWorkspaces, create_global_server
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.guidance.host_guidance import runtime_info
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from test_hook_runtime import FakeRuntime


@pytest.fixture
def projects(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('CODEX_HOME', str(tmp_path / 'codex-home'))
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE', raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL', raising=False)
    roots = []
    for name in ('a', 'b'):
        root = tmp_path / name
        root.mkdir()
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        (root / 'src').mkdir()
        (root / 'src/A.java').write_text('class A {}\n')
        subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(root), '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'safe'], check=True)
        roots.append(root.resolve())
    return roots


@pytest.fixture
def installed(projects, tmp_path, monkeypatch):
    # Installation unit fixtures never start real detached download processes.
    monkeypatch.setattr('security_runtime.personal_install.start_background_preparation',
        lambda *args, **kwargs: {'status': 'QUEUED', 'ready': False})
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    monkeypatch.setenv('SECURITY_RUNTIME_SKILLS_DIR', str(tmp_path / 'skills'))
    probe = lambda *args: check_capabilities(runtime_info(), REQUIRED_TOOLS)
    old = CodexIntegrationAdapter(directory=tmp_path / 'state/legacy', probe=probe,
        baseline_coordinator=HookCoordinator(FakeRuntime(), HookStateStore(tmp_path / 'state/legacy-hooks')))
    adapter = GlobalCodexIntegration(home=tmp_path / 'codex-home', directory=tmp_path / 'state/global-install',
        legacy_adapter=old, probe=probe, discover=lambda: {'command': str(Path(os.sys.executable)),
        'prefix': ['-I', '-m', 'security_runtime.cli'], 'kind': 'PYTHON_VENV'})
    return adapter


def test_fresh_global_install_no_project_writes(installed, projects):
    result = installed.execute('setup', projects[0])
    assert result['scope'] == 'GLOBAL' and result['ownership'] == GLOBAL
    assert result['overall'] == 'CONFIGURED'
    assert result['baseline']['status'] == 'NOT_REQUIRED'
    assert not any((root / '.codex').exists() for root in projects)
    server = tomllib.loads((installed.home / 'config.toml').read_text())['mcp_servers']['ai_security_runtime']
    assert 'cwd' not in server
    assert server['env']['SECURITY_RUNTIME_GLOBAL'] == '1'
    assert not server['env']['SECURITY_RUNTIME_WORKSPACE']
    hooks = json.loads((installed.home / 'hooks.json').read_bytes())
    assert hooks == product_hooks()
    assert all(g[0]['hooks'][0]['input']['workspace_path'] == '${cwd}' for g in hooks['hooks'].values())
    assert str(projects[0]) not in json.dumps(server)


def test_global_idempotence_and_user_preservation(installed, projects):
    installed.home.mkdir()
    a = installed.home / 'config.toml'; b = installed.home / 'hooks.json'
    original = b'# keep byte-for-byte\nmodel = "fixture"\n[mcp_servers.user]\ncommand = "user"\n'
    hooks = {'comment': 'keep', 'hooks': {'PostToolUse': [{'matcher': 'Read', 'hooks': [{'type': 'command', 'command': 'user command'}]}]}}
    a.write_bytes(original); b.write_text(json.dumps(hooks), encoding='utf-8')
    installed.execute('setup', projects[0])
    snapshots = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (a, b, installed._state_path(installed.home, 'ownership.json'))}
    for action in ('setup', 'repair', 'repair'):
        assert installed.execute(action, projects[1])['operation'] == 'ALREADY_CONFIGURED'
        assert snapshots == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in snapshots}
    assert a.read_bytes().startswith(original)
    assert json.loads(b.read_bytes())['hooks']['PostToolUse'][0] == hooks['hooks']['PostToolUse'][0]
    assert installed.execute('uninstall', projects[0])['overall'] == 'NOT_INSTALLED'
    assert a.read_bytes() == original and json.loads(b.read_bytes()) == hooks
    assert installed.execute('uninstall')['operation'] == 'ALREADY_REMOVED'


def test_known_project_migrates_all_three_hooks(installed, projects):
    root = projects[0]
    installed.legacy_adapter.setup(root)
    assert len(json.loads((root / '.codex/hooks.json').read_bytes())['hooks']) == 3
    result = installed.execute('setup', root)
    assert result['migration'] == {'status': 'MIGRATED', 'removed_layers': 1}
    assert 'ai_security_runtime' not in tomllib.loads((root / '.codex/config.toml').read_text()).get('mcp_servers', {})
    assert json.loads((root / '.codex/hooks.json').read_bytes())['hooks'] == {}
    assert installed.execute('repair', root)['migration']['status'] == 'NONE'


def test_migration_preserves_mixed_user_handlers(installed, projects):
    root = projects[0]
    installed.legacy_adapter.setup(root)
    a = root / '.codex/config.toml'; b = root / '.codex/hooks.json'
    a.write_bytes(a.read_bytes() + b'\n[mcp_servers.other]\ncommand = "keep"\n')
    hooks = json.loads(b.read_bytes())
    hooks['hooks']['Stop'][0]['hooks'].append({'type': 'command', 'command': 'keep'})
    b.write_text(json.dumps(hooks))
    installed.execute('setup', root)
    assert tomllib.loads(a.read_text())['mcp_servers'] == {'other': {'command': 'keep'}}
    assert json.loads(b.read_bytes())['hooks']['Stop'][0]['hooks'] == [{'type': 'command', 'command': 'keep'}]


@pytest.mark.parametrize('kind', ['mcp', 'hook', 'inline_hook'])
def test_unknown_project_ownership_not_removed(installed, projects, kind):
    root = projects[0]; folder = root / '.codex'; folder.mkdir()
    if kind == 'mcp':
        (folder / 'config.toml').write_text('[mcp_servers.ai_security_runtime]\ncommand="custom"\n')
    elif kind == 'hook':
        (folder / 'hooks.json').write_text(json.dumps(product_hooks()))
    else:
        (folder / 'config.toml').write_text('[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype="mcp_tool"\nserver="ai_security_runtime"\ntool="handle_stop_event"\n')
    before = {p: p.read_bytes() for p in folder.iterdir()}
    with pytest.raises(IntegrationDiagnostic): installed.execute('setup', root)
    assert before == {p: p.read_bytes() for p in folder.iterdir()}
    assert not (installed.home / 'config.toml').exists()


def test_global_unknown_and_corrupt_ownership_fail_closed(installed):
    installed.home.mkdir()
    a = installed.home / 'config.toml'
    a.write_text('[mcp_servers.ai_security_runtime]\ncommand="user"\n')
    before = a.read_bytes()
    for action in ('setup', 'repair', 'uninstall', 'status', 'doctor'):
        with pytest.raises(IntegrationDiagnostic): installed.execute(action)
        assert a.read_bytes() == before


def test_global_duplicate_semantic_table_rejected(installed):
    installed.execute('setup')
    a = installed.home / 'config.toml'; b = installed.home / 'hooks.json'
    a.write_bytes(a.read_bytes() * 2)
    hooks = json.loads(b.read_bytes())
    for event in hooks['hooks']: hooks['hooks'][event] *= 2
    b.write_text(json.dumps(hooks))
    before = a.read_bytes(), b.read_bytes()
    with pytest.raises(IntegrationDiagnostic, match='CONFIG_INVALID'):
        installed.execute('repair')
    assert (a.read_bytes(), b.read_bytes()) == before


def test_dev_not_implicitly_installed(installed):
    installed.discover = lambda: {'command': str(Path(os.sys.executable)), 'prefix': ['-I', '-m', 'security_runtime.cli'], 'kind': 'DEV'}
    with pytest.raises(IntegrationDiagnostic, match='INSTALLED_RUNTIME_REQUIRED'): installed.execute('setup')
    installed.allow_dev = True
    assert installed.execute('setup')['runtime']['kind'] == 'DEV'
    assert 'src' not in tomllib.loads((installed.home / 'config.toml').read_text())['mcp_servers']['ai_security_runtime'].get('env', {})


def test_resolve_git_subdirectory_nested_repo_and_canonical_case(projects):
    a, b = projects
    assert resolve_workspace(a / 'src') == a
    inner = a / 'nested'; inner.mkdir()
    subprocess.run(['git', 'init', '-q', str(inner)], check=True)
    assert resolve_workspace(inner) == inner
    if os.name == 'nt': assert resolve_workspace(str(b).upper()) == b


def test_non_git_project_layout_and_bounded_snapshot(tmp_path, projects):
    root = tmp_path / 'plain'; target = root / 'src/main/java/demo/A.java'
    target.parent.mkdir(parents=True); target.write_bytes(b'class A {}\n')
    assert resolve_workspace(target.parent) == root
    digest, scope = source_snapshot(root, b'k' * 32)
    assert scope == ['src/main/java/demo/A.java']
    target.write_bytes(b'class A { int n; }\n')
    assert source_snapshot(root, b'k' * 32)[0] != digest


@pytest.mark.parametrize('claim', ['', '${cwd}', '..', 'C:relative', '//host/share', 'bad\x00path'])
def test_invalid_cwd_claims(claim, projects):
    with pytest.raises((ValueError, OSError)): resolve_workspace(claim)


def test_home_drive_empty_state_and_traversal_rejected(tmp_path, projects, installed):
    empty = tmp_path / 'empty'; empty.mkdir()
    state = tmp_path / 'state'; state.mkdir(exist_ok=True)
    for path in (Path.home(), Path(Path.home().anchor), empty, state, installed.home,
                 str(projects[0] / 'src/../src')):
        with pytest.raises((ValueError, OSError)): resolve_workspace(path)


def test_symlink_ancestor_rejected(tmp_path, projects):
    link = tmp_path / 'link'
    try: link.symlink_to(projects[0], target_is_directory=True)
    except OSError: pytest.skip('Host does not permit fixture symlinks')
    with pytest.raises(ValueError): resolve_workspace(link / 'src')


class _Child:
    def __init__(self, binding):
        from mcp.server.fastmcp import FastMCP
        self.server = FastMCP('fixture')
        self.binding = binding
        @self.server.tool()
        def get_security_summary(workspace_path: str | None = None, scan_id: str | None = None, details: bool = False):
            return {'workspace': binding.root, 'scan_id': scan_id}
        @self.server.tool()
        def prepare_task_fix(task_ref: str, workspace_path: str | None = None, remediation_ref: str | None = None, security_context_ref: str | None = None):
            if task_ref != binding.root: raise ValueError('foreign')
            return {'status': 'READY_FOR_HOST_FIX'}


def complete_runtime(findings=()):
    runtime = FakeRuntime(findings)
    original = runtime.scan
    def scan(*a, **k):
        result = original(*a, **k); result.coverage = 'FULL'; return result
    runtime.scan = scan
    return runtime


def pool_fixture(installed, tmp_path, factory=None):
    installed.execute('setup')
    def child(root, directory, binding):
        fixture = _Child(binding)
        core = HookCoordinator(complete_runtime(), HookStateStore(directory / 'hooks'))
        return fixture.server, core
    return GlobalWorkspaces(base=tmp_path / 'state/global-workspaces', integration=installed, child_factory=factory or child)


def ready(pool, root, session):
    observed = pool.bootstrap(root, session)
    if observed['status'] != 'INITIALIZING':
        return observed
    key = (root, pool.bind_session(session, root))
    pool.jobs[key].result(timeout=20)
    return pool.bootstrap(root, session)


def test_project_a_b_bootstrap_without_setup_and_isolated_state(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    try:
        for root, session in zip(projects, ('s-a', 's-b')):
            assert ready(pool, root, session)['status'] == 'CONNECTED'
            assert not (workspace_state(root, pool.base)/'bootstrap.json').exists()
            assert not (root / '.codex').exists()
        assert workspace_state(projects[0], pool.base) != workspace_state(projects[1], pool.base)
        assert pool.children[projects[0]][1].store.key(projects[0]) != pool.children[projects[1]][1].store.key(projects[1])
        with pytest.raises(ValueError, match='SESSION_WORKSPACE_MISMATCH'): pool.bootstrap(projects[1], 's-a')
    finally: pool.close()


def test_initialization_not_blocking_or_fake_ready(installed, projects, tmp_path, monkeypatch):
    blocker = threading.Event(); started = threading.Event()
    def factory(root, directory, binding):
        core = HookCoordinator(complete_runtime(), HookStateStore(directory / 'hooks'))
        return _Child(binding).server, core
    from security_runtime.product_epoch_service import ProductEpochService
    original = ProductEpochService.step
    def handle(current, *args, **kwargs):
        started.set(); assert blocker.wait(10)
        return original(current, *args, **kwargs)
    monkeypatch.setattr(ProductEpochService, 'step', handle)
    pool = pool_fixture(installed, tmp_path, factory)
    try:
        assert pool.bootstrap(projects[0], 's')['status'] == 'CONNECTED'
        assert not started.is_set()
        server = create_global_server(workspaces=pool)
        result = asyncio.run(server.call_tool('get_security_summary', {'workspace_path': str(projects[0])}))
        assert structured(result)['workspace'] == str(projects[0])
        assert not pool.jobs
        assert not (workspace_state(projects[0], pool.base)/'bootstrap.json').exists()
    finally: blocker.set(); pool.close()


def structured(result):
    if hasattr(result, 'structuredContent'): return result.structuredContent
    if isinstance(result, tuple): return result[1]
    if isinstance(result, list): return json.loads(result[0].text)
    return result


def test_router_never_uses_last_workspace_or_decodes_refs(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    try:
        for root in projects: ready(pool, root, root.name)
        result = asyncio.run(server.call_tool('get_security_summary', {}))
        assert result.structuredContent['status'] == 'INCONCLUSIVE'
        for root in projects:
            result = asyncio.run(server.call_tool('get_security_summary', {'workspace_path': str(root)}))
            assert structured(result)['workspace'] == str(root)
        result = asyncio.run(server.call_tool('prepare_task_fix', {'task_ref': str(projects[0]), 'workspace_path': str(projects[1])}))
        assert result.structuredContent['status'] == 'INCONCLUSIVE'
        tools = asyncio.run(server.list_tools())
        assert not {'prepare_functional_verification', 'run_functional_verification'} & {t.name for t in tools}
        assert 'workspace_path' in next(t for t in tools if t.name == 'get_findings').inputSchema['properties']
        assert set(next(t for t in tools if t.name == 'handle_hook_event').inputSchema['properties']) == {'event','workspace_path','session_id','tool_name','tool_input','turn_id','tool_use_id','permission_mode'}
    finally: pool.close()


def test_single_admitted_workspace_is_not_an_implicit_current_workspace(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path); server = create_global_server(workspaces=pool)
    try:
        ready(pool, projects[0], 'a')
        # Host could already be in B before B's first Hook arrives. Even with
        # just A admitted, missing claims must not return A's records.
        result = asyncio.run(server.call_tool('get_security_summary', {}))
        assert result.structuredContent['reason_code'] == 'INVALID_HOST_CLAIMS'
        assert str(projects[0]) not in result.model_dump_json()
        result = asyncio.run(server.call_tool('get_security_summary', {'workspace_path': str(projects[1])}))
        assert structured(result)['workspace'] == str(projects[1])
    finally: pool.close()


def test_unknown_claim_not_reflected_no_source_in_output(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path); server = create_global_server(workspaces=pool)
    secret = 'SECRET-RAW-SOURCE-DO-NOT-REFLECT'
    try:
        result = asyncio.run(server.call_tool('handle_hook_event', {'event': 'PostToolUse', 'workspace_path': str(projects[0]), 'session_id': 's', 'tool_name': 'Edit', 'source': secret}))
        assert result.structuredContent['reason_code'] == 'INVALID_HOST_CLAIMS'
        assert secret not in result.model_dump_json()
        assert not pool.children
    finally: pool.close()


def test_stale_tampered_bootstrap_not_ready(installed, projects, tmp_path):
    root = projects[0]; base = tmp_path / 'state/global-workspaces'
    write_bootstrap(root, 'READY', 'BASELINE_ESTABLISHED', base=base)
    assert read_bootstrap(root, base=base)['security_proof'] is False
    path = workspace_state(root, base) / 'bootstrap.json'
    value = json.loads(path.read_bytes()); value['workspace_id'] = 'wrong'
    path.write_text(json.dumps(value))
    assert read_bootstrap(root, base=base)['status'] == 'DEGRADED'


def test_restart_rebuilds_live_context_and_initializes_new_session(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    assert ready(pool, projects[0], 'first')['status'] == 'CONNECTED'
    key = pool.children[projects[0]][1].store.key(projects[0]); pool.close()
    restarted = pool_fixture(installed, tmp_path)
    try:
        assert not restarted.jobs and not restarted.sessions
        assert ready(restarted, projects[0], 'second')['status'] == 'CONNECTED'
        assert restarted.children[projects[0]][1].store.key(projects[0]) == key
    finally: restarted.close()


@pytest.mark.parametrize('action', ['setup', 'status', 'doctor', 'repair', 'uninstall'])
def test_default_cli_uses_global_without_project_write(installed, projects, monkeypatch, capsys, action):
    from security_runtime.cli import main
    import security_runtime.global_integration as module
    monkeypatch.setattr(module, 'GlobalCodexIntegration', lambda **kwargs: installed)
    monkeypatch.chdir(projects[0])
    assert main([action, '--json']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['scope'] == 'GLOBAL'
    assert not (projects[0] / '.codex').exists()


def test_legacy_format_upgrade_uses_shared_ownership(installed):
    installed.execute('setup')
    manifest = installed._manifest(installed.home)
    manifest['managed_version'] = 'codex-integration-v0.1'
    installed._save(installed.home, manifest)
    assert 'MANAGED_FORMAT_UPGRADE_REQUIRED' in installed.configuration_status()['diagnostics']
    assert installed.execute('repair')['overall'] == 'CONFIGURED'
    assert installed.execute('repair')['operation'] == 'ALREADY_CONFIGURED'


@pytest.mark.parametrize('scope', ['global', 'project'])
def test_signed_english_hook_labels_upgrade_without_losing_ownership(installed, projects, monkeypatch, scope):
    """Old signed label fingerprints remain owned during the explicit upgrade."""
    from security_runtime import codex_integration, global_integration
    previous = copy.deepcopy(product_hooks())
    labels = {
        'PostToolUse': 'AI Security Runtime [codex-integration-v0.2]',
        'SessionStart': 'AI Security Runtime [readiness-v0.3]',
        'Stop': 'AI Security Runtime [continuation-guard-v0.1]',
    }
    for event, label in labels.items():
        previous['hooks'][event][0]['hooks'][0]['statusMessage'] = label
    root = projects[0]
    owner = installed if scope == 'global' else installed.legacy_adapter
    owner_root = installed.home if scope == 'global' else root
    with monkeypatch.context() as old_code:
        old_code.setattr(codex_integration, 'product_hooks', lambda: copy.deepcopy(previous))
        old_code.setattr(global_integration, 'product_hooks', lambda: copy.deepcopy(previous))
        if scope == 'global':
            installed.execute('setup', root)
        else:
            installed.legacy_adapter.setup(root)
    key_path = owner._state_path(owner_root, 'snapshot.key')
    signed_identity = key_path.read_bytes()
    hook_path = owner._config_paths(owner_root)[1] if scope == 'global' else root / '.codex/hooks.json'
    document = json.loads(hook_path.read_bytes())
    extra = {'type': 'command', 'command': 'user hook keep'}
    document['hooks']['Stop'][0]['hooks'].append(extra)
    hook_path.write_text(json.dumps(document), encoding='utf-8')

    if scope == 'global':
        status = installed.configuration_status()
        assert status['ownership'] == GLOBAL
        assert status['overall'] == 'DEGRADED' and 'HOOK_MISSING' in status['diagnostics']
        assert 'POTENTIAL_DUPLICATE_HOOK' not in status['diagnostics']
    upgraded = installed.execute('repair', root)
    assert upgraded['overall'] == 'CONFIGURED'
    assert key_path.read_bytes() == signed_identity
    current = json.loads((installed.home / 'hooks.json').read_bytes())
    for event, groups in product_hooks()['hooks'].items():
        assert sum(group == groups[0] for group in current['hooks'][event]) == 1
    if scope == 'global':
        assert any(extra in group['hooks'] for group in current['hooks']['Stop'])
    else:
        assert upgraded['migration']['status'] == 'MIGRATED'
        assert json.loads(hook_path.read_bytes())['hooks']['Stop'][0]['hooks'] == [extra]
    assert installed.execute('repair', root)['operation'] == 'ALREADY_CONFIGURED'


def test_subdirectory_user_override_preserved(installed, projects):
    sub = projects[0] / 'src'; folder = sub / '.codex'; folder.mkdir()
    (folder / 'config.toml').write_text('[mcp_servers.user]\ncommand="user"\n')
    user = {'hooks': {'Stop': [{'hooks': [{'type': 'command', 'command': 'user'}]}]}}
    (folder / 'hooks.json').write_text(json.dumps(user))
    before = {p: p.read_bytes() for p in folder.iterdir()}
    result = installed.execute('setup', sub)
    assert result['project_ownership'] == [{'ownership': 'USER_MANAGED', 'related': False}]
    assert before == {p: p.read_bytes() for p in folder.iterdir()}


@pytest.mark.parametrize('event', ['Stop', 'SessionStart', '${hook_event_name}'])
def test_invalid_edit_event_does_not_bootstrap(installed, projects, tmp_path, event):
    pool = pool_fixture(installed, tmp_path); server = create_global_server(workspaces=pool)
    try:
        result = asyncio.run(server.call_tool('handle_hook_event', {'event': event, 'workspace_path': str(projects[0]), 'session_id': 's', 'tool_name': 'Edit'}))
        assert result.structuredContent['reason_code'] == 'INVALID_HOST_CLAIMS'
        assert not pool.children and not pool.jobs
    finally: pool.close()


@pytest.mark.parametrize('tool', ['Read', '', '${tool_name}', 'x' * 100])
def test_non_edit_tool_does_not_bootstrap(installed, projects, tmp_path, tool):
    pool = pool_fixture(installed, tmp_path); server = create_global_server(workspaces=pool)
    try:
        result = asyncio.run(server.call_tool('handle_hook_event', {'event': 'PostToolUse', 'workspace_path': str(projects[0]), 'session_id': 's', 'tool_name': tool}))
        assert result.structuredContent['reason_code'] == 'INVALID_HOST_CLAIMS'
        assert not pool.children and not pool.jobs
    finally: pool.close()


def test_unused_product_A_failure_does_not_block_connection_or_claim_proof(installed, projects, tmp_path, monkeypatch):
    def factory(root, directory, binding):
        core = HookCoordinator(FakeRuntime(), HookStateStore(directory / 'hooks'))
        return _Child(binding).server, core
    from security_runtime.product_epoch_service import ProductEpochService
    monkeypatch.setattr(ProductEpochService, 'step',
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError('private source-like error')))
    pool = pool_fixture(installed, tmp_path, factory)
    try:
        value = ready(pool, projects[0], 's')
        assert value['status'] == 'CONNECTED' and value['security_proof'] is False
        assert value['startup_comparison_baseline']['status'] == 'NOT_REQUIRED'
        assert not pool.jobs
        assert 'private' not in json.dumps(value)
    finally: pool.close()


def test_connection_budget_does_not_evict_live_authority(installed, projects, tmp_path, monkeypatch):
    import security_runtime.global_mcp as module
    monkeypatch.setattr(module, 'LIMIT', 1)
    pool = pool_fixture(installed, tmp_path)
    try:
        first = pool.admit(projects[0])
        with pytest.raises(ValueError, match='BUDGET'): pool.admit(projects[1])
        assert pool.admit(projects[0]) is first
    finally: pool.close()


def test_changed_global_config_blocks_new_workspace(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    try:
        a = installed.home / 'hooks.json'
        hooks = json.loads(a.read_bytes()); hooks['hooks'].pop('Stop'); a.write_text(json.dumps(hooks))
        with pytest.raises(ValueError, match='GLOBAL_CONFIGURATION_NOT_READY'): pool.admit(projects[0])
        assert not pool.children
    finally: pool.close()


def test_encountered_legacy_project_is_degraded_until_explicit_repair(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    try:
        installed.legacy_adapter.setup(projects[0])
        with pytest.raises(ValueError, match='LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR'): pool.admit(projects[0])
        assert (projects[0] / '.codex/hooks.json').is_file()
        installed.execute('repair', projects[0])
        assert ready(pool, projects[0], 's')['status'] == 'CONNECTED'
    finally: pool.close()


def test_non_git_hook_stays_bounded_and_does_not_auto_remediate(installed, projects, tmp_path):
    from security_runtime.hooks import HookEvent
    root = tmp_path / 'plain'; target = root / 'src/A.java'
    target.parent.mkdir(parents=True); target.write_bytes(b'class A {}\n')
    runtime = FakeRuntime()
    core = HookCoordinator(runtime, HookStateStore(tmp_path / 'state/plain-hooks'),
                           workspace_resolver=resolve_workspace, snapshot_capture=source_snapshot)
    assert core.handle(HookEvent.SESSION_START, root, 'generic', 's')['status'] == 'BASELINE_ESTABLISHED'
    target.write_bytes(b'class A { int n; }\n')
    # No callback or model path is attached by the coordinator. Root discovery
    # does not grant a Git-dependent remediation receipt.
    result = core.handle(HookEvent.FILE_CHANGED, root, 'generic', 's')
    assert result['execution']['source_modified'] is False
    assert result['execution']['target_build'] is False


def test_new_subdirectory_duplicate_is_not_hidden_by_existing_child(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path); server = create_global_server(workspaces=pool)
    try:
        ready(pool, projects[0], 's')
        folder = projects[0] / 'src/.codex'; folder.mkdir()
        (folder / 'hooks.json').write_text(json.dumps(product_hooks()))
        before = (folder / 'hooks.json').read_bytes()
        value = asyncio.run(server.call_tool('handle_hook_event', {'event': 'PostToolUse',
            'workspace_path': str(projects[0] / 'src'), 'session_id': 's', 'tool_name': 'Edit'}))
        assert value.structuredContent['status'] == 'INCONCLUSIVE'
        assert value.structuredContent['scanner_run'] is False
        assert (folder / 'hooks.json').read_bytes() == before
    finally: pool.close()


def test_user_disabled_hooks_preserved_and_not_claimed_ready(installed):
    installed.home.mkdir()
    a = installed.home / 'config.toml'; a.write_bytes(b'[features]\nhooks=false\n')
    assert installed.execute('setup')['overall'] == 'DEGRADED'
    assert tomllib.loads(a.read_text())['features']['hooks'] is False


def test_global_and_project_tool_schemas_are_backward_compatible(installed, tmp_path, projects):
    from security_runtime.mcp_server import create_server
    project = create_server(global_mode=False)
    before = copy.deepcopy(project._tool_manager.get_tool('get_findings').parameters)
    pool = pool_fixture(installed, tmp_path)
    try:
        global_server = create_global_server(workspaces=pool)
        schemas = {t.name: t.inputSchema for t in asyncio.run(global_server.list_tools())}
        assert not {'prepare_functional_verification', 'run_functional_verification'} & schemas.keys()
        assert 'workspace_path' in schemas['get_findings']['properties']
        assert 'workspace_path' not in before['properties']
        assert project._tool_manager.get_tool('get_findings').parameters == before
        assert schemas['handle_hook_event']['properties'] == project._tool_manager.get_tool('handle_hook_event').parameters['properties']
    finally: pool.close()


@pytest.mark.parametrize('failure', ['old-cli', 'old-mcp', 'wrong-scope', 'wrong-schema', None])
def test_global_deployment_checks_actual_transport_capability(installed, monkeypatch, failure):
    # This case tests CLI/MCP capability validation, not a missing working directory.
    installed.home.mkdir()
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    from security_runtime.global_mcp import global_runtime_info
    from security_runtime.codex_integration import probe_runtime
    import security_runtime.codex_integration as module
    info = global_runtime_info()
    cli_info = copy.deepcopy(info); mcp_info = copy.deepcopy(info)
    if failure == 'old-cli': cli_info['features'].pop('global_runtime_integration')
    if failure == 'old-mcp': mcp_info['features'].pop('global_runtime_integration')
    if failure == 'wrong-scope': mcp_info['integration_scope'] = 'PROJECT'
    monkeypatch.setattr(module, 'run_process', lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps(cli_info)))
    @asynccontextmanager
    async def stdio(*a, **k): yield None, None
    class Session:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def initialize(self): pass
        async def list_tools(self):
            return SimpleNamespace(tools=[SimpleNamespace(name=n, inputSchema={'properties':
                {'workspace_path': {}} if n == 'get_findings' and failure != 'wrong-schema' else {}}) for n in REQUIRED_TOOLS | {'get_findings'}])
        async def call_tool(self, *a): return SimpleNamespace(structuredContent=mcp_info, isError=False)
    monkeypatch.setattr('mcp.client.stdio.stdio_client', stdio)
    monkeypatch.setattr('mcp.ClientSession', Session)
    if failure:
        with pytest.raises(IntegrationDiagnostic, match='CAPABILITY_MISMATCH'):
            probe_runtime(installed.discover(), installed.home, {'SECURITY_RUNTIME_GLOBAL': '1'})
    else:
        assert probe_runtime(installed.discover(), installed.home, {'SECURITY_RUNTIME_GLOBAL': '1'})['status'] == 'OK'


def test_manual_runtime_keeps_full_registry_while_hook_stays_core(installed, projects, tmp_path, monkeypatch):
    from security_runtime.runtime import SecurityRuntime
    instances = []
    class RecordedRuntime(SecurityRuntime):
        def __init__(self, *a, **k):
            super().__init__(*a, **k); instances.append(self)
    monkeypatch.setattr('security_runtime.runtime.SecurityRuntime', RecordedRuntime)
    installed.execute('setup')
    pool = GlobalWorkspaces(base=tmp_path / 'state/global-workspaces', integration=installed)
    try:
        child, core = pool.admit(projects[0])
        assert len(instances) == 2
        manual_names = {a.name for a in instances[0].registry.adapters}
        hook_names = {a.name for a in core.runtime.registry.adapters}
        from security_runtime.scanners import ScannerRegistry
        assert manual_names == {a.name for a in ScannerRegistry().adapters}
        assert len(manual_names) > len(hook_names)
        assert hook_names == {'semgrep', 'native-js-function', 'gitleaks', 'trivy-vuln'}
        assert {a.name for a in core.runtime.registry.fallback_adapters} == {'osv-scanner'}
        assert instances[0].store.path == core.runtime.store.path
        assert child._tool_manager.get_tool('scan_project') is not None
    finally: pool.close()


@pytest.mark.parametrize('scope', ['global', 'project'])
def test_runtime_under_an_unknown_mcp_alias_conflicts_without_deletion(installed, projects, scope):
    folder = installed.home if scope == 'global' else projects[0] / '.codex'
    folder.mkdir()
    path = folder / 'config.toml'
    raw = b'[mcp_servers.renamed_runtime]\ncommand="python"\nargs=["-I","-m","security_runtime.cli","mcp"]\n'
    path.write_bytes(raw)
    with pytest.raises(IntegrationDiagnostic, match='POTENTIAL_DUPLICATE_MCP'):
        installed.execute('setup', projects[0])
    assert path.read_bytes() == raw


def test_old_hook_under_unknown_server_alias_is_preserved(installed, projects):
    folder = projects[0] / '.codex'; folder.mkdir()
    path = folder / 'hooks.json'; hooks = product_hooks()
    for groups in hooks['hooks'].values(): groups[0]['hooks'][0]['server'] = 'renamed_runtime'
    path.write_text(json.dumps(hooks)); before = path.read_bytes()
    with pytest.raises(IntegrationDiagnostic, match='POTENTIAL_DUPLICATE_HOOK'):
        installed.execute('setup', projects[0])
    assert path.read_bytes() == before


def test_global_session_baseline_does_not_invent_preexisting_scanner_facts(installed, projects, tmp_path):
    from test_hook_runtime import row
    root = projects[0]
    def factory(root, directory, binding):
        runtime = complete_runtime([row(root, file='src/A.java')])
        return _Child(binding).server, HookCoordinator(runtime, HookStateStore(directory / 'hooks'), cooldown_ms=0)
    pool = pool_fixture(installed, tmp_path, factory)
    try:
        assert ready(pool, root, 's')['status'] == 'CONNECTED'
        core = pool.children[root][1]
        snapshot, _ = core.store.load(core.store.path(root, 'codex', 's'))
        assert snapshot is None
        assert core.runtime.calls == []
        (root / 'src/A.java').write_text('class A { int harmless; }\n')
        result = core.handle('FILE_CHANGED', root, 'codex', 's')
        assert result['delta']['new'] == 0
        assert result['reason'] == 'TASK_BASELINE_REQUIRED'
    finally: pool.close()


def test_global_session_baseline_alone_cannot_prove_new_risk(installed, projects, tmp_path):
    from test_hook_runtime import row
    pool = pool_fixture(installed, tmp_path)
    try:
        root = projects[0]
        assert ready(pool, root, 's')['status'] == 'CONNECTED'
        core = pool.children[root][1]; core.cooldown_ms = 0
        core.runtime.findings = [row(root, file='src/A.java')]
        (root / 'src/A.java').write_text('changed\n')
        result = core.handle('FILE_CHANGED', root, 'codex', 's')
        assert result['delta']['new'] == 0
        assert result['reason'] == 'TASK_BASELINE_REQUIRED'
    finally: pool.close()


@pytest.mark.parametrize('cause', ['FAILED', 'PARTIAL', 'moving'])
def test_product_observation_is_independent_of_engine_and_records_moving_gaps(installed, projects, tmp_path, monkeypatch, cause):
    root = projects[0]
    def factory(root, directory, binding):
        runtime = complete_runtime()
        original = runtime.scan
        def scan(*a, **k):
            result = original(*a, **k)
            if cause == 'PARTIAL': result.coverage = 'PARTIAL'
            elif cause == 'moving': (root / 'src/A.java').write_text('class A { int moved; }\n')
            return result
        runtime.scan = scan
        if cause == 'FAILED': runtime.status = 'FAILED'
        core = HookCoordinator(runtime, HookStateStore(directory / 'hooks'))
        return _Child(binding).server, core
    if cause == 'moving':
        from security_runtime.product_epoch_capture import StableHashReader
        original_read = StableHashReader._read_chunk
        def moving(reader, size):
            raw = original_read(reader, size)
            with (root/'src/A.java').open('ab') as output:
                output.write(b' changed')
            return raw
        monkeypatch.setattr(StableHashReader, '_read_chunk', moving)
    pool = pool_fixture(installed, tmp_path, factory)
    try:
        value = ready(pool, root, 's')
        assert value['status'] == 'CONNECTED'
        assert value['startup_comparison_baseline']['status'] == 'NOT_REQUIRED'
        assert value['security_proof'] is False
        core = pool.children[root][1]
        assert core.runtime.calls == []
        assert core.store.load(core.store.path(root, 'codex', 's'))[0] is None
    finally: pool.close()


def test_global_baseline_publication_holds_workspace_lock(installed, projects, tmp_path, monkeypatch):
    from security_runtime.baseline_seed import WorkspaceBaselineSeeds
    root = projects[0]; core = HookCoordinator(complete_runtime(), HookStateStore(tmp_path / 'state/hooks'))
    original = core.store.save
    def save(path, snapshot):
        with core.store.lock(root) as acquired: assert not acquired
        return original(path, snapshot)
    monkeypatch.setattr(core.store, 'save', save)
    snapshot = WorkspaceBaselineSeeds(integration=installed, coordinator=core).capture_session(root, 's')
    assert core.store.load(core.store.path(root, 'codex', 's'))[0] == snapshot
