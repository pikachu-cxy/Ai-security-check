"""Only attested Runtime config is migratable; custom bytes/handlers survive."""
import copy
import json
import tomllib
import pytest
from test_codex_integration import adapter, repo, call, config, write
from security_runtime.codex_integration import fingerprint, product_hooks
from security_runtime.hook_state import identity
from security_runtime.codex_mcp_hook import codex_mcp_hook_config


def stable(adapter, root):
    paths = (*config(root), adapter._state_path(root, 'ownership.json'))
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
    assert call(adapter, root, 'repair')['operation'] == 'ALREADY_CONFIGURED'
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}


def test_fresh_and_repeated_setup_repair_are_stable(adapter, repo):
    assert call(adapter, repo)['operation'] == 'CONFIGURED'
    assert call(adapter, repo)['operation'] == 'ALREADY_CONFIGURED'
    stable(adapter, repo)


@pytest.mark.parametrize('action', ['setup', 'repair'])
def test_signed_legacy_mcp_and_hook_migrate_together(adapter, repo, action):
    call(adapter, repo)
    a, b = config(repo)
    raw = a.read_bytes().replace(b'v0.2', b'v0.1')
    a.write_bytes(raw)
    old = codex_mcp_hook_config()
    b.write_text(json.dumps(old), encoding='utf-8')
    manifest = adapter._manifest(repo)
    manifest['managed_version'] = 'codex-integration-v0.1'
    manifest['records'][0]['block'] = identity(raw.decode())
    manifest['records'][0]['hooks'] = {e: fingerprint(g[0]) for e, g in old['hooks'].items()}
    adapter._save(repo, manifest)
    assert call(adapter, repo, action)['operation'] in {'CONFIGURED', 'REPAIRED'}
    assert b.read_text() and json.loads(b.read_bytes()) == product_hooks()
    assert b'v0.1' not in a.read_bytes()
    stable(adapter, repo)


@pytest.mark.parametrize('action', ['setup', 'repair'])
def test_duplicate_managed_mcp_conflict_repair_preserves_user_bytes(adapter, repo, action):
    call(adapter, repo)
    a, _ = config(repo)
    owned = a.read_bytes()
    user = b'# custom untouched\n[mcp_servers.other]\ncommand="user-server"\n'
    a.write_bytes(user + owned + owned)
    assert 'MCP_DUPLICATE_MANAGED_BLOCK' in call(adapter, repo, 'status')['diagnostics']
    assert call(adapter, repo, action)['operation'] in {'CONFIGURED','REPAIRED'}
    assert a.read_bytes() == user + owned
    assert tomllib.loads(a.read_text())['mcp_servers']['other']['command'] == 'user-server'
    stable(adapter, repo)


def test_legacy_poc_duplicate_repairs_with_owned_mcp_anchor(adapter, repo):
    call(adapter, repo)
    _, b = config(repo)
    hooks = json.loads(b.read_bytes())
    hooks['hooks']['PostToolUse'] += codex_mcp_hook_config()['hooks']['PostToolUse']
    user = {'type':'command', 'command':'echo user custom'}
    hooks['hooks']['PostToolUse'][1]['hooks'].append(user)
    hooks['hooks']['OtherEvent'] = [{'hooks':[user]}]
    b.write_text(json.dumps(hooks), encoding='utf-8')
    assert 'HOOK_DUPLICATE' in call(adapter, repo, 'status')['diagnostics']
    assert call(adapter, repo, 'repair')['operation'] == 'REPAIRED'
    result = json.loads(b.read_bytes())
    assert result['hooks']['PostToolUse'][0]['hooks'] == [user]
    assert result['hooks']['PostToolUse'][1] == product_hooks()['hooks']['PostToolUse'][0]
    assert result['hooks']['OtherEvent'] == hooks['hooks']['OtherEvent']
    stable(adapter, repo)


def test_legacy_command_plus_mixed_custom_hook_migrates(adapter, repo):
    from security_runtime.hook_adapters import CodexHookAdapter
    from security_runtime.integration_config import IntegrationConfigStore
    hooks = {'hooks':CodexHookAdapter().config(repo)}
    user = {'type':'command','command':'echo keep custom'}
    hooks['hooks']['PostToolUse'][0]['hooks'].append(user)
    write(repo, hooks=hooks)
    IntegrationConfigStore(repo,'.codex/hooks.json')._local_exclude(add=True)
    assert call(adapter, repo)['operation'] == 'CONFIGURED'
    result = json.loads(config(repo)[1].read_bytes())
    assert result['hooks']['PostToolUse'][0]['hooks'] == [user]
    assert result['hooks']['PostToolUse'][1] == product_hooks()['hooks']['PostToolUse'][0]
    stable(adapter, repo)


def test_crlf_managed_block_is_idempotent_not_rewritten(adapter, repo):
    call(adapter, repo)
    a, _ = config(repo)
    raw = a.read_bytes().replace(b'\n', b'\r\n')
    a.write_bytes(raw)
    stable(adapter, repo)
    assert a.read_bytes() == raw


@pytest.mark.parametrize('changed', ['matcher', 'input', 'timeout'])
def test_custom_runtime_looking_hook_is_never_claimed(adapter, repo, changed):
    call(adapter, repo)
    _, b = config(repo)
    hooks = json.loads(b.read_bytes())
    custom = copy.deepcopy(codex_mcp_hook_config()['hooks']['PostToolUse'][0])
    if changed == 'matcher': custom['matcher'] = 'Read'
    elif changed == 'input': custom['hooks'][0]['input']['tool_name'] = 'user value'
    else: custom['hooks'][0]['timeout'] = 77
    hooks['hooks']['PostToolUse'].append(custom)
    b.write_text(json.dumps(hooks), encoding='utf-8')
    before = tuple(p.read_bytes() for p in config(repo))
    assert call(adapter, repo, 'repair')['diagnostics'] == ['POTENTIAL_DUPLICATE_HOOK']
    assert before == tuple(p.read_bytes() for p in config(repo))
