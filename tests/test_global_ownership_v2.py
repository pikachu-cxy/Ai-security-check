"""Synthetic shared Codex config; no personal config or provider credentials."""
import json
import tomllib

import pytest

from test_global_integration import installed, projects
from security_runtime.codex_integration import SERVER, BEGIN, END
from security_runtime.global_integration import OWNERSHIP_VERSION
from security_runtime.global_toml import foreign_semantics
from security_runtime.integration_lifecycle import IntegrationDiagnostic


def install(adapter):
    assert adapter.execute('setup')['overall'] == 'CONFIGURED'
    return adapter.home / 'config.toml'


def legacy(adapter, raw):
    manifest = adapter._manifest(adapter.home)
    for key in ('scope', 'ownership_model', 'runtime_version', 'capability_contract'):
        manifest.pop(key)
    manifest['managed_version'] = 'codex-integration-v0.2'
    adapter._save(adapter.home, manifest)
    return BEGIN.encode() + raw + END.encode()


def test_global_v2_install_signed_binding(installed):
    path = install(installed)
    assert b'AI Security Runtime managed Codex' not in path.read_bytes()
    manifest = installed._manifest(installed.home)
    assert manifest['managed_version'] == OWNERSHIP_VERSION
    assert manifest['scope'] == 'GLOBAL' and manifest['ownership_model'] == 2
    assert manifest['server'] == SERVER
    assert manifest['runtime_version'] == '0.3.1'
    assert manifest['capability_contract']
    assert installed.configuration_status()['mcp']['ownership_state'] == 'OWNED_AND_CURRENT'


@pytest.mark.parametrize('markers', ['both', 'begin-only', 'end-only', 'none', 'moved', 'mismatched'])
def test_legacy_marker_loss_never_changes_global_ownership(installed, markers):
    path = install(installed)
    raw = legacy(installed, path.read_bytes())
    if markers in ('begin-only', 'none'):
        raw = raw.replace(END.encode(), b'')
    if markers in ('end-only', 'none'):
        raw = raw.replace(BEGIN.encode(), b'')
    if markers == 'moved':
        raw = raw.replace(BEGIN.encode(), b'') + BEGIN.encode()
    if markers == 'mismatched':
        raw = raw.replace(END.encode(), END.replace('v0.2', 'v0.1').encode())
    path.write_bytes(raw)
    assert installed.configuration_status()['mcp']['status'] == 'CONFIGURED'
    assert installed.execute('repair')['overall'] == 'CONFIGURED'
    assert b'AI Security Runtime managed Codex' not in path.read_bytes()
    assert installed._manifest(installed.home)['managed_version'] == OWNERSHIP_VERSION
    assert installed.execute('repair')['operation'] == 'ALREADY_CONFIGURED'


SIBLINGS = b'''# synthetic user settings stay byte-for-byte
model = 'fixture'
notes = """multiline string
[mcp_servers.ai_security_runtime]
# END AI Security Runtime managed Codex v0.2
literal header, never a table
"""
[marketplaces.fixture]
source = 'local-fixture'
[plugins.fixture]
enabled = true
[projects.'synthetic/project']
trust_level = 'trusted'
[mcp_servers.endor_like_tool]
command = 'synthetic-endor'
[mcp_servers.node_like_tool]
command = 'synthetic-node'
[hooks.state.fixture]
enabled = true
trusted_hash = 'synthetic-hash'
[desktop]
fixture = true
'''


@pytest.mark.parametrize('position', ['prefix', 'between-env', 'inside-markers', 'suffix'])
def test_repair_and_remove_preserve_sibling_bytes(installed, position):
    path = install(installed)
    canonical = path.read_bytes()
    if position == 'prefix':
        raw = SIBLINGS + canonical
    elif position == 'between-env':
        pivot = canonical.index(b'[mcp_servers.ai_security_runtime.env]')
        raw = canonical[:pivot] + SIBLINGS.replace(b"model = 'fixture'\n", b'').replace(
            b'notes = ', b'[user_notes]\nnotes = ', 1) + canonical[pivot:]
    elif position == 'inside-markers':
        raw = legacy(installed, canonical + SIBLINGS.replace(b"model = 'fixture'\n", b'').replace(
            b'notes = ', b'[user_notes]\nnotes = ', 1))
    else:
        raw = canonical + SIBLINGS.replace(b"model = 'fixture'\n", b'').replace(
            b'notes = ', b'[user_notes]\nnotes = ', 1)
    path.write_bytes(raw)
    before = tomllib.loads(raw.decode())
    assert installed.configuration_status()['mcp']['status'] == 'CONFIGURED'
    installed.execute('repair')
    repaired = path.read_bytes()
    assert foreign_semantics(tomllib.loads(repaired.decode())) == foreign_semantics(before)
    foreign_bytes = SIBLINGS if position == 'prefix' else SIBLINGS.replace(b"model = 'fixture'\n", b'').replace(
        b'notes = ', b'[user_notes]\nnotes = ', 1)
    assert foreign_bytes in repaired
    installed.execute('uninstall')
    assert foreign_bytes in path.read_bytes()
    assert foreign_semantics(tomllib.loads(path.read_text())) == foreign_semantics(before)


@pytest.mark.parametrize('layout', ['quoted', 'dotted', 'inline-server', 'inline-parent'])
def test_structural_layouts(installed, layout):
    path = install(installed)
    raw = path.read_bytes()
    if layout == 'quoted':
        raw = raw.replace(b'[mcp_servers.ai_security_runtime', b'["mcp_servers" . "ai_security_runtime"')
    else:
        server = tomllib.loads(raw.decode())['mcp_servers'][SERVER]
        def val(v):
            if isinstance(v, dict):
                return '{' + ','.join(json.dumps(k) + '=' + val(x) for k,x in v.items()) + '}'
            return json.dumps(v)
        if layout == 'dotted':
            raw = ('\n'.join('mcp_servers.ai_security_runtime.' + k + '=' + val(v) for k,v in server.items()) + '\n').encode()
        elif layout == 'inline-server':
            raw = ('[mcp_servers]\nai_security_runtime=' + val(server) + '\n').encode()
        else:
            raw = ('mcp_servers={ai_security_runtime=' + val(server) + ',other={command="fixture"}}\n').encode()
    path.write_bytes(raw)
    assert installed.configuration_status()['mcp']['status'] == 'CONFIGURED'
    if layout == 'inline-parent':
        with pytest.raises(IntegrationDiagnostic, match='MCP_CONFIGURATION_LAYOUT_UNSUPPORTED'):
            installed.execute('repair')
        assert path.read_bytes() == raw
    else:
        assert installed.execute('repair')['overall'] == 'CONFIGURED'
        assert installed.execute('repair')['operation'] == 'ALREADY_CONFIGURED'


@pytest.mark.parametrize('failure', ['hmac', 'scope', 'absent', 'duplicate'])
def test_missing_invalid_or_wrong_scope_ownership_is_rejected(installed, failure):
    path = install(installed)
    manifest_path = installed._state_path(installed.home, 'ownership.json')
    if failure == 'hmac':
        value = json.loads(manifest_path.read_bytes()); value['signature'] = '0' * 64
        manifest_path.write_text(json.dumps(value))
    elif failure == 'scope':
        value = installed._manifest(installed.home); value['scope'] = 'PROJECT'
        installed._save(installed.home, value)
    elif failure == 'absent':
        manifest_path.unlink()
    else:
        path.write_bytes(path.read_bytes() * 2)
    before = path.read_bytes()
    for action in ('status', 'repair', 'uninstall'):
        with pytest.raises(IntegrationDiagnostic):
            installed.execute(action)
        assert path.read_bytes() == before


def test_owned_stale_definition_can_be_repaired(installed):
    path = install(installed)
    before = path.read_bytes()
    previous = installed.discover
    installed.discover = lambda: dict(previous(), prefix=['-I', '-m', 'security_runtime.cli', '--synthetic-new-contract'])
    status = installed.configuration_status()
    assert status['mcp']['ownership_state'] == 'OWNED_BUT_STALE'
    assert 'RUNTIME_STALE' in status['diagnostics']
    assert installed.execute('repair')['overall'] == 'CONFIGURED'
    assert path.read_bytes() != before


def test_owned_runtime_version_stale_can_be_repaired(installed):
    install(installed)
    value = installed._manifest(installed.home); value['runtime_version'] = 'synthetic-old-version'
    installed._save(installed.home, value)
    assert 'RUNTIME_STALE' in installed.configuration_status()['diagnostics']
    assert installed.execute('repair')['overall'] == 'CONFIGURED'


def test_unexpected_datetime_inside_server_rejects_as_conflict(installed):
    path = install(installed)
    path.write_bytes(path.read_bytes().replace(b'[mcp_servers.ai_security_runtime.env]',
        b'unknown = 2026-01-01\n[mcp_servers.ai_security_runtime.env]'))
    with pytest.raises(IntegrationDiagnostic, match='MCP_CONFIGURATION_CONFLICT'):
        installed.configuration_status()


def test_hook_state_changes_do_not_change_ownership_or_hook_bytes(installed):
    path = install(installed)
    hooks = installed.home / 'hooks.json'; old = hooks.read_bytes()
    state = b'\n[hooks.state.fixture]\nenabled = false\ntrusted_hash = "host-changed"\n'
    path.write_bytes(state + path.read_bytes())
    assert installed.configuration_status()['mcp']['status'] == 'CONFIGURED'
    installed.execute('repair')
    assert path.read_bytes().startswith(state)
    assert hooks.read_bytes() == old
