"""Host-owned TOML hook state survives the owned Global lifecycle."""
import copy
import json
import tomllib
from pathlib import Path

import pytest

from security_runtime.codex_integration import CodexIntegrationAdapter
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from test_global_integration import installed, projects  # isolated CODEX_HOME fixtures


STATE = (Path(__file__).parent / 'fixtures/codex/host-hook-state.toml').read_bytes()
USER = b'''# preserve unrelated settings and MCP byte-for-byte
model = "fixture-model"
[features]
hooks = true
[mcp_servers.node_repl]
command = "node"
args = ["fixture.js"]
[plugins.fixture]
enabled = true
[projects."fixture/project"]
trust_level = "trusted"
[future_user_settings]
opaque = { values = ["one", "two"] }
'''
INLINE = b'''[[hooks.PostToolUse]]
matcher = "Read"
[[hooks.PostToolUse.hooks]]
type = "command"
command = "user-owned-command"
'''


def configure(adapter, raw):
    adapter.home.mkdir()
    path = adapter.home / 'config.toml'
    path.write_bytes(raw)
    return path


@pytest.mark.parametrize('raw', [STATE, USER + STATE, USER + STATE + INLINE])
def test_state_setup_lifecycle_preserves_bytes_and_values(installed, raw):
    path = configure(installed, raw)
    original = tomllib.loads(raw.decode())
    assert not (installed.home / 'hooks.json').exists()
    assert installed.execute('setup')['overall'] == 'CONFIGURED'
    assert path.read_bytes().startswith(raw)
    parsed = tomllib.loads(path.read_text())
    assert parsed['hooks'] == original['hooks']
    for key, value in original.items():
        if key != 'mcp_servers':
            assert parsed[key] == value
    if 'mcp_servers' in original:
        assert parsed['mcp_servers']['node_repl'] == original['mcp_servers']['node_repl']
    paths = [path, installed.home / 'hooks.json', installed._state_path(installed.home, 'ownership.json')]
    snapshot = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
    for action in ('setup', 'repair', 'repair'):
        assert installed.execute(action)['operation'] == 'ALREADY_CONFIGURED'
        assert snapshot == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
    assert installed.execute('status')['overall'] == 'CONFIGURED'
    assert installed.execute('uninstall')['overall'] == 'NOT_INSTALLED'
    assert path.read_bytes() == raw
    assert tomllib.loads(path.read_text()) == original
    assert json.loads((installed.home / 'hooks.json').read_bytes()) == {'hooks': {}}


def test_existing_runtime_hook_and_host_state_coexist(installed):
    installed.execute('setup')
    path = installed.home / 'config.toml'
    path.write_bytes(STATE + path.read_bytes())
    before = path.read_bytes()
    assert installed.execute('status')['overall'] == 'CONFIGURED'
    assert installed.execute('setup')['operation'] == 'ALREADY_CONFIGURED'
    assert installed.execute('repair')['operation'] == 'ALREADY_CONFIGURED'
    assert path.read_bytes() == before
    installed.execute('uninstall')
    assert path.read_bytes() == STATE


def test_state_and_both_user_hook_sources_preserved(installed):
    path = configure(installed, USER + STATE + INLINE)
    hooks = {'description': 'user fixture', 'hooks': {'Stop': [{'hooks': [
        {'type': 'command', 'command': 'user-stop'}]}]}}
    other = installed.home / 'hooks.json'
    other.write_text(json.dumps(hooks), encoding='utf-8')
    assert installed.execute('setup')['overall'] == 'CONFIGURED'
    assert tomllib.loads(path.read_text())['hooks']['PostToolUse'][0]['matcher'] == 'Read'
    assert json.loads(other.read_bytes())['hooks']['Stop'][0] == hooks['hooks']['Stop'][0]
    installed.execute('uninstall')
    assert path.read_bytes() == USER + STATE + INLINE
    assert json.loads(other.read_bytes()) == hooks


def test_project_state_is_not_runtime_definition(installed, projects):
    for root in projects:
        folder = root / '.codex'; folder.mkdir()
        (folder / 'config.toml').write_bytes(USER + STATE + INLINE)
    assert installed.execute('setup', projects[0])['overall'] == 'CONFIGURED'
    assert installed.execute('repair', projects[1])['overall'] == 'CONFIGURED'
    assert all((root / '.codex/config.toml').read_bytes() == USER + STATE + INLINE for root in projects)


@pytest.mark.parametrize('raw', [
    b'[hooks]\nstate=[]\n', b'[hooks.state]\nkey=true\n',
    b'[hooks.state.key]\nenabled="yes"\n', b'[hooks.state.key]\ntrusted_hash=12\n',
    b'[hooks.unknown_metadata]\nvalue=true\n', b'[hooks.PostToolUse]\nvalue=true\n',
    b'[hooks]\nStop="wrong"\n',
])
def test_unknown_or_malformed_metadata_not_silently_accepted(installed, raw):
    path = configure(installed, raw)
    for action in ('setup', 'repair', 'uninstall', 'status'):
        with pytest.raises(IntegrationDiagnostic, match='CONFIG_INVALID'):
            installed.execute(action)
        assert path.read_bytes() == raw
        assert not (installed.home / 'hooks.json').exists()


def test_host_state_extensions_preserved_per_official_schema(installed):
    raw = STATE + b'future_host_field = { value = [1, 2] }\n'
    path = configure(installed, raw)
    installed.execute('setup'); installed.execute('repair'); installed.execute('uninstall')
    assert path.read_bytes() == raw


@pytest.mark.parametrize('mutation', [
    'type', 'missing_server', 'missing_tool', 'input', 'timeout', 'statusMessage', 'groups', 'handlers',
])
def test_malformed_owned_hook_fail_closed_with_state(installed, mutation):
    path = configure(installed, STATE)
    installed.execute('setup')
    hook_path = installed.home / 'hooks.json'
    hooks = json.loads(hook_path.read_bytes())
    handler = hooks['hooks']['PostToolUse'][0]['hooks'][0]
    if mutation.startswith('missing_'):
        del handler[mutation.removeprefix('missing_')]
    elif mutation == 'groups':
        hooks['hooks']['PostToolUse'] = {}
    elif mutation == 'handlers':
        hooks['hooks']['PostToolUse'][0]['hooks'] = {}
    else:
        handler[mutation] = {'type': 'unknown', 'input': [], 'timeout': True, 'statusMessage': 123}[mutation]
    hook_path.write_text(json.dumps(hooks), encoding='utf-8')
    before = path.read_bytes(), hook_path.read_bytes()
    for action in ('setup', 'repair', 'uninstall', 'status'):
        with pytest.raises(IntegrationDiagnostic, match='CONFIG_INVALID'):
            installed.execute(action)
        assert (path.read_bytes(), hook_path.read_bytes()) == before


def test_inline_runtime_hook_conflict_not_hidden_by_state(installed):
    raw = STATE + b'[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype="mcp_tool"\nserver="ai_security_runtime"\ntool="handle_stop_event"\n'
    path = configure(installed, raw)
    with pytest.raises(IntegrationDiagnostic, match='POTENTIAL_DUPLICATE_HOOK'):
        installed.execute('setup')
    assert path.read_bytes() == raw


def test_state_not_allowed_as_json_event(installed):
    path = configure(installed, STATE)
    hook_path = installed.home / 'hooks.json'
    raw = json.dumps({'hooks': {'state': {'key': {'enabled': True}}}}).encode()
    hook_path.write_bytes(raw)
    with pytest.raises(IntegrationDiagnostic, match='CONFIG_INVALID'):
        installed.execute('setup')
    assert path.read_bytes() == STATE and hook_path.read_bytes() == raw


def test_inline_view_does_not_mutate_document():
    document = tomllib.loads((STATE + INLINE).decode())
    before = copy.deepcopy(document)
    assert set(CodexIntegrationAdapter._inline_hooks(document)) == {'PostToolUse'}
    assert document == before
