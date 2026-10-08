"""Global semantic identity and the still-strict project legacy boundary."""
import tomllib
import pytest
from test_global_integration import installed, projects
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from security_runtime.codex_integration import SERVER


def install(installed, projects):
    installed.execute('setup', projects[0])
    return installed.home / 'config.toml'


def drift(path):
    raw = path.read_bytes()
    raw = raw.replace(b'enabled = true', b'enabled    =    true # host serialization')
    raw = raw.replace(b'required = true', b'\nrequired=true')
    path.write_bytes(raw)


@pytest.mark.parametrize('formatting', ['spaces', 'crlf', 'single-quotes'])
def test_signed_format_drift_and_repair(installed, projects, formatting):
    path = install(installed, projects)
    canonical = path.read_bytes()
    if formatting == 'spaces':
        drift(path)
    elif formatting == 'crlf':
        path.write_bytes(canonical.replace(b'\n', b'\r\n').replace(b'enabled = true', b'enabled=true'))
    else:
        path.write_bytes(canonical.replace(b'"codex"', b"'codex'"))
    assert path.read_bytes() != canonical
    status = installed.configuration_status()
    assert status['mcp']['status'] == 'CONFIGURED'
    assert installed.execute('repair', projects[0])['operation'] == 'REPAIRED'
    assert path.read_bytes().endswith(canonical)
    assert tomllib.loads(path.read_text()) == tomllib.loads(canonical.decode())
    assert installed.execute('repair', projects[0])['operation'] == 'ALREADY_CONFIGURED'
    assert installed._manifest(installed.home)['phase'] == 'COMMITTED'


@pytest.mark.parametrize('field', ['command', 'args', 'env', 'enabled', 'required', 'startup_timeout_sec', 'tool_timeout_sec', 'cwd', 'unknown'])
def test_semantic_tampering_rejected(installed, projects, field):
    path = install(installed, projects)
    drift(path)
    text = path.read_text()
    if field == 'env':
        text = text.replace('SECURITY_RUNTIME_GLOBAL = "1"', 'SECURITY_RUNTIME_GLOBAL = "0"')
    elif field in ('cwd', 'unknown'):
        text = text.replace('[mcp_servers.ai_security_runtime.env]', field + ' = "foreign"\n[mcp_servers.ai_security_runtime.env]')
    else:
        lines = text.splitlines()
        i = next(i for i,line in enumerate(lines) if line.split('=',1)[0].strip() == field)
        value = {'command':'"foreign"', 'args':'["foreign"]', 'enabled':'false', 'required':'false',
                 'startup_timeout_sec':'61', 'tool_timeout_sec':'121'}[field]
        lines[i] = field + ' = ' + value
        text = '\n'.join(lines) + '\n'
    path.write_text(text)
    with pytest.raises(IntegrationDiagnostic, match='MCP_CONFIGURATION_CONFLICT'):
        installed.configuration_status()
    before = path.read_bytes()
    with pytest.raises(IntegrationDiagnostic, match='MCP_CONFIGURATION_CONFLICT'):
        installed.execute('repair', projects[0])
    assert path.read_bytes() == before


def test_sibling_servers_and_host_hook_state_preserved(installed, projects):
    path = install(installed, projects)
    siblings = b'\n# host-owned\n[mcp_servers.endor_like_tool]\ncommand="fixture-a"\n[mcp_servers.node_like_tool]\ncommand="fixture-b"\n[hooks.state.fixture]\nenabled=true\ntrusted_hash="synthetic"\n[desktop]\nfixture=true\n'
    # Prefix keeps unrelated semantics outside the managed block, byte-for-byte.
    canonical = path.read_bytes()
    path.write_bytes(siblings + canonical)
    drift(path)
    assert installed.configuration_status()['mcp']['status'] == 'CONFIGURED'
    assert installed.execute('repair', projects[0])['operation'] == 'REPAIRED'
    assert path.read_bytes().startswith(siblings) and path.read_bytes().endswith(canonical)
    parsed = tomllib.loads(path.read_text())
    assert set(parsed['mcp_servers']) == {SERVER, 'endor_like_tool', 'node_like_tool'}
    assert parsed['hooks']['state']['fixture']['trusted_hash'] == 'synthetic'


@pytest.mark.parametrize('extra', ['[unrelated]\nvalue=true\n', '[mcp_servers.foreign]\ncommand="fixture"\n'])
def test_extra_semantics_inside_marker_rejected(installed, projects, extra):
    adapter = installed.legacy_adapter
    root = projects[0]
    adapter.setup(root)
    path = root / '.codex/config.toml'
    drift(path)
    text = path.read_text().replace('# END AI Security Runtime', extra + '# END AI Security Runtime')
    path.write_text(text)
    with pytest.raises(IntegrationDiagnostic, match='MCP_CONFIGURATION_CONFLICT'):
        adapter._config(root)


@pytest.mark.parametrize('damage', ['mismatch', 'unknown-version', 'duplicate', 'manifest'])
def test_drift_still_requires_markers_and_signed_manifest(installed, projects, damage):
    adapter = installed.legacy_adapter
    root = projects[0]
    adapter.setup(root)
    path = root / '.codex/config.toml'
    drift(path)
    raw = path.read_bytes()
    if damage == 'mismatch':
        raw = raw.replace(b'# END AI Security Runtime managed Codex v0.2', b'# END AI Security Runtime managed Codex v0.1')
    elif damage == 'unknown-version':
        raw = raw.replace(b'managed Codex v0.2', b'managed Codex v9.9')
    elif damage == 'duplicate':
        raw += raw
    else:
        manifest = adapter._state_path(root, 'ownership.json')
        manifest.write_bytes(manifest.read_bytes().replace(b'COMMITTED', b'CORRUPTED'))
    path.write_bytes(raw)
    with pytest.raises(IntegrationDiagnostic):
        adapter._config(root)


def test_relative_cli_status_uses_local_path(installed, projects, monkeypatch, capsys):
    from security_runtime.cli import main
    import security_runtime.global_integration as module
    install(installed, projects)
    monkeypatch.setattr(module, 'GlobalCodexIntegration', lambda **kw: installed)
    monkeypatch.chdir(projects[0])
    assert main(['status', '--path', '.', '--json']) == 0
    assert 'GLOBAL_CONFIGURATION_REJECTED' not in capsys.readouterr().out


def test_status_reads_explicitly_enrolled_dev_without_reenrollment(installed, projects):
    discover = installed.discover
    installed.discover = lambda: dict(discover(), kind='DEV')
    installed.allow_dev = True
    install(installed, projects)
    drift(installed.home / 'config.toml')
    installed.allow_dev = False
    assert installed.status()['mcp']['status'] == 'CONFIGURED'
    with pytest.raises(IntegrationDiagnostic, match='INSTALLED_RUNTIME_REQUIRED'):
        installed.execute('repair', projects[0])
