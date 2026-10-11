"""Single global installation and actionable, non-mutating conflict feedback."""
import asyncio
import json
import tomllib

import pytest

from security_runtime.cli import main
from security_runtime.codex_integration import product_hooks
from security_runtime.global_integration import GLOBAL, render_global
from security_runtime.global_mcp import create_global_server
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from security_runtime.integration_recovery import configuration_recovery, repair_connection, display_command
from security_runtime.review_skill import ReviewSkillManager
from security_runtime.upgrade import InstallationUpgrade
from test_global_integration import installed, projects, pool_fixture


def unknown_project(root):
    folder = root / '.codex'
    folder.mkdir()
    raw = (b'# retain this comment\nmodel="keep-model"\n'
           b'[mcp_servers.ai_security_runtime]\ncommand="do-not-execute"\nargs=["mcp"]\n'
           b'[mcp_servers.ai_security_runtime.env]\nPRIVATE="do-not-disclose"\n'
           b'[mcp_servers.other]\ncommand="keep-other"\n')
    path = folder / 'config.toml'
    path.write_bytes(raw)
    return path, raw


def test_setup_path_is_global_unless_scope_explicit(installed, projects, tmp_path, monkeypatch, capsys):
    import security_runtime.global_integration as module
    monkeypatch.setattr(module, 'GlobalCodexIntegration', lambda **kwargs: installed)
    monkeypatch.setenv('SECURITY_RUNTIME_SKILLS_DIR', str(tmp_path / 'skills'))
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    assert main(['setup', 'codex', '--path', str(projects[0]), '--json']) == 0
    value = json.loads(capsys.readouterr().out)
    assert value['scope'] == 'GLOBAL'
    assert value['skill']['status'] == 'INSTALLED'
    assert value['installation']['local_files_ready'] is True
    assert not (projects[0] / '.codex').exists()
    assert not (projects[1] / '.codex').exists()


def test_scan_conflict_returns_location_and_confirmation_without_writes(installed, projects, tmp_path):
    installed.execute('setup')
    path, raw = unknown_project(projects[0])
    pool = pool_fixture(installed, tmp_path)
    server = create_global_server(workspaces=pool)
    try:
        result = asyncio.run(server.call_tool('scan_project', {'workspace_path': str(projects[0]), 'summary': True}))
        data = result.structuredContent
        assert data['scanner_run'] is False and data['coverage'] == 'UNKNOWN'
        recovery = data['configuration_recovery']
        assert recovery['confirmation_required'] is True
        assert recovery['issues'][0]['config_path'] == str(path)
        assert recovery['repair_argv'][-1] == '--approve-user-managed'
        assert '全局' in recovery['message'] and '扫描' in recovery['message']
        assert '是否' in recovery['question']
        assert 'do-not-disclose' not in result.model_dump_json()
        assert 'do-not-execute' not in result.model_dump_json()
        assert path.read_bytes() == raw
        assert not pool.children and not pool.jobs
    finally:
        pool.close()


def test_repair_without_confirmation_explains_conflict_and_preserves_everything(installed, projects, monkeypatch, capsys):
    import security_runtime.global_integration as module
    installed.execute('setup')
    path, raw = unknown_project(projects[0])
    before = (installed.home / 'config.toml').read_bytes()
    monkeypatch.setattr(module, 'GlobalCodexIntegration', lambda **kwargs: installed)
    assert main(['repair', '--path', str(projects[0]), '--json']) == 2
    value = json.loads(capsys.readouterr().out)
    assert value['configuration_recovery']['confirmation_required'] is True
    assert path.read_bytes() == raw
    assert (installed.home / 'config.toml').read_bytes() == before


def test_one_repair_command_migrates_confirmed_server_preserves_other_settings(installed, projects, monkeypatch, capsys):
    import security_runtime.global_integration as module
    installed.execute('setup')
    path, raw = unknown_project(projects[0])
    monkeypatch.setattr(module, 'GlobalCodexIntegration', lambda **kwargs: installed)
    argv = ['repair', '--path', str(projects[0]), '--approve-user-managed', '--json']
    assert main(argv) == 0
    value = json.loads(capsys.readouterr().out)
    assert value['overall'] == 'CONFIGURED' and value['scope'] == 'GLOBAL'
    assert value['reconnect_required'] is True
    assert value['state_and_keys_preserved'] is True
    assert value['recovery_record']
    document = tomllib.loads(path.read_text())
    assert document['model'] == 'keep-model'
    assert document['mcp_servers'] == {'other': {'command': 'keep-other'}}
    assert path.read_bytes().startswith(b'# retain this comment\nmodel="keep-model"\n')
    assert not (projects[1] / '.codex').exists()
    assert (projects[0] / 'src/A.java').read_text() == 'class A {}\n'
    assert main(argv) == 0
    capsys.readouterr()
    assert not (projects[0] / '.codex/hooks.json').exists()


def test_unowned_hook_not_removed_even_when_server_removal_confirmed(installed, projects, monkeypatch, capsys):
    import security_runtime.global_integration as module
    installed.execute('setup')
    path, raw = unknown_project(projects[0])
    hook = path.parent / 'hooks.json'
    hook.write_text(json.dumps(product_hooks()))
    before = hook.read_bytes()
    monkeypatch.setattr(module, 'GlobalCodexIntegration', lambda **kwargs: installed)
    assert main(['repair', '--path', str(projects[0]), '--approve-user-managed', '--json']) == 2
    value = json.loads(capsys.readouterr().out)
    assert value['overall'] == 'BROKEN'
    assert value['configuration_recovery']['automatic_repair_available'] is False
    assert path.read_bytes() == raw and hook.read_bytes() == before


def test_probe_failure_does_not_hide_valid_global_configuration(installed):
    installed.execute('setup')
    def failed(*args):
        raise IntegrationDiagnostic('MCP_PROBE_FAILED')
    installed.probe = failed
    value = installed.status()
    assert value['ownership'] == GLOBAL
    assert value['mcp']['status'] == 'CONFIGURED'
    assert value['post_tool_hook']['status'] == 'CONFIGURED'
    assert value['overall'] == 'DEGRADED'
    assert value['runtime']['status'] == 'MCP_PROBE_FAILED'
    assert value['live_connection'] == 'UNKNOWN'


def test_owned_stale_global_explains_underlying_reason(installed, projects, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    hooks = installed.home / 'hooks.json'
    value = json.loads(hooks.read_bytes())
    value['hooks'].pop('Stop')
    hooks.write_text(json.dumps(value))
    before = hooks.read_bytes()
    try:
        result = asyncio.run(create_global_server(workspaces=pool).call_tool('get_security_summary', {
            'workspace_path': str(projects[0])}))
        recovery = result.structuredContent['configuration_recovery']
        assert any('HOOK_MISSING' in row['diagnostics'] for row in recovery['issues'])
        assert recovery['confirmation_required'] is False
        assert result.structuredContent['scanner_run'] is False
        assert hooks.read_bytes() == before
    finally:
        pool.close()


def test_invalid_global_receipt_remains_blocked_after_explicit_approval(installed, projects, monkeypatch, capsys):
    import security_runtime.global_integration as module
    installed.execute('setup')
    receipt = installed._state_path(installed.home, 'ownership.json')
    value = json.loads(receipt.read_bytes())
    value['signature'] = '0' * 64
    receipt.write_text(json.dumps(value))
    before = receipt.read_bytes()
    monkeypatch.setattr(module, 'GlobalCodexIntegration', lambda **kwargs: installed)
    assert main(['repair', '--path', str(projects[0]), '--approve-user-managed', '--json']) == 2
    assert receipt.read_bytes() == before
    recovery = json.loads(capsys.readouterr().out)['configuration_recovery']
    assert recovery['automatic_repair_available'] is False


def test_invalid_workspace_claim_is_not_echoed_as_recovery(installed, tmp_path):
    pool = pool_fixture(installed, tmp_path)
    try:
        result = asyncio.run(create_global_server(workspaces=pool).call_tool('get_security_summary', {
            'workspace_path': 'PRIVATE-UNTRUSTED-CLAIM'}))
        assert 'configuration_recovery' not in result.structuredContent
        assert 'PRIVATE-UNTRUSTED-CLAIM' not in result.model_dump_json()
    finally:
        pool.close()


def test_connection_only_repair_preserves_custom_skill(installed, projects, tmp_path, monkeypatch):
    import security_runtime.upgrade as module
    skill = ReviewSkillManager(tmp_path / 'custom-skills', tmp_path / 'skill-state')
    skill.root.mkdir(parents=True)
    path = skill.root / 'SKILL.md'
    path.write_bytes(b'custom user Skill must not be replaced')
    monkeypatch.setattr(module, 'ReviewSkillManager', lambda: skill)
    installed.execute('setup')
    unknown_project(projects[0])
    assert repair_connection(installed, projects[0], approve_user_managed=True)['overall'] == 'CONFIGURED'
    assert path.read_bytes() == b'custom user Skill must not be replaced'
    assert not skill.state.exists()


def test_signed_project_repair_uses_journal_without_extra_unknown_approval(installed, projects):
    installed.legacy_adapter.setup(projects[0])
    recovery = configuration_recovery(installed, projects[0])
    assert recovery['issues'][-1]['diagnostics'] == ['LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR']
    key = installed.legacy_adapter._state_path(projects[0], 'snapshot.key')
    before = key.read_bytes()
    result = repair_connection(installed, projects[0])
    assert result['migration'] == {'status': 'MIGRATED', 'removed_layers': 1}
    assert result['recovery_record']
    assert key.read_bytes() == before
    assert 'ai_security_runtime' not in tomllib.loads((projects[0] / '.codex/config.toml').read_text()).get('mcp_servers', {})


def test_interrupted_connection_repair_offers_signed_recovery_not_another_repair(installed, projects):
    installed.execute('setup')
    path, raw = unknown_project(projects[0])
    def failed(*args):
        raise IntegrationDiagnostic('MCP_PROBE_FAILED')
    installed.probe = failed
    with pytest.raises(IntegrationDiagnostic, match='MCP_PROBE_FAILED'):
        repair_connection(installed, projects[0], approve_user_managed=True)
    recovery = configuration_recovery(installed, projects[0], reason='UPGRADE_GLOBAL_NOT_READY')
    assert 'UPGRADE_RECOVERY_REQUIRED' in recovery['blocked']
    assert recovery['repair_argv'] == []
    assert recovery['recovery_argv'][-2:] == ['upgrade', 'recover']
    assert recovery['automatic_repair_available'] is False
    assert '确认后恢复' in render_global({'configuration_recovery': recovery})
    assert InstallationUpgrade(installed, manage_skill=False).recover()['status'] == 'RECOVERED'
    assert path.read_bytes() == raw


def test_invalid_codex_home_returns_bounded_cli_error(monkeypatch, capsys):
    import security_runtime.global_integration as module
    def failed(**kwargs):
        raise IntegrationDiagnostic('CODEX_HOME_INVALID')
    monkeypatch.setattr(module, 'GlobalCodexIntegration', failed)
    assert main(['status', '--json']) == 2
    value = json.loads(capsys.readouterr().out)
    assert value['diagnostics'] == ['CODEX_HOME_INVALID']
    assert 'configuration_recovery' not in value


def test_windows_command_guidance_handles_spaces_and_literal_apostrophes(monkeypatch):
    import security_runtime.integration_recovery as module
    monkeypatch.setattr(module.os, 'name', 'nt')
    assert display_command(['C:/Program Files/Runtime/security-check.exe', 'repair', '--path', "C:/Jane's project"]) == (
        "& 'C:/Program Files/Runtime/security-check.exe' 'repair' '--path' 'C:/Jane''s project'")
