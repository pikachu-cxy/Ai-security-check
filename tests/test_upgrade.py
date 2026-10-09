import json
import time
import tomllib

import pytest

from security_runtime.integration_lifecycle import IntegrationDiagnostic
from security_runtime.review_skill import ReviewSkillManager
from security_runtime.upgrade import InstallationUpgrade
from security_runtime.trial import TrialProfile, isolated_environment
from test_global_integration import installed, projects


@pytest.fixture
def upgrade(installed, tmp_path):
    return InstallationUpgrade(installed, ReviewSkillManager(tmp_path / 'skills', tmp_path / 'skill-state'))


def test_plan_and_diagnosis_read_only_and_no_env_disclosure(upgrade, projects):
    folder = projects[0] / '.codex'
    folder.mkdir()
    raw = b'[mcp_servers.ai_security_runtime]\ncommand="unknown-do-not-execute"\n[mcp_servers.ai_security_runtime.env]\nPRIVATE="do-not-print-this"\n[mcp_servers.other]\ncommand="keep"\n'
    (folder / 'config.toml').write_bytes(raw)
    before = {p: p.read_bytes() for p in folder.iterdir()}
    diagnosis = upgrade.diagnose(projects[0])
    assert 'do-not-print-this' not in json.dumps(diagnosis)
    assert diagnosis['layers'][1]['action'] == 'REMOVE_SERVER_WITH_EXPLICIT_APPROVAL'
    plan = upgrade.plan(projects[0])
    assert not plan['blocked']
    assert before == {p: p.read_bytes() for p in folder.iterdir()}
    assert not upgrade.directory.exists()
    assert not upgrade.integration.home.exists()
    with pytest.raises(IntegrationDiagnostic, match='USER_MANAGED_APPROVAL_REQUIRED'):
        upgrade.apply(plan)
    assert (folder / 'config.toml').read_bytes() == raw
    assert upgrade.apply(plan, approve_user_managed=True)['status'] == 'UPGRADED'
    assert tomllib.loads((folder / 'config.toml').read_text())['mcp_servers'] == {'other': {'command': 'keep'}}


def test_signed_migration_preserves_keys_and_unrelated_content(upgrade, projects):
    old = upgrade.integration.legacy_adapter
    old.setup(projects[0])
    key = old._state_path(projects[0], 'snapshot.key')
    prior = key.read_bytes()
    for _ in range(3):
        assert upgrade.apply(upgrade.plan(projects[0]))['state_and_keys_preserved']
    assert key.read_bytes() == prior
    assert upgrade.skill.status()['status'] == 'INSTALLED'


@pytest.mark.parametrize('change', ['config', 'expired', 'plan'])
def test_plan_cas_expiry_and_untrusted_plan(upgrade, projects, change):
    plan = upgrade.plan(projects[0])
    if change == 'config':
        upgrade.integration.home.mkdir()
        (upgrade.integration.home / 'config.toml').write_text('model="user-changed"\n')
    elif change == 'expired':
        upgrade.now = lambda: plan['issued_at'] + 901
    else:
        plan['steps'][0]['layer'] = str(projects[1])
    with pytest.raises(IntegrationDiagnostic, match='UPGRADE_PLAN_(EXPIRED|CHANGED)'):
        upgrade.apply(plan, approve_user_managed=True)
    assert not upgrade.skill.root.exists()


def test_invalid_signature_never_reenrolled(upgrade, projects):
    upgrade.integration.execute('setup')
    path = upgrade.integration._state_path(upgrade.integration.home, 'ownership.json')
    raw = json.loads(path.read_bytes())
    raw['signature'] = '0' * 64
    path.write_text(json.dumps(raw))
    before = path.read_bytes()
    assert upgrade.diagnose()['layers'][0]['diagnostics'] == ['OWNERSHIP_INVALID']
    assert 'OWNERSHIP_INVALID' in upgrade.plan()['blocked']
    with pytest.raises(IntegrationDiagnostic, match='UPGRADE_PLAN_BLOCKED'):
        upgrade.apply(upgrade.plan())
    assert path.read_bytes() == before


def test_cross_component_crash_recovery_and_later_user_edits(upgrade, projects, monkeypatch):
    plan = upgrade.plan(projects[0])
    real = upgrade.skill.execute
    def crash(action):
        real(action)
        raise RuntimeError('simulated process death after Skill writes')
    monkeypatch.setattr(upgrade.skill, 'execute', crash)
    with pytest.raises(RuntimeError):
        upgrade.apply(plan)
    config = upgrade.integration.home / 'config.toml'
    prior = config.read_bytes()
    config.write_bytes(prior + b'\nmodel="user edit"\n')
    with pytest.raises(IntegrationDiagnostic, match='UPGRADE_RECOVERY_CONCURRENT_CHANGE'):
        upgrade.recover()
    assert upgrade.skill.root.joinpath('SKILL.md').exists()
    config.write_bytes(prior)
    assert upgrade.recover()['status'] == 'RECOVERED'
    assert not config.exists()
    assert not upgrade.skill.root.joinpath('SKILL.md').exists()
    # Signing keys are retained, while failed enrollment receipts are removed.
    assert upgrade.integration._state_path(upgrade.integration.home, 'snapshot.key').is_file()
    monkeypatch.setattr(upgrade.skill, 'execute', real)
    assert upgrade.apply(upgrade.plan(projects[0]))['status'] == 'UPGRADED'


def test_trial_environment_clears_inherited_bindings(tmp_path):
    root = tmp_path / 'trial'
    profile = TrialProfile(root)
    result = profile.create()
    env = isolated_environment(root, {'SECURITY_RUNTIME_GLOBAL': '1', 'SECURITY_RUNTIME_WORKSPACE': 'real',
        'SECURITY_RUNTIME_STATE_DIR': 'real-state', 'CODEX_HOME': 'real-home', 'SEMGREP_APP_TOKEN': 'secret',
        'PYTHONPATH': 'foreign', 'PATH': 'keep'})
    assert env['PATH'] == 'keep'
    assert 'SECURITY_RUNTIME_GLOBAL' not in env and 'SEMGREP_APP_TOKEN' not in env and 'PYTHONPATH' not in env
    assert env['SECURITY_RUNTIME_STATE_DIR'] == str(root / 'state')
    assert result['desktop'].startswith('PENDING')
    with pytest.raises(FileExistsError):
        profile.create()
    with pytest.raises(ValueError, match='TRIAL_TARGET_OUTSIDE_PROFILE'):
        profile.run(['setup', '--path', str(tmp_path / 'real'), '--dev'])


def test_unknown_related_hooks_are_not_auto_removed(upgrade, projects):
    from security_runtime.codex_integration import product_hooks
    folder = projects[0] / '.codex'
    folder.mkdir()
    (folder / 'hooks.json').write_text(json.dumps(product_hooks()))
    plan = upgrade.plan(projects[0])
    assert 'POTENTIAL_DUPLICATE_HOOK' in plan['blocked']
    with pytest.raises(IntegrationDiagnostic, match='UPGRADE_PLAN_BLOCKED'):
        upgrade.apply(plan, approve_user_managed=True)


@pytest.mark.parametrize('key_kind', ['installation', 'journal'])
def test_interrupted_upgrade_refuses_changed_or_missing_signing_keys(upgrade, projects, monkeypatch, key_kind):
    real = upgrade.skill.execute
    def crash(action):
        real(action)
        raise RuntimeError('simulated interrupted upgrade')
    monkeypatch.setattr(upgrade.skill, 'execute', crash)
    with pytest.raises(RuntimeError):
        upgrade.apply(upgrade.plan(projects[0]))
    config = upgrade.integration.home / 'config.toml'
    original = config.read_bytes()
    if key_kind == 'installation':
        key = upgrade.integration._state_path(upgrade.integration.home, 'snapshot.key')
        key.write_bytes(b'x' * 32)
        code = 'UPGRADE_RECOVERY_SIGNING_KEY_CHANGED'
    else:
        key = upgrade.directory / 'snapshot.key'
        key.unlink()
        code = 'UPGRADE_JOURNAL_INVALID'
    with pytest.raises(IntegrationDiagnostic, match=code):
        upgrade.recover()
    assert config.read_bytes() == original
    if key_kind == 'journal':
        with pytest.raises(IntegrationDiagnostic, match=code):
            upgrade._save({'contract': 'installation-upgrade-v1'})
        assert not key.exists()


def test_untrusted_plan_shape_and_incomplete_trial_arguments_are_bounded(upgrade, tmp_path):
    with pytest.raises(IntegrationDiagnostic, match='UPGRADE_PLAN_INVALID'):
        upgrade.apply([])
    profile = TrialProfile(tmp_path / 'isolated-arguments')
    profile.create()
    with pytest.raises(ValueError, match='TRIAL_ARGUMENT_INVALID'):
        profile.run(['status', '--path'])


def test_trial_cli_json_and_frozen_child_use_native_executable(tmp_path, monkeypatch, capsys):
    from security_runtime.cli import main
    import subprocess
    import sys
    from types import SimpleNamespace
    root = tmp_path / 'cli-native-trial'
    assert main(['trial', 'create', '--root', str(root), '--json']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'ISOLATED_PROFILE'
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(tmp_path / 'fixture-runtime.exe'))
    def run(command, **kwargs):
        assert command == [sys.executable, 'runtime-info', '--json']
        assert kwargs['cwd'] == root / 'workspace'
        assert kwargs['env']['SECURITY_RUNTIME_STATE_DIR'] == str(root / 'state')
        assert kwargs['stdin'] == subprocess.DEVNULL
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(subprocess, 'run', run)
    assert main(['trial', 'run', '--root', str(root), '--', 'runtime-info', '--json']) == 0


@pytest.mark.parametrize('arguments', [
    ['review-skill', 'install', '--skills-d=outside'],
    ['upgrade', 'plan', '--out=outside'],
    ['setup', 'codex', '--p=outside'],
    ['setup', 'cursor', '--scope', 'global'],
    ['setup', 'workbuddy'],
])
def test_trial_rejects_abbreviated_paths_and_other_editor_setup(tmp_path, monkeypatch, arguments):
    import subprocess
    profile = TrialProfile(tmp_path / 'trial-boundary')
    profile.create()
    def unexpected(*args, **kwargs):
        pytest.fail('Rejected trial arguments must not start a child process')
    monkeypatch.setattr(subprocess, 'run', unexpected)
    with pytest.raises(ValueError, match='TRIAL_(ARGUMENT_INVALID|INTEGRATION_NOT_ALLOWED)'):
        profile.run(arguments)


def test_trial_setup_without_integration_never_auto_detects_other_editors(tmp_path, monkeypatch):
    import subprocess
    from types import SimpleNamespace
    profile = TrialProfile(tmp_path / 'trial-codex-only')
    profile.create()
    def run(command, **kwargs):
        assert command[-4:] == ['setup', 'codex', '--scope', 'project']
        assert kwargs['env']['SECURITY_RUNTIME_CODEX_HOME'] == str(profile.root / 'codex-home')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(subprocess, 'run', run)
    assert profile.run(['setup', '--scope', 'project']) == 0
