"""Personal setup is a coordinated transaction, not a Skill packaging claim."""
import json
import subprocess
from types import SimpleNamespace
from pathlib import Path

import pytest

from security_runtime.cli import main
from security_runtime.integration_lifecycle import IntegrationDiagnostic
from security_runtime.personal_install import setup_personal_codex, install_personal_codex, CONTRACT
from security_runtime.review_skill import ReviewSkillManager, RETIRED_METHODS
from security_runtime.upgrade import InstallationUpgrade
from test_global_integration import installed, projects
from test_delivery import bundle
from security_runtime.delivery import EXE


def ready_scanning_receipt():
    versions = {'semgrep': '1.178.0', 'gitleaks': '8.30.0', 'trivy': '0.74.0'}
    return {'contract': 'installation-readiness-v1', 'status': 'READY',
            'ready': True, 'message': '检查工具和漏洞数据已准备完成。',
            'network_allowed': False,
            'tools': {name: {'status': 'READY', 'version': version,
                             'expected_version': version, 'ready': True}
                      for name, version in versions.items()},
            'vulnerability_db': {'status': 'READY', 'freshness': 'FRESH',
                                 'ready': True, 'cached_usable': True},
            'failures': []}


@pytest.fixture
def skill(tmp_path):
    return ReviewSkillManager(tmp_path / 'skills', tmp_path / 'skill-state')


def test_first_setup_installs_global_and_skill_without_project_writes(installed, projects, skill):
    stages = []
    data = setup_personal_codex(installed, projects[0], skill=skill, progress=stages.append)
    assert stages == ['CHECK_CONFIG', 'APPLY_CONFIG', 'GLOBAL_CONFIG', 'SKILL', 'SELF_CHECK']
    assert data['overall'] == 'CONFIGURED'
    assert data['installation']['local_files_ready'] is True
    assert data['skill']['status'] == 'INSTALLED'
    assert data['installation']['completed_steps'] == ['REPAIR_GLOBAL', 'UPGRADE_SKILL']
    assert (skill.root / 'references/deep-audit.md').is_file()
    assert not any((root / '.codex').exists() for root in projects)
    assert not data['installation']['risk_fix_authorized']
    assert data['installation']['live_host_connection'] == 'NOT_VERIFIED_UNTIL_RECONNECT'
    assert not any(data['execution'].values())


@pytest.mark.parametrize('existing', [False, True])
def test_default_setup_leaves_optional_git_hook_untouched(installed, projects, skill, existing):
    hook = projects[0] / '.git/hooks/pre-commit'
    if existing:
        hook.write_bytes(b'#!/bin/sh\n# user installed hook\nexit 0\n')
    before = (hook.read_bytes(), hook.stat().st_mtime_ns) if existing else None
    data = setup_personal_codex(installed, projects[0], skill=skill)
    assert data['overall'] == 'CONFIGURED'
    assert (installed.home / 'hooks.json').is_file()
    assert (installed.home / 'config.toml').is_file()
    assert (skill.root / 'SKILL.md').is_file()
    if existing:
        assert (hook.read_bytes(), hook.stat().st_mtime_ns) == before
    else:
        assert not hook.exists()


def test_repeat_install_is_idempotent_preserves_user_files(installed, skill):
    installed.home.mkdir()
    original = b'# keep this comment\nmodel="custom"\n[mcp_servers.other]\ncommand="other"\n'
    config = installed.home / 'config.toml'
    config.write_bytes(original)
    assert setup_personal_codex(installed, skill=skill)['installation']['local_files_ready']
    note = skill.root / 'notes.md'
    note.write_bytes(b'user note')
    paths = [config, installed.home / 'hooks.json', skill.root / 'SKILL.md', skill.root / 'references/deep-audit.md']
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
    assert setup_personal_codex(installed, skill=skill)['installation']['local_files_ready']
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
    assert config.read_bytes().startswith(original) and note.read_bytes() == b'user note'


@pytest.mark.parametrize('owned', [False, True])
def test_user_skill_conflict_blocks_before_global_writes(installed, skill, owned):
    if owned:
        skill.execute('install')
    else:
        skill.root.mkdir(parents=True)
    path = skill.root / 'SKILL.md'
    path.write_bytes(b'user customized instructions')
    data = setup_personal_codex(installed, skill=skill)
    assert data['overall'] == 'BROKEN' and not data['installation']['local_files_ready']
    assert 'SKILL_USER_CONTENT_PRESERVED' in data['diagnostics']
    assert path.read_bytes() == b'user customized instructions'
    assert not (installed.home / 'config.toml').exists()


def test_signed_old_skill_is_upgraded_in_same_setup(installed, skill):
    current = skill.expected
    skill.expected = dict(current, **{'SKILL.md': b'previous signed Skill'})
    skill.execute('install')
    skill.expected = current
    assert skill.status()['status'] == 'UPGRADE_AVAILABLE'
    assert setup_personal_codex(installed, skill=skill)['installation']['local_files_ready']
    assert (skill.root / 'SKILL.md').read_bytes() == current['SKILL.md']


@pytest.mark.parametrize('customized', [False, True])
def test_coordinated_upgrade_cleans_owned_retired_methods_and_preserves_user_edits(installed, skill, customized):
    current = skill.expected
    skill.expected = current | {name: b'old managed method' for name in RETIRED_METHODS}
    assert skill.execute('install')['status'] == 'INSTALLED'
    skill.expected = current
    key = (skill.state / 'ownership.key').read_bytes()
    personal = skill.root / sorted(RETIRED_METHODS)[0]
    if customized:
        personal.write_bytes(b'user customized retired method')

    result = setup_personal_codex(installed, skill=skill)

    assert result['installation']['local_files_ready'] is True, result['diagnostics']
    assert result['skill']['status'] == 'INSTALLED'
    for name in RETIRED_METHODS:
        path = skill.root / name
        if customized and path == personal:
            assert path.read_bytes() == b'user customized retired method'
        else:
            assert not path.exists()
    assert (skill.state / 'ownership.key').read_bytes() == key


def test_coordinated_upgrade_restores_retired_methods_after_late_failure(installed, skill, monkeypatch):
    current = skill.expected
    skill.expected = current | {name: b'old managed method' for name in RETIRED_METHODS}
    assert skill.execute('install')['status'] == 'INSTALLED'
    skill.expected = current
    before = {path: path.read_bytes() for path in skill.root.rglob('*') if path.is_file()}
    ownership = (skill.state / 'ownership.json').read_bytes()
    real = skill.execute
    cleaned = []

    def fail_after_upgrade(action):
        assert real(action)['status'] == 'INSTALLED'
        assert all(not (skill.root / name).exists() for name in RETIRED_METHODS)
        cleaned.append(True)
        raise OSError('synthetic failure after retired method cleanup')

    monkeypatch.setattr(skill, 'execute', fail_after_upgrade)
    result = setup_personal_codex(installed, skill=skill)

    assert result['installation']['status'] == 'ROLLED_BACK'
    assert result['installation']['recovery_status'] == 'RECOVERED'
    assert cleaned == [True]
    assert {path: path.read_bytes() for path in skill.root.rglob('*') if path.is_file()} == before
    assert (skill.state / 'ownership.json').read_bytes() == ownership
    assert not (installed.home / 'config.toml').exists()


def test_failed_skill_write_rolls_back_only_this_transaction(installed, skill, monkeypatch):
    installed.home.mkdir()
    config = installed.home / 'config.toml'
    original = b'model="retain me"\n'
    config.write_bytes(original)
    real = skill.execute
    def fail(action):
        real(action)
        raise OSError('private error text must not appear')
    monkeypatch.setattr(skill, 'execute', fail)
    data = setup_personal_codex(installed, skill=skill)
    assert data['installation']['status'] == 'ROLLED_BACK'
    assert data['installation']['recovery_status'] == 'RECOVERED'
    assert config.read_bytes() == original
    assert not (installed.home / 'hooks.json').exists()
    assert not (skill.root / 'SKILL.md').exists()
    assert installed._state_path(installed.home, 'snapshot.key').is_file()
    assert 'private error' not in json.dumps(data)


def test_concurrent_user_edit_prevents_rollback(installed, skill, monkeypatch):
    real = skill.execute
    def fail(action):
        real(action)
        (installed.home / 'config.toml').write_bytes(b'model="concurrent user edit"\n')
        raise OSError()
    monkeypatch.setattr(skill, 'execute', fail)
    data = setup_personal_codex(installed, skill=skill)
    assert data['installation']['status'] == 'RECOVERY_REQUIRED'
    assert (installed.home / 'config.toml').read_bytes() == b'model="concurrent user edit"\n'
    assert (skill.root / 'SKILL.md').is_file()


def test_previous_pending_transaction_not_auto_recovered(installed, skill, monkeypatch):
    manager = InstallationUpgrade(installed, skill)
    real = skill.execute
    def fail(action):
        real(action)
        raise OSError()
    monkeypatch.setattr(skill, 'execute', fail)
    with pytest.raises(OSError):
        manager.apply(manager.plan())
    monkeypatch.setattr(skill, 'execute', real)
    before = (installed.home / 'config.toml').read_bytes()
    data = setup_personal_codex(installed, skill=skill)
    assert data['installation']['status'] == 'RECOVERY_REQUIRED'
    assert (installed.home / 'config.toml').read_bytes() == before
    assert manager._load()['phase'] == 'RECOVERY_REQUIRED'


def test_unknown_server_needs_separate_approval(installed, skill):
    installed.home.mkdir()
    config = installed.home / 'config.toml'
    raw = b'[mcp_servers.ai_security_runtime]\ncommand="do-not-run"\n'
    config.write_bytes(raw)
    data = setup_personal_codex(installed, skill=skill)
    assert 'USER_MANAGED_APPROVAL_REQUIRED' in data['diagnostics']
    assert config.read_bytes() == raw and not skill.root.exists()


def test_unknown_project_not_removed_by_setup(installed, projects, skill):
    folder = projects[0] / '.codex'
    folder.mkdir()
    raw = b'[mcp_servers.ai_security_runtime]\ncommand="private-custom-command"\n'
    (folder / 'config.toml').write_bytes(raw)
    with pytest.raises(IntegrationDiagnostic):
        setup_personal_codex(installed, projects[0], skill=skill)
    assert (folder / 'config.toml').read_bytes() == raw and not skill.root.exists()


def test_single_install_cli_for_python_distribution(installed, monkeypatch, capsys):
    import security_runtime.global_integration as module
    import security_runtime.personal_install as personal_module
    monkeypatch.setattr(module, 'GlobalCodexIntegration', lambda **kwargs: installed)
    monkeypatch.setattr(personal_module, 'prepare_installation_readiness',
                        lambda **kwargs: ready_scanning_receipt())
    assert main(['install', 'codex', '--json']) == 0
    output = capsys.readouterr()
    data = json.loads(output.out)
    assert '开始安装' in output.err and '本地安装完成' in output.err
    assert data['installation']['contract'] == CONTRACT and data['skill']['status'] == 'INSTALLED'


def test_install_cli_has_bounded_json_failure(monkeypatch, capsys):
    import security_runtime.personal_install as module
    def failed(**kwargs):
        raise OSError('private environment contents')
    monkeypatch.setattr(module, 'install_personal_codex', failed)
    assert main(['install', 'codex', '--json']) == 2
    data = json.loads(capsys.readouterr().out)
    assert data['diagnostics'] == ['INSTALL_PATH_OR_STATE_INVALID']
    assert not data['installation']['local_files_ready']
    assert 'private' not in json.dumps(data)


@pytest.fixture
def portable(installed, tmp_path, monkeypatch):
    import security_runtime.global_integration as integration_module
    import security_runtime.delivery as delivery_module
    from security_runtime.delivery import StableDelivery
    import security_runtime.build_identity as identity_module
    # Mock child execution without intercepting unrelated Git provenance calls.
    monkeypatch.setattr(identity_module, 'git_provenance', lambda root, *args: 'a' * 40 if args[0] == 'rev-parse' else ' M fixture')
    monkeypatch.setattr(integration_module, 'GlobalCodexIntegration', lambda **kwargs: installed)
    monkeypatch.setattr(delivery_module, 'StableDelivery', lambda root: StableDelivery(root, probe=lambda _: {'status': 'OK'}))
    return bundle(tmp_path / 'package'), tmp_path / 'program'


def test_portable_installer_uses_validated_fixed_launcher(installed, portable, monkeypatch):
    package, root = portable
    stages = []
    def run(argv, **kwargs):
        assert Path(argv[0]).is_relative_to(root / 'versions') and Path(argv[0]).name == EXE
        assert Path(argv[0]).parent.name == 'bundle'
        if argv[1] == 'setup':
            assert kwargs['stdin'] == subprocess.DEVNULL
            assert stages[-1] == 'SETUP_CHILD'
            assert argv[1:] == ['setup', 'codex', '--json']
            assert kwargs['timeout'] == 120
            return SimpleNamespace(returncode=0, stdout=json.dumps(setup_personal_codex(installed)).encode())
        assert argv[1:] == ['prepare-installation', '--json', '--offline']
        assert kwargs['timeout'] == 45
        return SimpleNamespace(returncode=0, stdout=json.dumps(ready_scanning_receipt()).encode())
    monkeypatch.setattr(subprocess, 'run', run)
    monkeypatch.setattr('security_runtime.personal_install.run_process', run)
    data = install_personal_codex(bundle=package, root=root, progress=stages.append)
    assert stages[:12] == ['PREPARE', 'PACKAGE_VERIFY', 'CHECK_CONFIG', 'PACKAGE_VERIFY',
        'COPY_RUNTIME', 'VERIFY_INSTALLED', 'CAPABILITY_CHECK', 'PREPARE_LAUNCHER',
        'VERIFY_ACTIVATION', 'SETUP_CHILD', 'VERIFY_RECEIPT', 'CHECK_SCAN_CACHE']
    assert stages[-1] == 'CLEANUP'
    assert data['delivery']['status'] == 'ACTIVATED' and data['installation']['local_files_ready']
    assert data['installation']['scan_ready']


@pytest.mark.parametrize('receipt', [b'not json', b'{"installation":[]}', b'{"installation":null}',
    b'{"installation":{"contract":"personal-install-v1","local_files_ready":true,"message":"fake","status":"INSTALLED"},"overall":"CONFIGURED"}'])
def test_invalid_setup_receipt_never_reports_success(portable, monkeypatch, receipt):
    package, root = portable
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=0, stdout=receipt))
    data = install_personal_codex(bundle=package, root=root)
    assert data['overall'] == 'BROKEN' and not data['installation']['local_files_ready']
    assert data['diagnostics'] == ['INSTALLED_SETUP_RECEIPT_INVALID']
    assert (root / 'launcher' / EXE).is_file()


@pytest.mark.parametrize('exception,code', [(OSError('private error'), 'INSTALLED_SETUP_FAILED'),
    (subprocess.TimeoutExpired('fixed', 120, output=b'private output'), 'INSTALLED_SETUP_TIMEOUT')])
def test_child_failure_preserves_files_without_false_success(portable, monkeypatch, exception, code):
    package, root = portable
    def run(*a, **k):
        raise exception
    monkeypatch.setattr(subprocess, 'run', run)
    data = install_personal_codex(bundle=package, root=root)
    assert data['diagnostics'] == [code] and not data['installation']['local_files_ready']
    assert 'private error' not in json.dumps(data)
    assert 'private output' not in json.dumps(data)
    assert (root / 'launcher' / EXE).exists()


def test_portable_preflight_skill_conflict_does_not_activate(portable):
    package, root = portable
    manager = ReviewSkillManager()
    manager.root.mkdir(parents=True)
    (manager.root / 'SKILL.md').write_bytes(b'user content')
    assert not install_personal_codex(bundle=package, root=root)['installation']['local_files_ready']
    assert not root.exists()
