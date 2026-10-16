"""Project-scoped connection and rollback; never launch Codex or a model."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tomllib

import pytest


@pytest.fixture
def installer():
    path = Path(__file__).parents[1] / 'scripts/install_codex_desktop_pilot.py'
    spec = importlib.util.spec_from_file_location('pilot_installer_under_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def lab(tmp_path):
    root, runtime, home = (tmp_path / x for x in ('project', 'runtime', 'codex-home'))
    for path in (root, runtime / 'scripts', home):
        path.mkdir(parents=True)
    (runtime / 'scripts/codex_desktop_pilot.py').write_text('# placeholder, never executed\n')
    python, codex = tmp_path / 'python.exe', tmp_path / 'codex.exe'
    python.write_bytes(b'never executed')
    codex.write_bytes(b'never executed')
    return dict(workspace=root, state_dir=tmp_path / 'external-state',
                runtime_root=runtime, python=python, codex=codex, home=home)


def _status_kwargs(lab):
    return {key: value for key, value in lab.items() if key not in {'python', 'codex'}}


def test_override_same_server_reuses_global_hooks_and_restores_exact_bytes(installer, lab):
    root, home = lab['workspace'], lab['home']
    (root / '.codex').mkdir()
    original = b'# Keep this comment\r\nmodel = "user-choice"\r\n[mcp_servers.other]\r\ncommand = "custom"\r\n'
    agents = b'# Existing local guidance\r\nUse small edits.\r\n'
    (root / '.codex/config.toml').write_bytes(original)
    (root / 'AGENTS.md').write_bytes(agents)
    global_config = b'# unchanged\n[mcp_servers.ai_security_runtime]\ncommand = "formal"\n'
    global_hooks = json.dumps(installer.product_hooks(), ensure_ascii=False).encode()
    (home / 'config.toml').write_bytes(global_config)
    (home / 'hooks.json').write_bytes(global_hooks)
    result = installer.install(**lab)
    assert result['status'] == 'INSTALLED_NOT_OBSERVED'
    assert set(result['hooks_reused']) == {'SessionStart', 'PostToolUse', 'Stop'}
    assert result['hooks_added'] == []
    assert not (root / '.codex/hooks.json').exists()
    config = tomllib.loads((root / '.codex/config.toml').read_text('utf-8'))
    assert config['model'] == 'user-choice'
    assert config['mcp_servers']['other']['command'] == 'custom'
    server = config['mcp_servers']['ai_security_runtime']
    assert server['args'][:2] == ['-I', str(lab['runtime_root'] / 'scripts/codex_desktop_pilot.py')]
    assert server['env']['SECURITY_RUNTIME_GLOBAL'] == '0'
    assert server['env']['SECURITY_RUNTIME_WORKSPACE'] == str(root)
    assert server['env']['SECURITY_RUNTIME_STATE_DIR'] == str(lab['state_dir'])
    assert installer.GUIDANCE in (root / 'AGENTS.md').read_text('utf-8')
    assert installer.install(**lab) == result
    assert installer.remove(**_status_kwargs(lab))['status'] == 'NOT_INSTALLED'
    assert (root / '.codex/config.toml').read_bytes() == original
    assert (root / 'AGENTS.md').read_bytes() == agents
    assert (home / 'config.toml').read_bytes() == global_config
    assert (home / 'hooks.json').read_bytes() == global_hooks


def test_install_adds_only_missing_hooks_and_preserves_other_handlers(installer, lab):
    wanted = installer.product_hooks()
    (lab['home'] / 'hooks.json').write_text(json.dumps({'hooks': {'PostToolUse': wanted['hooks']['PostToolUse']}}))
    directory = lab['workspace'] / '.codex'
    directory.mkdir()
    local = {'description': 'Keep', 'hooks': {'SessionStart': wanted['hooks']['SessionStart'],
        'Stop': [{'hooks': [{'type': 'command', 'command': 'existing-user-hook'}]}]}}
    (directory / 'hooks.json').write_text(json.dumps(local))
    before = (directory / 'hooks.json').read_bytes()
    result = installer.install(**lab)
    assert result['hooks_added'] == ['Stop']
    after = json.loads((directory / 'hooks.json').read_bytes())
    assert after['description'] == 'Keep'
    assert len(after['hooks']['Stop']) == 2
    assert 'PostToolUse' not in after['hooks']
    installer.remove(**_status_kwargs(lab))
    assert (directory / 'hooks.json').read_bytes() == before


def test_inline_global_hooks_are_reused_without_reading_trust_state(installer, lab):
    # Inline SessionStart has exactly the native product input ABI.
    goal = installer.product_hooks()['hooks']['SessionStart'][0]['hooks'][0]
    lines = ['[[hooks.SessionStart]]', '[[hooks.SessionStart.hooks]]']
    lines += [f'{key} = {json.dumps(goal[key])}' for key in ('type', 'server', 'tool')]
    lines += ['[hooks.SessionStart.hooks.input]']
    lines += [f'{key} = {json.dumps(value)}' for key, value in goal['input'].items()]
    lines += ['[hooks.state."opaque-host-state"]', 'enabled = false', 'trusted_hash = "untouched"']
    raw = ('\n'.join(lines) + '\n').encode()
    (lab['home'] / 'config.toml').write_bytes(raw)
    result = installer.install(**lab)
    assert result['hooks_reused'] == ['SessionStart']
    assert set(result['hooks_added']) == {'PostToolUse', 'Stop'}
    assert (lab['home'] / 'config.toml').read_bytes() == raw


def test_remove_refuses_all_writes_if_user_edited_any_owned_file(installer, lab):
    installer.install(**lab)
    root = lab['workspace']
    config = (root / '.codex/config.toml').read_bytes()
    (root / 'AGENTS.md').write_text('# New user instructions after install\n')
    assert installer.status(**_status_kwargs(lab))['status'] == 'CONFIGURATION_CHANGED'
    with pytest.raises(ValueError, match='ROLLBACK_REFUSED'):
        installer.remove(**_status_kwargs(lab))
    assert (root / '.codex/config.toml').read_bytes() == config
    assert (root / 'AGENTS.md').read_text() == '# New user instructions after install\n'


@pytest.mark.parametrize('target', ['project', 'runtime', 'codex-home', 'containing-git', 'parent'])
def test_rejects_unsafe_state_locations_before_any_writes(installer, lab, tmp_path, target):
    paths = {'project': lab['workspace'] / 'state', 'runtime': lab['runtime_root'] / 'state',
             'codex-home': lab['home'] / 'state', 'parent': tmp_path}
    enclosing = tmp_path / 'source'
    enclosing.mkdir()
    (enclosing / '.git').mkdir()
    paths['containing-git'] = enclosing / 'state'
    lab['state_dir'] = paths[target]
    with pytest.raises(ValueError, match='STATE_'):
        installer.install(**lab)
    assert not (lab['workspace'] / '.codex/config.toml').exists()


def test_duplicate_global_and_local_runtime_hooks_refused(installer, lab):
    raw = json.dumps(installer.product_hooks()).encode()
    (lab['home'] / 'hooks.json').write_bytes(raw)
    (lab['workspace'] / '.codex').mkdir()
    (lab['workspace'] / '.codex/hooks.json').write_bytes(raw)
    with pytest.raises(ValueError, match='DUPLICATE_RUNTIME_HOOKS'):
        installer.install(**lab)
    assert not lab['state_dir'].exists()


def test_existing_incompatible_hook_does_not_get_silently_duplicated(installer, lab):
    hooks = installer.product_hooks()
    hooks['hooks']['PostToolUse'][0]['matcher'] = '^Bash$'
    (lab['home'] / 'hooks.json').write_text(json.dumps(hooks))
    with pytest.raises(ValueError, match='EXISTING_RUNTIME_HOOK_REQUIRES_REVIEW'):
        installer.install(**lab)


def test_prepared_install_can_rollback_after_interruption(installer, lab, monkeypatch):
    write = installer.atomic_bytes
    def interrupted(path, raw):
        if path.name == 'AGENTS.md':
            raise OSError('simulated interrupted install')
        write(path, raw)
    monkeypatch.setattr(installer, 'atomic_bytes', interrupted)
    with pytest.raises(OSError):
        installer.install(**lab)
    monkeypatch.setattr(installer, 'atomic_bytes', write)
    assert installer.remove(**_status_kwargs(lab))['status'] == 'NOT_INSTALLED'
    for name in installer.FILES:
        assert not (lab['workspace'] / name).exists()


def test_corrupt_receipt_cannot_select_another_restore_target(installer, lab):
    installer.install(**lab)
    receipt = next(lab['state_dir'].glob('project-install-*.json'))
    saved = json.loads(receipt.read_bytes())
    saved['files']['../../outside.txt'] = saved['files'].pop('AGENTS.md')
    receipt.write_text(json.dumps(saved))
    with pytest.raises(ValueError, match='PILOT_RECEIPT_INVALID'):
        installer.remove(**_status_kwargs(lab))
    assert not (lab['workspace'].parent / 'outside.txt').exists()


def test_missing_launcher_fails_before_configuration_changes(installer, lab):
    (lab['runtime_root'] / 'scripts/codex_desktop_pilot.py').unlink()
    with pytest.raises(ValueError, match='PILOT_LAUNCHER_MISSING'):
        installer.install(**lab)
    assert not lab['state_dir'].exists()


def test_installer_only_status_never_claims_native_connection_or_review_success(installer, lab):
    assert installer.status(**_status_kwargs(lab))['status'] == 'NOT_INSTALLED'
    result = installer.install(**lab)
    assert result['native_events'] == 'NOT_OBSERVED_BY_INSTALLER'
    assert result['hook_trust'] == 'USER_REVIEW_IN_CODEX_REQUIRED_IF_UNTRUSTED'
    assert result['requires_new_codex_session'] is True
    assert result['project_trust'] == 'USER_REVIEW_IN_CODEX'
    assert 'READY' not in json.dumps(result)


def test_status_separates_runtime_callback_report_from_installer_observation(installer, lab):
    installer.install(**lab)
    observation = lab['state_dir'] / 'pilot-connection.json'
    observation.write_text(json.dumps({'workspace': str(lab['workspace']),
        'startup_observed': True, 'readiness_callback_observed': False}))
    result = installer.status(**_status_kwargs(lab))
    assert result['status'] == 'INSTALLED_NOT_OBSERVED'
    assert result['connection_observation']['status'] == 'STARTUP_REPORTED'
    observation.write_text(json.dumps({'workspace': str(lab['workspace']),
        'startup_observed': True, 'readiness_callback_observed': True}))
    result = installer.status(**_status_kwargs(lab))
    assert result['status'] == 'INSTALLED_CALLBACK_REPORTED'
    assert result['connection_observation']['authority'] == 'RUNTIME_REPORTED'
    assert result['native_events'] == 'RUNTIME_REPORTED_CALLBACK'
    assert 'SAFE' not in json.dumps(result)


@pytest.mark.parametrize('payload', [None, {'workspace': 'different', 'readiness_callback_observed': True},
                                   {'readiness_callback_observed': 'true'}])
def test_malformed_or_cross_project_callback_cannot_upgrade_status(installer, lab, payload):
    installer.install(**lab)
    if isinstance(payload, dict) and payload.get('workspace') is None:
        payload['workspace'] = str(lab['workspace'])
    (lab['state_dir'] / 'pilot-connection.json').write_text(json.dumps(payload))
    result = installer.status(**_status_kwargs(lab))
    assert result['status'] == 'INSTALLED_NOT_OBSERVED'
    assert result['connection_observation']['status'] == 'UNVERIFIABLE'
