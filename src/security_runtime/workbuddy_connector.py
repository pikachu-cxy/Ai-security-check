"""Owned WorkBuddy desktop MCP, native command Hooks, and host-local Skill."""
from __future__ import annotations

import os
import shlex
from pathlib import Path

from .codex_integration import unique_json
from .cursor_integration import GlobalCursorIntegration, cursor_home
from .cursor_connector import CursorConnectorInstallation, CursorInstallPreflight
from .hook_state import HookStateStore, no_links
from .owned_json import OwnedJsonServer, WriteTransaction, related
from .review_skill import ReviewSkillManager
from .storage import SQLiteStore

EVENTS = ('SessionStart', 'PreToolUse', 'PostToolUse', 'Stop')


def probe_delivery(bundle):
    """Same complete candidate checks, bounded for cold Intel desktop startup."""
    import tempfile
    from .trial import TrialProfile, isolated_environment
    from .codex_integration import probe_runtime
    with tempfile.TemporaryDirectory(prefix='workbuddy-delivery-probe-') as temporary:
        root = Path(temporary).resolve() / 'profile'
        TrialProfile(root).create()
        env = isolated_environment(root)
        env.update(SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_WORKSPACE='',
                   SECURITY_RUNTIME_INTEGRATION='codex', SECURITY_RUNTIME_MCP_SELF_TEST='1')
        executable = Path(bundle) / ('security-check.exe' if os.name == 'nt' else 'security-check')
        return probe_runtime(dict(kind='FROZEN', command=str(executable), prefix=[]),
                             root/'codex-home', env, timeout=120, mcp_timeout=90)


def workbuddy_home(value=None):
    return cursor_home(value or os.getenv('SECURITY_RUNTIME_WORKBUDDY_HOME') or Path.home() / '.workbuddy-ai')


class WorkBuddyHooks(GlobalCursorIntegration):
    host = 'workbuddy'
    manifest_version = 'workbuddy-global-v1'

    def __init__(self, *, home=None, directory=None, **kwargs):
        super().__init__(home=workbuddy_home(home),
            directory=directory or SQLiteStore.default_path().parent / 'workbuddy-integrations', **kwargs)

    def event_names(self):
        return EVENTS

    def allowed_record_sets(self):
        return (set(EVENTS),)

    def finalize_config(self, value, action):
        if action == 'remove' and not value.get('hooks'):
            value.pop('hooks', None)
        return value

    def expected_hooks(self, runtime):
        args = [runtime['command'], *runtime['prefix'], 'workbuddy-hook']
        if os.name == 'nt':
            if any(any(c in v for c in '%!"\r\n') for v in args):
                raise ValueError('UNSAFE_LAUNCHER_PATH')
            command = ' '.join('"'+v+'"' for v in args)
        else:
            command = shlex.join(args)
        return {e: dict(matcher='.*', hooks=[dict(type='command', command=command, timeout=120)]) for e in EVENTS}

    def related_hook(self, group):
        return any('workbuddy-hook' in h.get('command', '') for h in group.get('hooks', []))

    def _load(self):
        path = self.home / 'settings.json'
        no_links(path)
        raw = path.read_bytes() if path.exists() else None
        if raw is not None and len(raw) > 262144:
            raise ValueError('CONFIG_INVALID')
        value = unique_json(raw) if raw is not None else {}
        if not isinstance(value, dict):
            raise ValueError('CONFIG_INVALID')
        value.setdefault('hooks', {})
        if not isinstance(value['hooks'], dict) or value.get('disableAllHooks') is True:
            raise ValueError('CONFIG_INVALID')
        for groups in value['hooks'].values():
            if not isinstance(groups, list):
                raise ValueError('CONFIG_INVALID')
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get('hooks'), list) or any(
                        not isinstance(h, dict) for h in group['hooks']):
                    raise ValueError('CONFIG_INVALID')
        return path, raw, value


class WorkBuddyConnectorInstallation(CursorConnectorInstallation):
    def __init__(self, *, skill=None, **kwargs):
        self.hooks = WorkBuddyHooks(**kwargs)
        self.home = self.hooks.home
        self.skill = skill or ReviewSkillManager(skills_dir=self.home / 'skills')

    def mcp(self, observer=None):
        runtime = self.hooks.discover()
        return OwnedJsonServer(self.home, self.hooks.store,
            dict(command=runtime['command'], args=[*runtime['prefix'], 'mcp'], disabled=False,
                 env={'SECURITY_RUNTIME_GLOBAL': '1', 'SECURITY_RUNTIME_HOST': 'workbuddy'}), observer=observer)

    def inspect_project(self, candidate):
        root = Path(candidate).resolve(strict=True)
        if not root.is_dir():
            raise ValueError('WORKSPACE_DIRECTORY_REQUIRED')
        rows = []
        for parent in (root, *root.parents):
            if parent == Path.home():
                break
            for directory in ('.workbuddy', '.workbuddy-ai', '.codebuddy'):
                for name in ('mcp.json', 'settings.json', 'settings.local.json'):
                    path = parent / directory / name
                    if path.parent == self.home:
                        continue
                    no_links(path)
                    if not path.exists():
                        continue
                    if path.stat().st_size > 262144:
                        raise ValueError('CONFIG_INVALID')
                    value = unique_json(path.read_bytes())
                    if not isinstance(value, dict):
                        raise ValueError('CONFIG_INVALID')
                    entries = value.get('mcpServers', {})
                    if not isinstance(entries, dict):
                        raise ValueError('CONFIG_INVALID')
                    found = any(related(n, e) for n, e in entries.items()) or 'workbuddy-hook' in str(value.get('hooks', {}))
                    rows.append(dict(path=str(path), related=found))
                source = parent / directory / 'skills' / 'ai-security-review'
                no_links(source)
                if source != self.skill.root and source.exists():
                    rows.append(dict(path=str(source), related=True))
        return rows

    def check_skill_sources(self, workspace=None):
        if workspace is not None and any(row['related'] for row in self.inspect_project(workspace)):
            raise ValueError('LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR')

    def preflight(self, workspace=None):
        self.hooks.execute('status')
        self.mcp().inspect()
        self.check_skill_sources(workspace)
        if self.skill.status()['status'] in {'USER_MANAGED', 'USER_MODIFIED', 'OWNERSHIP_CONFLICT'}:
            raise ValueError('SKILL_USER_CONTENT_PRESERVED')

    def configuration_status(self):
        report = self.hooks.execute('status')
        state, skill = self.mcp().status(), self.skill.status()
        ready = report['overall'] == state == 'CONFIGURED' and skill['status'] == 'INSTALLED'
        return {**report, 'overall': 'CONFIGURED' if ready else 'NOT_READY', 'mcp_status': state,
            'skill': skill, 'continuation_status': 'BOUNDED_STOP_FALLBACK',
            'fresh_host_trial': 'REQUIRES_ACTUAL_WORKBUDDY_DESKTOP',
            'supports_user_visible_feedback': True, 'supports_agent_continuation': True,
            'post_tool_use_mode': 'DEVELOPMENT_CONTEXT'}

    def execute(self, action, workspace=None):
        if action == 'status':
            return self.configuration_status()
        if action not in {'setup', 'repair', 'remove'}:
            raise ValueError('UNSUPPORTED_INTEGRATION')
        with self.hooks.store.lock(self.home / 'connector-transaction', wait_seconds=2) as locked:
            if not locked:
                raise ValueError('CONFIGURATION_BUSY')
            self.preflight(workspace)
            transaction = WriteTransaction()
            self.hooks.write_observer = self.skill.write_observer = transaction.observe
            try:
                if action != 'remove':
                    self.skill.execute('install')
                    if self.skill.status()['status'] != 'INSTALLED':
                        raise ValueError('SKILL_NOT_READY')
                self.hooks.execute(action)
                self.mcp(transaction.observe).execute(action)
                if action == 'remove':
                    self.skill.execute('remove')
            except Exception:
                if not transaction.rollback():
                    raise ValueError('WORKBUDDY_CONFIGURATION_RECOVERY_REQUIRED') from None
                raise
            finally:
                self.hooks.write_observer = self.skill.write_observer = None
        return dict(integration='workbuddy', scope='GLOBAL', overall='REMOVED') if action == 'remove' else self.configuration_status()


class WorkBuddyInstallPreflight(CursorInstallPreflight):
    host = 'workbuddy'


def setup_personal_workbuddy(integration, workspace=None, *, progress=None):
    from .personal_install import CONTRACT, _blocked
    try:
        data = integration.execute('setup', workspace)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        return _blocked(WorkBuddyInstallPreflight(integration), [str(exc) if str(exc).isupper() else 'WORKBUDDY_CONFIGURATION_CONFLICT'])
    ready = data['overall'] == 'CONFIGURED'
    data['installation'] = dict(contract=CONTRACT, status='INSTALLED' if ready else 'NOT_READY',
        local_files_ready=ready, scan_ready=False, restart_required=True,
        live_host_connection='NOT_VERIFIED_UNTIL_RECONNECT', risk_fix_authorized=False,
        message='WorkBuddy 全局 MCP、原生 Hook 与 Skill 已配置。重启客户端并审核连接信任后验证实际调用。')
    data['execution'] = dict(scanner_run=False, source_modified=False, network_query=False)
    return data
