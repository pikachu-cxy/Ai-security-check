"""User-level WorkBuddy MCP and Hooks, preserving unrelated configuration."""
from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

from .codex_integration import unique_json
from .global_integration import installed_runtime
from .hook_state import HookStateStore, atomic_bytes, native_io_path, no_links
from .owned_json import OwnedJsonServer, WriteTransaction, related
from .review_skill import ReviewSkillManager
from .storage import SQLiteStore
from .tasks.durable import SignedRecords


def hook_command(runtime, *, windows=None):
    args = [runtime['command'], *runtime['prefix'], 'workbuddy-hook']
    is_windows = os.name == 'nt' if windows is None else windows
    if is_windows:
        if any(any(c in arg for c in '%!"\r\n') for arg in args):
            raise ValueError('UNSAFE_LAUNCHER_PATH')
        return ' '.join('"'+arg+'"' for arg in args)
    return shlex.join(args)


def workbuddy_config_dir(home=None):
    if home:
        return Path(home).absolute()
    for name in ('WORKBUDDY_CONFIG_DIR', 'CODEBUDDY_CONFIG_DIR'):
        configured = os.getenv(name, '').strip()
        if configured:
            return Path(configured).absolute()
    desktop = Path.home()/'.workbuddy-ai'
    return desktop if native_io_path(desktop).is_dir() else Path.home()/'.workbuddy'


class WorkBuddyConnectorInstallation:
    def __init__(self, *, home=None, directory=None, discover=None):
        self.home = workbuddy_config_dir(home)
        no_links(self.home)
        self.store = HookStateStore(directory or SQLiteStore.default_path().parent/'workbuddy-integrations')
        self.discover = discover or installed_runtime
        self.skill = ReviewSkillManager(skills_dir=self.home/'skills')

    def mcp(self, observer=None):
        runtime = self.discover()
        return OwnedJsonServer(self.home, self.store, dict(command=runtime['command'],
            args=[*runtime['prefix'], 'mcp'], env={'SECURITY_RUNTIME_GLOBAL': '1',
                'SECURITY_RUNTIME_HOST': 'workbuddy'}), observer=observer)

    def hooks(self, action='status', observer=None):
        from .workbuddy_hook import EVENTS
        path = self.home/'settings.json'
        no_links(path)
        io = native_io_path(path)
        raw = io.read_bytes() if io.exists() else None
        if raw is not None and len(raw) > 262144:
            raise ValueError('CONFIG_INVALID')
        value = unique_json(raw) if raw else {}
        if not isinstance(value, dict) or not isinstance(value.get('hooks', {}), dict):
            raise ValueError('CONFIG_INVALID')
        groups = value.get('hooks', {})
        if any(not isinstance(v, list) or any(not isinstance(g, dict) or
                not isinstance(g.get('hooks'), list) for g in v) for v in groups.values()):
            raise ValueError('CONFIG_INVALID')
        ledger = SignedRecords(self.store, self.home, 'workbuddy-hooks.db') if native_io_path(self.home).exists() else None
        record = ledger.read('installed') if ledger else None
        old = record.get('groups', {}) if record else {}
        expected = {e: [{'hooks': [{'type': 'command', 'command': hook_command(self.discover()),
                                   'timeout': 120}]}] for e in EVENTS}
        for event, entries in groups.items():
            for group in entries:
                if any('workbuddy-hook' in h.get('command', '') for h in group['hooks']):
                    if group not in old.get(event, []):
                        raise ValueError('UNOWNED_RUNTIME_HOOK')
        ready = all(groups.get(e, []).count(g) == 1 for e in expected for g in expected[e]) and old == expected
        if action == 'status':
            return 'CONFIGURED' if ready else 'NEEDS_REPAIR'
        merged = json.loads(json.dumps(value))
        hooks = merged.setdefault('hooks', {})
        for e, entries in old.items():
            hooks[e] = [g for g in hooks.get(e, []) if g not in entries]
        for e, entries in expected.items():
            hooks.setdefault(e, []).extend(entries)
        desired = (json.dumps(merged, ensure_ascii=True, indent=2)+'\n').encode()
        if (io.read_bytes() if io.exists() else None) != raw:
            raise ValueError('CONFIGURATION_CHANGED')
        if raw != desired:
            if observer:
                observer(path, desired)
            atomic_bytes(path, desired)
        ledger = SignedRecords(self.store, self.home, 'workbuddy-hooks.db')
        self.store.key(self.home)
        with ledger.transaction() as db:
            ledger._put(db, 'installed', dict(groups=expected))
        return 'CONFIGURED'

    def inspect_project(self, root):
        rows = []
        for parent in (Path(root), *Path(root).parents):
            path = parent/'.workbuddy/mcp.json'
            if path.parent == self.home:
                continue
            no_links(path)
            io = native_io_path(path)
            if io.is_file():
                if io.stat().st_size > 262144:
                    raise ValueError('CONFIG_INVALID')
                entries = unique_json(io.read_bytes()).get('mcpServers', {})
                rows.append(dict(path=str(path), related=any(related(n, e) for n, e in entries.items())))
        return rows

    def configuration_status(self):
        ready = self.mcp().status() == 'CONFIGURED' and self.hooks() == 'CONFIGURED'
        return dict(integration='workbuddy', scope='GLOBAL', overall='CONFIGURED' if ready else 'NEEDS_REPAIR',
                    fresh_host_trial='PENDING_ACTUAL_DESKTOP')

    def setup(self):
        # Preflight before writing, then reuse the common rollback and Skill installer.
        self.mcp().inspect()
        self.hooks()
        if self.skill.status()['status'] in {'USER_MANAGED', 'USER_MODIFIED', 'OWNERSHIP_CONFLICT'}:
            raise ValueError('SKILL_USER_CONTENT_PRESERVED')
        transaction = WriteTransaction()
        with self.store.lock(self.home, wait_seconds=2) as locked:
            if not locked:
                raise ValueError('CONFIGURATION_BUSY')
            try:
                self.mcp(transaction.observe).execute('setup')
                self.skill.write_observer = transaction.observe
                self.skill.execute('upgrade' if self.skill.status()['status'] == 'INSTALLED' else 'install')
                self.hooks('setup', transaction.observe)
            except Exception:
                transaction.rollback()
                raise
            finally:
                self.skill.write_observer = None
        return {**self.configuration_status(), 'restart_required': True}


class WorkBuddyInstallPreflight:
    host = 'workbuddy'

    def __init__(self, integration):
        self.integration, self.skill = integration, integration.skill

    def plan(self, workspace=None):
        try:
            self.integration.mcp().inspect()
            self.integration.hooks()
            if workspace is not None and any(row['related'] for row in self.integration.inspect_project(workspace)):
                raise ValueError('LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR')
            if self.skill.status()['status'] in {'USER_MANAGED', 'USER_MODIFIED', 'OWNERSHIP_CONFLICT'}:
                raise ValueError('SKILL_USER_CONTENT_PRESERVED')
            return dict(blocked=[], steps=[])
        except (ValueError, OSError, KeyError, TypeError) as exc:
            from .cursor_connector import cursor_reason
            return dict(blocked=[cursor_reason(exc)], steps=[])


def setup_personal_workbuddy(integration, workspace=None, *, progress=None):
    from .personal_install import CONTRACT, _blocked
    manager = WorkBuddyInstallPreflight(integration)
    plan = manager.plan(workspace)
    if plan['blocked']:
        return _blocked(manager, plan['blocked'])
    try:
        data = integration.setup()
    except (ValueError, OSError, KeyError, TypeError):
        return _blocked(manager, ['WORKBUDDY_CONFIGURATION_FAILED'])
    data['skill'] = integration.skill.status()
    ready = data['overall'] == 'CONFIGURED' and data['skill']['status'] == 'INSTALLED'
    data['installation'] = dict(contract=CONTRACT, status='INSTALLED' if ready else 'NOT_READY',
        local_files_ready=ready, scan_ready=False, restart_required=True,
        live_host_connection='NOT_VERIFIED_UNTIL_RECONNECT', risk_fix_authorized=False,
        message='WorkBuddy 全局连接、Hook 和 Skill 已安装；请重启并审核连接信任。'
            if ready else 'WorkBuddy 配置尚未就绪。')
    return data
