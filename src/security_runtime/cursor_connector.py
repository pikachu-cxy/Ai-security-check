"""Cursor installation adapter: global MCP, command Hooks and shared review Skill."""
from __future__ import annotations

from .cursor_integration import GlobalCursorIntegration
from .owned_json import OwnedJsonServer, WriteTransaction, related
from .review_skill import ReviewSkillManager
from .codex_integration import unique_json
from .hook_state import no_links
from .cursor_permissions import CursorRoutinePermissions


def cursor_reason(exc):
    reason = str(exc)
    allowed = {'UNOWNED_RUNTIME_HOOK', 'UNOWNED_RUNTIME_MCP', 'DUPLICATE_REVIEW_SKILL',
        'SKILL_USER_CONTENT_PRESERVED', 'INSTALLED_RUNTIME_REQUIRED', 'CONFIG_INVALID',
        'OWNERSHIP_INVALID', 'CONFIGURATION_CHANGED', 'CONFIGURATION_BUSY',
        'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR', 'POTENTIAL_DUPLICATE_HOOK',
        'CURSOR_CONFIGURATION_RECOVERY_REQUIRED', 'CURSOR_PERMISSIONS_INVALID',
        'CURSOR_PERMISSION_OWNERSHIP_INVALID', 'CURSOR_PERMISSION_SOURCE_UNAVAILABLE'}
    return reason if reason in allowed else 'CURSOR_CONFIGURATION_OR_SKILL_CONFLICT'


class CursorConnectorInstallation:
    def __init__(self, *, skill=None, **kwargs):
        self.hooks = GlobalCursorIntegration(automatic=True, **kwargs)
        self.home = self.hooks.home
        self.skill = skill or ReviewSkillManager()

    def mcp(self, observer=None):
        runtime = self.hooks.discover()
        return OwnedJsonServer(self.home, self.hooks.store,
            dict(command=runtime['command'], args=[*runtime['prefix'], 'mcp'],
                 env={'SECURITY_RUNTIME_GLOBAL': '1', 'SECURITY_RUNTIME_HOST': 'cursor'}), observer=observer)

    def permissions(self, observer=None):
        return CursorRoutinePermissions(self.home, self.hooks.store, observer=observer)

    def inspect_project(self, candidate):
        from pathlib import Path
        candidate = Path(candidate).resolve(strict=True)
        if not candidate.is_dir():
            raise ValueError('WORKSPACE_DIRECTORY_REQUIRED')
        # Cursor reads the workspace config. Inspect ancestors as well so opening
        # a subfolder cannot evade a project-level duplicate installation.
        rows = []
        for root in (candidate, *candidate.parents):
            if root == Path.home():
                break  # User configuration is not a project configuration layer.
            for host_dir in ('.agents', '.cursor', '.codex'):
                source = root / host_dir / 'skills' / 'ai-security-review'
                no_links(source)
                if source != self.skill.root and source.exists() and (
                        not source.is_dir() or any(source.iterdir())):
                    rows.append(dict(path=str(source), related=True))
            for name in ('mcp.json', 'hooks.json'):
                config = root / '.cursor' / name
                if config.parent == self.home:
                    continue
                no_links(config)
                if not config.is_file():
                    continue
                if config.stat().st_size > 262144:
                    raise ValueError('CONFIG_INVALID')
                value = unique_json(config.read_bytes())
                if not isinstance(value, dict):
                    raise ValueError('CONFIG_INVALID')
                if name == 'mcp.json':
                    entries = value.get('mcpServers', {})
                    if not isinstance(entries, dict):
                        raise ValueError('CONFIG_INVALID')
                    found = any(related(n, e) for n, e in entries.items())
                else:
                    groups = value.get('hooks', {})
                    if not isinstance(groups, dict) or any(not isinstance(g, list) for g in groups.values()):
                        raise ValueError('CONFIG_INVALID')
                    found = any(isinstance(g, dict) and 'cursor-hook' in str(g.get('command', ''))
                                for entries in groups.values() for g in entries)
                rows.append(dict(path=str(config), related=found))
        return rows

    def preflight(self, workspace=None):
        self.hooks.execute('status')
        self.mcp().inspect()
        self.permissions().inspect()
        if workspace is not None and any(row['related'] for row in self.inspect_project(workspace)):
            raise ValueError('LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR')
        if self.skill.status()['status'] in {'USER_MANAGED', 'USER_MODIFIED', 'OWNERSHIP_CONFLICT'}:
            raise ValueError('SKILL_USER_CONTENT_PRESERVED')
        self.check_skill_sources(workspace)

    def check_skill_sources(self, workspace=None):
        from pathlib import Path
        # One shared user Skill is canonical. Do not delete or adopt duplicate
        # host/project guidance, even if its content happens to look identical.
        roots = [self.home.parent]
        if workspace is not None:
            roots.append(Path(workspace).resolve(strict=True))
        sources = [self.home / 'skills' / 'ai-security-review']
        sources += [root / host_dir / 'skills' / 'ai-security-review'
                    for root in roots for host_dir in ('.agents', '.cursor', '.codex')]
        for directory in sources:
            if directory == self.skill.root:
                continue
            no_links(directory)
            if directory.exists() and (not directory.is_dir() or any(directory.iterdir())):
                raise ValueError('DUPLICATE_REVIEW_SKILL')

    def configuration_status(self):
        self.check_skill_sources()
        report = self.hooks.execute('status')
        state = self.mcp().status()
        ready = report['overall'] == state == 'CONFIGURED' and self.skill.status()['status'] == 'INSTALLED'
        return {**report, 'overall': 'CONFIGURED' if ready else 'NOT_READY', 'mcp_status': state,
            'connector_mode': 'AUTOMATIC_LOCAL_BETA', 'post_tool_use_mode': 'TASK_CONTEXT',
            'supports_user_visible_feedback': True, 'supports_agent_continuation': True,
            'continuation_status': 'BOUNDED_STOP_FALLBACK', 'feedback_status': 'POST_TOOL_CONTEXT',
            'routine_tool_approval': self.permissions().status(),
            'skill': self.skill.status()}

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
            self.hooks.write_observer = transaction.observe
            self.skill.write_observer = transaction.observe
            try:
                if action != 'remove':
                    self.skill.execute('install')
                    if self.skill.status()['status'] != 'INSTALLED':
                        raise ValueError('SKILL_NOT_READY')
                self.hooks.execute(action)
                self.mcp(transaction.observe).execute(action)
                self.permissions(transaction.observe).execute(action)
            except Exception:
                if not transaction.rollback():
                    raise ValueError('CURSOR_CONFIGURATION_RECOVERY_REQUIRED') from None
                raise
            finally:
                self.hooks.write_observer = None
                self.skill.write_observer = None
        if action == 'remove':
            return dict(integration='cursor', scope='GLOBAL', overall='REMOVED', shared_skill='PRESERVED')
        return self.configuration_status()


class CursorInstallPreflight:
    """Common delivery pipeline's conflict-only preflight; no configuration writes."""
    host = 'cursor'

    def __init__(self, integration):
        self.integration, self.skill = integration, integration.skill

    def plan(self, workspace=None):
        try:
            self.integration.preflight(workspace)
            return dict(blocked=[], steps=[])
        except (ValueError, OSError, KeyError, TypeError) as exc:
            return dict(blocked=[cursor_reason(exc)], steps=[])


def setup_personal_cursor(integration, workspace=None, *, progress=None):
    from .personal_install import CONTRACT, _blocked
    from .install_progress import report_progress
    report_progress(progress, 'CHECK_CONFIG')
    try:
        report_progress(progress, 'APPLY_CONFIG')
        data = integration.execute('setup', workspace)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        if str(exc) == 'CURSOR_CONFIGURATION_RECOVERY_REQUIRED':
            return _blocked(CursorInstallPreflight(integration), [str(exc)], status='RECOVERY_REQUIRED')
        return _blocked(CursorInstallPreflight(integration), [cursor_reason(exc)])
    report_progress(progress, 'SELF_CHECK')
    ready = data['overall'] == 'CONFIGURED'
    data['installation'] = dict(contract=CONTRACT, status='INSTALLED' if ready else 'NOT_READY',
        local_files_ready=ready, scan_ready=False, restart_required=True,
        live_host_connection='NOT_VERIFIED_UNTIL_RECONNECT', risk_fix_authorized=False,
        message='Cursor 全局连接、自动 Hook、公共 Skill 和常规检查免确认白名单已安装。'
            '请重启 Cursor 或重新加载连接；免确认仍受 Cursor 运行模式及团队策略约束，修复不在本产品预批准范围内。'
            if ready else 'Cursor 配置尚未就绪，请查看连接状态。')
    data['execution'] = dict(scanner_run=False, source_modified=False, network_query=False)
    return data
