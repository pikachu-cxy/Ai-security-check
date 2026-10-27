"""Owned user-level Codex installation. No Codex trust-store access."""
from __future__ import annotations

import json
import os
import sys
import tomllib
from pathlib import Path, PureWindowsPath

from .codex_integration import (CodexIntegrationAdapter, SERVER,
    current_runtime, fingerprint, product_hooks, unique_json, CONTRACT)
from ._version import __version__
from .global_toml import patch_server
from .hook_state import identity, no_links
from .integration_lifecycle import IntegrationDiagnostic
from .storage import SQLiteStore

GLOBAL = 'RUNTIME_MANAGED_GLOBAL'
LEGACY = 'RUNTIME_MANAGED_LEGACY_PROJECT'
OWNERSHIP_VERSION = 'codex-global-ownership-v0.2'


def runtime_aliases(document):
    """Relatedness only, never ownership. Renamed launchers need user review."""
    aliases = {SERVER}
    for name, entry in document.get('mcp_servers', {}).items():
        command = entry.get('command', '')
        args = entry.get('args', [])
        if not isinstance(command, str) or not isinstance(args, list):
            continue
        if (PureWindowsPath(command).name.lower() in {'security-check', 'security-check.exe'}
            or ('security_runtime.cli' in args and 'mcp' in args)):
            aliases.add(name)
    return aliases


def codex_home(value=None):
    raw = str(value if value is not None else os.getenv('CODEX_HOME', Path.home() / '.codex'))
    if not raw or len(raw) > 4096 or '${' in raw or any(ord(c) < 32 for c in raw):
        raise IntegrationDiagnostic('CODEX_HOME_INVALID')
    path = Path(raw).absolute()
    if not Path(raw).is_absolute() or raw.startswith(('\\\\', '//')) or path == Path(path.anchor) or path == Path.home():
        raise IntegrationDiagnostic('CODEX_HOME_INVALID')
    no_links(path)
    return path


def installed_runtime():
    runtime = current_runtime()
    if not getattr(sys, 'frozen', False):
        source = Path(__file__).resolve()
        # An editable checkout is not a stable installed delivery. Do not put a
        # source path/PYTHONPATH in a user's permanent config to make it work.
        if (source.parents[2] / 'pyproject.toml').is_file():
            runtime['kind'] = 'DEV'
    return runtime


class _DeferredBaselines:
    @staticmethod
    def ensure(*args, **kwargs):
        # Internal installer compatibility only; status() exposes DEFERRED,
        # never workspace READY. Installation does not scan current sources.
        return {'status': 'READY', 'scope': 'INSTALLATION_ONLY'}

    @staticmethod
    def remove(*args):
        pass


class GlobalCodexIntegration(CodexIntegrationAdapter):
    """Reuse exact ownership/CAS merge. Destination is an explicit Codex home."""
    manifest_versions = CodexIntegrationAdapter.manifest_versions | {OWNERSHIP_VERSION}
    def __init__(self, *, home=None, directory=None, discover=None, probe=None,
                 legacy_adapter=None, allow_dev=False):
        self.home = codex_home(home)
        self.allow_dev = allow_dev
        super().__init__(directory=directory or SQLiteStore.default_path().parent / 'global-codex-integrations',
                         discover=discover or installed_runtime, probe=probe)
        self.baselines = _DeferredBaselines()
        self.legacy_adapter = legacy_adapter or CodexIntegrationAdapter()

    def _config_paths(self, root):
        return root / 'config.toml', root / 'hooks.json'

    def _legacy(self, root, hooks):
        return {}

    def _manifest(self, root):
        manifest = super()._manifest(root)
        if manifest is not None:
            if manifest.get('scope', 'GLOBAL') != 'GLOBAL':
                raise IntegrationDiagnostic('OWNERSHIP_INVALID')
            if manifest['managed_version'] == OWNERSHIP_VERSION and (
                    manifest.get('scope') != 'GLOBAL' or manifest.get('ownership_model') != 2
                    or not isinstance(manifest.get('runtime_version'), str)
                    or not isinstance(manifest.get('capability_contract'), str)):
                raise IntegrationDiagnostic('OWNERSHIP_INVALID')
        return manifest

    def _new_manifest(self, root, record):
        from .build_identity import build_identity
        return {**super()._new_manifest(root, record), 'managed_version': OWNERSHIP_VERSION,
                'scope': 'GLOBAL', 'ownership_model': 2, 'runtime_version': __version__,
                'capability_contract': CONTRACT, 'build_id': build_identity().get('build_id')}

    def _config(self, root, manifest=None):
        # Shared user/Host document: comments never establish Global ownership.
        # Parse the entire document strictly, including duplicate-key rejection.
        a_path, b_path = self._config_paths(root)
        a, b = self._read(a_path), self._read(b_path)
        try:
            document = tomllib.loads(a.decode('utf-8')) if a else {}
            hooks = unique_json(b) if b else {'hooks': {}}
            if (not isinstance(document.get('mcp_servers', {}), dict)
                    or not isinstance(document.get('features', {}), dict)):
                raise ValueError()
            if any(not isinstance(s, dict) for s in document.get('mcp_servers', {}).values()):
                raise ValueError()
            self._validate_hooks(hooks)
            self._inline_hooks(document)
            return (a_path, a, document), (b_path, b, hooks)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise IntegrationDiagnostic('CONFIG_INVALID') from None

    def _inspect_mcp(self, root, raw, document, manifest, server):
        current = document.get('mcp_servers', {}).get(SERVER)
        diagnostics = []
        if current is None:
            return ['MCP_NOT_CONFIGURED'], []
        try:
            attested = manifest is not None and fingerprint(current) in {r['server'] for r in manifest['records']}
        except (ValueError, TypeError):
            attested = False
        if not attested:
            raise IntegrationDiagnostic('MCP_CONFIGURATION_CONFLICT')
        if current != server or (manifest.get('runtime_version', __version__) != __version__
                or manifest.get('capability_contract', CONTRACT) != CONTRACT):
            diagnostics.append('RUNTIME_STALE')
        from .build_identity import build_identity
        build = build_identity()
        # A previously enrolled source checkout changes identity on every edit.
        # Keep the signed server/path, version, contract and Hook checks; only
        # source-content drift is expected in this explicit development mode.
        # Frozen deliveries and unverifiable identities still require an exact
        # build match. Reading status never grants a new development install.
        development_source = (self.discover().get('kind') == 'DEV'
            and build.get('status') == 'DEV' and manifest.get('phase') == 'COMMITTED'
            and current == server)
        if (not development_source and manifest.get('build_id') != build.get('build_id')
                and 'RUNTIME_STALE' not in diagnostics):
            diagnostics.append('RUNTIME_STALE')
        if manifest['managed_version'] != OWNERSHIP_VERSION:
            diagnostics.append('MANAGED_FORMAT_UPGRADE_REQUIRED')
        # A semantic ownership receipt, not a byte span or marker match.
        return diagnostics, [current]

    def _patch_mcp(self, raw, document, owned, block, server, action):
        return patch_server(raw, block, remove=action == 'remove')

    def _desired(self, root, *, verify_existing=False):
        runtime = self.discover()
        if runtime['kind'] == 'DEV' and not self.allow_dev and not verify_existing:
            raise IntegrationDiagnostic('INSTALLED_RUNTIME_REQUIRED')
        directory = SQLiteStore.default_path().parent.absolute()
        no_links(directory)
        if directory.is_relative_to(root):
            raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH')
        env = {'SECURITY_RUNTIME_GLOBAL': '1', 'SECURITY_RUNTIME_WORKSPACE': '',
               'SECURITY_RUNTIME_INTEGRATION': 'codex',
               'SECURITY_RUNTIME_CODEX_HOME': str(root),
               'SECURITY_RUNTIME_STATE_DIR': str(directory)}
        server = {'command': runtime['command'], 'args': [*runtime['prefix'], 'mcp'],
                  'enabled': True, 'required': True, 'startup_timeout_sec': 60,
                  'tool_timeout_sec': 600, 'env': env}
        q = lambda s: json.dumps(s, ensure_ascii=True)
        lines = [f'[mcp_servers.{SERVER}]', 'command = ' + q(server['command']),
                 'args = ' + q(server['args']), 'enabled = true', 'required = true',
                 'startup_timeout_sec = 60', 'tool_timeout_sec = 600', f'[mcp_servers.{SERVER}.env]']
        lines.extend(k + ' = ' + q(v) for k, v in env.items())
        block = ('\n'.join(lines) + '\n').encode()
        hooks = product_hooks()
        record = {'block': identity(block.decode()), 'server': fingerprint(server),
                  'hooks': {e: fingerprint(g[0]) for e, g in hooks['hooks'].items()}}
        return runtime, env, server, block, hooks, record

    def _inspection(self, root, configs, manifest, desired):
        diagnostics, owned, legacy = super()._inspection(root, configs, manifest, desired)
        diagnostics = [d for d in diagnostics if d != 'WORKSPACE_BINDING_MISMATCH']
        current = configs[0][2].get('mcp_servers', {}).get(SERVER)
        if current is not None and current != desired[2] and not any(d in diagnostics for d in ('RUNTIME_STALE', 'RUNTIME_MISSING')):
            diagnostics.append('RUNTIME_STALE')
        if runtime_aliases(configs[0][2]) - {SERVER}:
            diagnostics.append('POTENTIAL_DUPLICATE_MCP')
        for hooks in (configs[1][2]['hooks'], self._inline_hooks(configs[0][2])):
            if any(h.get('type') == 'mcp_tool' and h.get('server') != SERVER
                   and h.get('tool') in {'handle_before_hook_event', 'handle_hook_event', 'handle_readiness_event', 'handle_stop_event'}
                   for groups in hooks.values() for group in groups for h in group['hooks']):
                diagnostics.append('POTENTIAL_DUPLICATE_HOOK')
        return diagnostics, owned, legacy

    def configuration_status(self):
        manifest = self._manifest(self.home)
        configs = self._config(self.home, manifest)
        # A signed existing configuration may have been explicitly enrolled
        # with allow_dev. Read-only fingerprint verification is not a new
        # installation. Mutations still call _desired without this exception.
        desired = self._desired(self.home, verify_existing=bool(manifest and manifest['phase'] == 'COMMITTED'))
        diagnostics, owned, _ = self._inspection(self.home, configs, manifest, desired)
        absent = not manifest and configs[0][2].get('mcp_servers', {}).get(SERVER) is None
        if manifest and manifest['phase'] != 'COMMITTED':
            diagnostics.append('CONFIG_UPDATE_INCOMPLETE')
        return {'integration': 'codex', 'scope': 'GLOBAL',
                'ownership': GLOBAL if manifest else ('USER_MANAGED' if configs[0][2] or configs[1][2]['hooks'] else 'UNKNOWN'),
                'overall': 'NOT_INSTALLED' if absent else 'DEGRADED' if diagnostics else 'CONFIGURED',
                'mcp': {'status': 'CONFIGURED' if owned else 'MCP_NOT_CONFIGURED',
                        'ownership_state': ('OWNED_BUT_STALE' if 'RUNTIME_STALE' in diagnostics else 'OWNED_AND_CURRENT')
                            if owned else 'NOT_INSTALLED'},
                'pre_tool_hook': {'status': self._hook_status('PreToolUse', configs[1][2], desired[4], manifest)},
                'post_tool_hook': {'status': self._hook_status('PostToolUse', configs[1][2], desired[4], manifest)},
                'stop_hook': {'status': self._hook_status('Stop', configs[1][2], desired[4], manifest)},
                'readiness': {'status': 'AWAITING_SESSION_CONNECTION',
                              'hook_status': self._hook_status('SessionStart', configs[1][2], desired[4], manifest)},
                'baseline': {'status': 'NOT_REQUIRED', 'required': False,
                             'message': '当前任务审计模式不要求产品启动比较基线。'},
                'hook_definition_hash': fingerprint(product_hooks()),
                'hook_trust': 'HOST_MANAGED_UNKNOWN', 'live_connection': 'UNKNOWN',
                'cold_start_host_trial': 'PENDING_ACTUAL_DESKTOP',
                'diagnostics': diagnostics}

    def status(self, root=None):
        result = self.configuration_status()
        manifest = self._manifest(self.home)
        runtime, env, *_ = self._desired(self.home, verify_existing=bool(manifest and manifest['phase'] == 'COMMITTED'))
        try:
            capability = self.probe(runtime, self.home, {**os.environ, **env, 'SECURITY_RUNTIME_MCP_SELF_TEST': '1'})
        except IntegrationDiagnostic as exc:
            # A failed live probe must not erase valid ownership/configuration
            # diagnostics; configured and connected are independent observations.
            capability = {'status': exc.code, 'mode': 'UNKNOWN'}
            result['diagnostics'] = list(dict.fromkeys([*result['diagnostics'], exc.code]))
            result['overall'] = 'DEGRADED'
        result.update(runtime={**capability, 'kind': runtime['kind']}, mode=capability['mode'])
        return result

    def project_layers(self, candidate):
        from .global_workspace import resolve_workspace
        root = resolve_workspace(candidate, excluded=(self.store.directory,),
                                 codex_homes=(self.home,))
        cwd = Path(candidate).absolute().resolve()
        return [root, *reversed([p for p in (cwd, *cwd.parents) if p != root and p.is_relative_to(root)])]

    def inspect_project(self, candidate):
        """Only active layers. No search of other projects or whole home."""
        rows = []
        for layer in self.project_layers(candidate):
            adapter = self.legacy_adapter
            manifest = adapter._manifest(layer)
            configs = adapter._config(layer, manifest)
            document, hooks = configs[0][2], configs[1][2]
            current = document.get('mcp_servers', {}).get(SERVER)
            if runtime_aliases(document) - {SERVER}:
                raise IntegrationDiagnostic('POTENTIAL_DUPLICATE_MCP')
            if any(h.get('type') == 'mcp_tool' and h.get('server') != SERVER
                   and h.get('tool') in {'handle_before_hook_event', 'handle_hook_event', 'handle_readiness_event', 'handle_stop_event'}
                   for source in (hooks['hooks'], adapter._inline_hooks(document))
                   for groups in source.values() for group in groups for h in group['hooks']):
                raise IntegrationDiagnostic('POTENTIAL_DUPLICATE_HOOK')
            related = any(adapter._related(e, g) for e, gs in hooks['hooks'].items() for g in gs)
            related |= any(adapter._related(e, g) for e, gs in adapter._inline_hooks(document).items() for g in gs)
            legacy = adapter._legacy(layer, hooks)
            if current is None and not related and not manifest and not legacy:
                if document or hooks['hooks']:
                    rows.append({'layer': layer, 'ownership': 'USER_MANAGED', 'related': False})
                continue
            # Inspection proves all related handlers are owned, including mixed
            # groups. Do not delete merely because a server name matches.
            desired = adapter._desired(layer)
            diagnostics, _, _ = adapter._inspection(layer, configs, manifest, desired)
            if 'POTENTIAL_DUPLICATE_HOOK' in diagnostics:
                raise IntegrationDiagnostic('POTENTIAL_DUPLICATE_HOOK')
            rows.append({'layer': layer, 'ownership': LEGACY if manifest or legacy else 'UNKNOWN', 'related': True})
        return rows

    def execute(self, action, workspace=None):
        if action not in {'setup', 'status', 'doctor', 'repair', 'uninstall'}:
            raise IntegrationDiagnostic('UNSUPPORTED_GLOBAL_ACTION')
        rows = self.inspect_project(workspace) if workspace is not None and action != 'uninstall' else []
        if action in {'setup', 'repair'}:
            # Complete preflight before either location is changed. Unknown
            # entries were rejected by the shared ownership inspection.
            preflight = self.configuration_status()
            if 'POTENTIAL_DUPLICATE_MCP' in preflight['diagnostics']:
                raise IntegrationDiagnostic('POTENTIAL_DUPLICATE_MCP')
            no_links(self.home)
            self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
            result = self._mutate(self.home, action)
            for row in rows:
                if row['ownership'] == LEGACY:
                    self.legacy_adapter.remove(row['layer'])
            result['migration'] = {'status': 'MIGRATED' if any(r['ownership'] == LEGACY for r in rows) else 'NONE',
                                   'removed_layers': sum(r['ownership'] == LEGACY for r in rows)}
            result['baseline'] = {'status': 'NOT_REQUIRED', 'required': False,
                                  'message': '当前任务审计模式不要求产品启动比较基线。'}
        elif action == 'uninstall':
            result = self._mutate(self.home, 'remove')
            result.update(scope='GLOBAL', ownership=GLOBAL)
        else:
            result = self.status()
        result['project_ownership'] = [{k: v for k, v in r.items() if k != 'layer'} for r in rows]
        result['workspace_readiness'] = {'status': 'NOT_OBSERVED'}
        if workspace is not None:
            from .global_workspace import read_bootstrap
            from .global_workspace import resolve_workspace
            root = resolve_workspace(workspace, excluded=(self.store.directory,),
                                     codex_homes=(self.home,))
            result['workspace_readiness'] = read_bootstrap(root)
            if any(r['related'] for r in rows) and action not in {'setup', 'repair'}:
                result['diagnostics'] = [*result.get('diagnostics', []), 'LEGACY_PROJECT_CONFIGURATION_PRESENT']
                result['overall'] = 'DEGRADED'
        return result


def render_global(value):
    lines = ['AI Security Runtime — Global Codex',
             'Global Runtime: ' + value.get('runtime', {}).get('status', value.get('overall', 'UNKNOWN')),
             'Global MCP: ' + value.get('mcp', {}).get('status', 'UNKNOWN'),
             'Global Hook: ' + value.get('post_tool_hook', {}).get('status', 'UNKNOWN'),
             'Hook trust: ' + value.get('hook_trust', 'HOST_MANAGED_UNKNOWN'),
             'Workspace: ' + value.get('workspace_readiness', {}).get('status', 'NOT_OBSERVED')]
    lines.extend(value.get('diagnostics', []))
    if value.get('skill'):
        lines.append('专业 Skill：' + value['skill'].get('status', 'UNKNOWN'))
    if value.get('installation'):
        lines.append(value['installation']['message'])
    recovery = value.get('configuration_recovery')
    if recovery:
        lines.append(recovery['message'])
        for row in recovery['issues']:
            lines.extend('配置位置：' + path for path in row['affected_paths'])
            lines.extend(row['explanations'])
        lines.extend(recovery['blocker_explanations'])
        if recovery.get('question'):
            lines.append(recovery['question'])
        if recovery.get('repair_command'):
            lines.append('确认后执行：' + recovery['repair_command'])
        if recovery.get('recovery_argv'):
            from .integration_recovery import display_command
            lines.append('确认后恢复：' + display_command(recovery['recovery_argv']))
    if value.get('recovery_record'):
        lines.append('配置已备份，恢复记录：' + value['recovery_record'])
    if value.get('reconnect_required'):
        lines.append('请重启 Codex 或重新连接安全工具，再继续扫描。无需在每个项目安装。')
    if value.get('operation') in {'CONFIGURED', 'REPAIRED'}:
        lines.append('Restart Codex, review the user-level Hook in /hooks, then open a project. READY is not a safety verdict.')
    return '\n'.join(lines)
