"""Bounded, explicit installation migration. Diagnosis and planning are read-only.

The private signed journal contains local configuration recovery bytes, never
source, scanner state, Host trust or repair/triage capabilities.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from .codex_integration import SERVER, fingerprint
from .global_integration import GlobalCodexIntegration, LEGACY, runtime_aliases
from .global_toml import patch_server
from .hook_state import HookStateStore, atomic_bytes, no_links
from .integration_lifecycle import IntegrationDiagnostic
from .review_skill import ReviewSkillManager
from .storage import SQLiteStore

CONTRACT = 'installation-upgrade-v1'
TTL = 900
MAX_JOURNAL = 8_000_000


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def read(path):
    no_links(path)
    if not path.exists():
        return None
    if not path.is_file() or path.stat().st_size > 262_144:
        raise IntegrationDiagnostic('UPGRADE_FILE_INVALID')
    with path.open('rb') as stream:
        raw = stream.read(262_145)
    if len(raw) > 262_144:
        raise IntegrationDiagnostic('UPGRADE_FILE_INVALID')
    return raw


def revision(raw):
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def reason(exc):
    code = getattr(exc, 'code', None)
    return code if code else 'STATE_PERMISSION_DENIED' if isinstance(exc, PermissionError) else 'PATH_OR_STATE_INVALID'


class InstallationUpgrade:
    def __init__(self, integration=None, skill=None, *, now=None, manage_skill=True):
        self.integration = integration or GlobalCodexIntegration()
        self.skill = skill or ReviewSkillManager()
        self.manage_skill = manage_skill
        self.now = now or time.time
        self.locks = HookStateStore(SQLiteStore.default_path().parent / 'installation-upgrades')
        self.directory = self.locks.workspace_directory(self.integration.home)

    def layers(self, workspace=None):
        rows = []
        candidates = [('GLOBAL', self.integration.home, self.integration)]
        if workspace is not None:
            candidates += [('PROJECT', p, self.integration.legacy_adapter)
                           for p in self.integration.project_layers(workspace)]
        for scope, root, adapter in candidates:
            row = {'scope': scope, 'layer': str(root), 'ownership': 'UNKNOWN', 'diagnostics': []}
            try:
                manifest = adapter._manifest(root)
                configs = adapter._config(root, manifest)
                document, hooks = configs[0][2], configs[1][2]
                server = document.get('mcp_servers', {}).get(SERVER)
                row['config_path'] = str(configs[0][0])
                row['hooks_path'] = str(configs[1][0])
                row['server_present'] = server is not None
                row['server_fingerprint'] = fingerprint(server) if server is not None else None
                row['config_fingerprint'] = revision(configs[0][1])
                related_hooks = any(adapter._related(e, g) for source in
                    (hooks['hooks'], adapter._inline_hooks(document)) for e, gs in source.items() for g in gs)
                row['related_hooks'] = related_hooks
                if runtime_aliases(document) - {SERVER}:
                    raise IntegrationDiagnostic('POTENTIAL_DUPLICATE_MCP')
                if manifest:
                    desired = adapter._desired(root, verify_existing=True) if scope == 'GLOBAL' else adapter._desired(root)
                    diagnostics, _, _ = adapter._inspection(root, configs, manifest, desired)
                    row.update(ownership='RUNTIME_MANAGED_GLOBAL' if scope == 'GLOBAL' else LEGACY,
                               diagnostics=diagnostics, action='REPAIR' if scope == 'GLOBAL' else 'MIGRATE_OWNED')
                elif server is not None:
                    row.update(ownership='USER_MANAGED', diagnostics=['MCP_CONFIGURATION_CONFLICT'],
                               action='USER_REVIEW_REQUIRED' if related_hooks else 'REMOVE_SERVER_WITH_EXPLICIT_APPROVAL')
                elif related_hooks:
                    row.update(diagnostics=['POTENTIAL_DUPLICATE_HOOK'], action='USER_REVIEW_REQUIRED')
                else:
                    row.update(ownership='USER_MANAGED' if document or hooks['hooks'] else 'NOT_INSTALLED',
                               action='INSTALL' if scope == 'GLOBAL' else 'PRESERVE')
            except (ValueError, OSError, TypeError, RecursionError) as exc:
                row.update(diagnostics=[reason(exc)], action='USER_REVIEW_REQUIRED')
            rows.append(row)
        return rows

    def diagnose(self, workspace=None, *, probe=False):
        from .host_guidance import runtime_info
        from .global_workspace import read_bootstrap
        layers = self.layers(workspace)
        try:
            runtime = self.integration.discover()
            launcher = {'kind': runtime['kind'], 'path': runtime['command'],
                        'diagnostic': 'DEV_LAUNCHER_REQUIRES_EXPLICIT_OPT_IN' if runtime['kind'] == 'DEV' else 'LAUNCHER_PRESENT'}
        except (ValueError, OSError) as exc:
            launcher = {'diagnostic': reason(exc)}
        result = {'contract': CONTRACT, 'status': 'DIAGNOSED', 'layers': layers,
                  'launcher': launcher, 'build': runtime_info()['build_identity'],
                  'skill': self.skill.status(), 'live_connection': 'UNKNOWN_RECONNECT_AFTER_UPDATE',
                  'capabilities': 'NOT_PROBED_READ_ONLY', 'engines': 'NOT_PROBED_READ_ONLY',
                  'execution': {'scanner_run': False, 'configuration_modified': False, 'unknown_command_run': False}}
        if workspace is not None:
            result['bootstrap'] = read_bootstrap(self.integration.project_layers(workspace)[0])
        if probe:
            # Only the current/verified product executable, never the command
            # obtained from an unknown project or global MCP definition.
            try:
                runtime, env, *_ = self.integration._desired(self.integration.home, verify_existing=True)
                result['capabilities'] = self.integration.probe(runtime, self.integration.home,
                    {**os.environ, **env, 'SECURITY_RUNTIME_MCP_SELF_TEST': '1'})
            except (ValueError, OSError) as exc:
                result['capabilities'] = {'status': 'FAILED', 'reason': reason(exc)}
        from .toolchain import default_data_root, VERSIONS
        data = default_data_root()
        suffix = '.exe' if os.name == 'nt' else ''
        managed = {name: data / 'tools' / name / VERSIONS[name] / (name + suffix) for name in ('gitleaks', 'trivy')}
        managed['semgrep'] = data / 'engines/semgrep' / VERSIONS['semgrep'] / 'runtime' / ('Scripts' if os.name == 'nt' else 'bin') / ('semgrep' + suffix)
        # File presence is not execution or a successful version probe.
        result['engines'] = {name: 'MANAGED_FILE_PRESENT_VERSION_UNPROBED' if path.is_file()
                             else 'MANAGED_FILE_MISSING_EXTERNAL_ENGINE_UNPROBED'
                             for name, path in managed.items()}
        return result

    def paths(self, workspace):
        adapters = [(self.integration, self.integration.home)]
        if workspace is not None:
            adapters += [(self.integration.legacy_adapter, p) for p in self.integration.project_layers(workspace)]
        paths = []
        for adapter, root in adapters:
            paths.extend(adapter._config_paths(root))
            paths.append(adapter._state_path(root, 'ownership.json'))
        if self.manage_skill:
            paths.extend(self.skill.root / name for name in self.skill.expected)
            paths.append(self.skill.state / 'ownership.json')
        return sorted(set(paths), key=str)

    def signing_keys(self, workspace):
        paths = [self.integration._state_path(self.integration.home, 'snapshot.key')]
        if self.manage_skill:
            paths.append(self.skill.state / 'ownership.key')
        if workspace is not None:
            paths += [self.integration.legacy_adapter._state_path(p, 'snapshot.key')
                      for p in self.integration.project_layers(workspace)]
        return {str(p): revision(read(p)) for p in paths}

    def plan(self, workspace=None, *, issued_at=None):
        layers = self.layers(workspace)
        steps, blocked = [], []
        for row in layers:
            if row['action'] == 'USER_REVIEW_REQUIRED':
                blocked += row['diagnostics']
            elif row['action'] == 'REMOVE_SERVER_WITH_EXPLICIT_APPROVAL':
                # Validate the exact bounded layout now; never serialize TOML.
                patch_server(read(Path(row['config_path'])) or b'', b'', remove=True)
                steps.append({'kind': 'REMOVE_USER_SERVER', 'layer': row['layer'], 'scope': row['scope'],
                              'subtree': 'mcp_servers.' + SERVER, 'requires_explicit_approval': True})
            elif row['action'] == 'MIGRATE_OWNED':
                if 'POTENTIAL_DUPLICATE_HOOK' in row['diagnostics']:
                    blocked.append('POTENTIAL_DUPLICATE_HOOK')
                else:
                    steps.append({'kind': 'MIGRATE_OWNED', 'layer': row['layer'], 'scope': row['scope'],
                                  'subtree': 'mcp_servers.' + SERVER, 'hooks': 'SIGNED_HANDLERS_ONLY'})
        if self.manage_skill:
            skill_status = self.skill.status()['status']
            if skill_status in {'USER_MANAGED', 'USER_MODIFIED', 'OWNERSHIP_CONFLICT'}:
                blocked.append('SKILL_USER_CONTENT_PRESERVED')
        steps.append({'kind': 'REPAIR_GLOBAL', 'layer': str(self.integration.home), 'scope': 'GLOBAL',
                      'subtree': 'mcp_servers.' + SERVER, 'hooks': 'SIGNED_HANDLERS_ONLY'})
        if self.manage_skill:
            steps.append({'kind': 'UPGRADE_SKILL', 'layer': str(self.skill.root), 'scope': 'USER',
                          'files': sorted(self.skill.expected)})
        from .host_guidance import runtime_info
        value = {'contract': CONTRACT, 'issued_at': self.now() if issued_at is None else issued_at,
                 'expires_after_seconds': TTL, 'workspace': str(Path(workspace).absolute()) if workspace is not None else None,
                 'home': str(self.integration.home), 'skill_root': str(self.skill.root),
                 'build_identity': runtime_info()['build_identity'], 'steps': steps, 'blocked': sorted(set(blocked)),
                 'files': [{'path': str(p), 'revision': revision(read(p))} for p in self.paths(workspace)],
                 'recovery': 'SIGNED_LOCAL_JOURNAL_CAS_ROLLBACK; KEYS_AND_SCAN_STATE_PRESERVED',
                 'reconnect_required': True}
        if not self.manage_skill:
            value['manage_skill'] = False
        return value | {'plan_id': revision(encode(value))}

    def _save(self, journal):
        # Never replace a lost/changed journal identity while an operation (or
        # its completed receipt) exists. Validate with the current key first.
        if (self.directory / 'operation.json').exists():
            self._load()
        key = self.locks.key(self.integration.home)
        raw = encode(journal | {'signature': hmac.new(key, encode(journal), hashlib.sha256).hexdigest()})
        if len(raw) > MAX_JOURNAL:
            raise IntegrationDiagnostic('UPGRADE_JOURNAL_BUDGET_EXCEEDED')
        atomic_bytes(self.directory / 'operation.json', raw)

    def _load(self):
        path = self.directory / 'operation.json'
        no_links(path)
        if not path.exists():
            return None
        try:
            if path.stat().st_size > MAX_JOURNAL:
                raise ValueError()
            value = json.loads(path.read_bytes())
            signature = value.pop('signature')
            key_path = self.directory / 'snapshot.key'
            no_links(key_path)
            key = key_path.read_bytes()
            if (len(key) != 32 or value['contract'] != CONTRACT or value['home'] != str(self.integration.home)
                or not hmac.compare_digest(signature, hmac.new(key, encode(value), hashlib.sha256).hexdigest())):
                raise ValueError()
            return value
        except (ValueError, OSError, KeyError, TypeError, RecursionError):
            raise IntegrationDiagnostic('UPGRADE_JOURNAL_INVALID') from None

    def apply(self, plan, *, approve_user_managed=False, progress=None):
        from .install_progress import report_progress
        if not isinstance(plan, dict) or not isinstance(plan.get('workspace'), (str, type(None))):
            raise IntegrationDiagnostic('UPGRADE_PLAN_INVALID')
        workspace = plan.get('workspace')
        issued = plan.get('issued_at')
        if not isinstance(issued, (int, float)) or not 0 <= self.now() - issued <= TTL:
            raise IntegrationDiagnostic('UPGRADE_PLAN_EXPIRED')
        with self.locks.lock(self.integration.home) as acquired:
            if not acquired:
                raise IntegrationDiagnostic('UPGRADE_BUSY')
            old = self._load()
            if old and old['phase'] not in {'COMMITTED', 'RECOVERED'}:
                raise IntegrationDiagnostic('UPGRADE_RECOVERY_REQUIRED')
            if self.plan(workspace, issued_at=issued) != plan:
                raise IntegrationDiagnostic('UPGRADE_PLAN_CHANGED')
            if plan['blocked']:
                raise IntegrationDiagnostic('UPGRADE_PLAN_BLOCKED')
            if any(s['kind'] == 'REMOVE_USER_SERVER' for s in plan['steps']) and not approve_user_managed:
                raise IntegrationDiagnostic('USER_MANAGED_APPROVAL_REQUIRED')
            allowed = {p['path']: p['revision'] for p in plan['files']}
            journal = {'contract': CONTRACT, 'home': str(self.integration.home), 'plan_id': plan['plan_id'],
                       'phase': 'RUNNING', 'completed_steps': [], 'writes': {},
                       'keys': self.signing_keys(workspace),
                       'created_skill_root': str(self.skill.root) if self.manage_skill and not self.skill.root.exists() else None}
            self._save(journal)

            def observe(path, after):
                name = str(path)
                before = read(path)
                for key_path, expected in journal['keys'].items():
                    current = revision(read(Path(key_path)))
                    if expected is not None and current != expected:
                        raise IntegrationDiagnostic('UPGRADE_SIGNING_KEY_CHANGED')
                    if expected is None and current is not None:
                        journal['keys'][key_path] = current
                if name not in allowed or revision(before) != allowed[name]:
                    raise IntegrationDiagnostic('UPGRADE_CONCURRENT_CHANGE')
                row = journal['writes'].setdefault(name, {'original': base64.b64encode(before).decode() if before is not None else None,
                                                         'known_revisions': [revision(before)]})
                row['known_revisions'].append(revision(after))
                # Persist intent BEFORE the write, including crash-before-write.
                self._save(journal)
                allowed[name] = revision(after)

            adapters = (self.integration, self.integration.legacy_adapter)
            if self.manage_skill:
                adapters += (self.skill,)
            originals = [getattr(a, 'write_observer', None) for a in adapters]
            try:
                for adapter in adapters:
                    adapter.write_observer = observe
                for step in plan['steps']:
                    if any(revision(read(Path(name))) != digest for name, digest in allowed.items()):
                        raise IntegrationDiagnostic('UPGRADE_CONCURRENT_CHANGE')
                    if step['kind'] == 'REMOVE_USER_SERVER':
                        adapter = self.integration if step['scope'] == 'GLOBAL' else self.integration.legacy_adapter
                        path = adapter._config_paths(Path(step['layer']))[0]
                        raw = patch_server(read(path) or b'', b'', remove=True)
                        observe(path, raw)
                        atomic_bytes(path, raw)
                    elif step['kind'] == 'MIGRATE_OWNED':
                        report_progress(progress, 'MIGRATE_CONFIG')
                        self.integration.legacy_adapter.remove(Path(step['layer']))
                    elif step['kind'] == 'REPAIR_GLOBAL':
                        report_progress(progress, 'GLOBAL_CONFIG')
                        result = self.integration._mutate(self.integration.home, 'repair')
                        if result['overall'] != 'CONFIGURED':
                            raise IntegrationDiagnostic('UPGRADE_GLOBAL_NOT_READY')
                    else:
                        report_progress(progress, 'SKILL')
                        result = self.skill.execute('upgrade')
                        if result['status'] != 'INSTALLED':
                            raise IntegrationDiagnostic('UPGRADE_SKILL_NOT_READY')
                    journal['completed_steps'].append(step['kind'])
                    self._save(journal)
                if any(revision(read(Path(name))) != digest for name, digest in allowed.items()):
                    raise IntegrationDiagnostic('UPGRADE_CONCURRENT_CHANGE')
                journal['phase'] = 'COMMITTED'
                self._save(journal)
                return {'status': 'UPGRADED', 'plan_id': plan['plan_id'], 'completed_steps': journal['completed_steps'],
                        'reconnect_required': True, 'state_and_keys_preserved': True}
            except (ValueError, OSError) as exc:
                journal.update(phase='RECOVERY_REQUIRED', reason=reason(exc))
                self._save(journal)
                raise
            finally:
                for adapter, observer in zip(adapters, originals):
                    adapter.write_observer = observer

    def recover(self):
        with self.locks.lock(self.integration.home) as acquired:
            if not acquired:
                raise IntegrationDiagnostic('UPGRADE_BUSY')
            journal = self._load()
            if not journal or journal['phase'] in {'COMMITTED', 'RECOVERED'}:
                return {'status': 'NO_RECOVERY_REQUIRED'}
            # All-file preflight before touching any file. Never overwrite a
            # post-failure user edit, even in another component of the operation.
            for name, expected in journal.get('keys', {}).items():
                if expected is not None and revision(read(Path(name))) != expected:
                    raise IntegrationDiagnostic('UPGRADE_RECOVERY_SIGNING_KEY_CHANGED')
            for name, row in journal['writes'].items():
                if revision(read(Path(name))) not in row['known_revisions']:
                    raise IntegrationDiagnostic('UPGRADE_RECOVERY_CONCURRENT_CHANGE')
            for name, row in reversed(list(journal['writes'].items())):
                path = Path(name)
                if revision(read(path)) not in row['known_revisions']:
                    raise IntegrationDiagnostic('UPGRADE_RECOVERY_CONCURRENT_CHANGE')
                raw = base64.b64decode(row['original'], validate=True) if row['original'] is not None else None
                if raw is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_bytes(path, raw)
            if journal.get('created_skill_root'):
                root = Path(journal['created_skill_root'])
                no_links(root)
                for directory in (root / 'agents', root / 'references', root):
                    try:
                        directory.rmdir()
                    except OSError:
                        pass  # Preserve any subsequently created user files.
            journal['phase'] = 'RECOVERED'
            self._save(journal)
            return {'status': 'RECOVERED', 'reconnect_required': True, 'state_and_keys_preserved': True}
