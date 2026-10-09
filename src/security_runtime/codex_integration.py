"""Owned Codex MCP/Hook lifecycle and offline setup baseline. No source/mode mutation.

TOML user bytes are retained verbatim outside a signed, delimited owned block.
JSON retains unrelated values/order. A bounded HMAC manifest records fingerprints,
not config backups. Interrupted writes retain both old/new fingerprints for repair.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
import time
import tomllib
from datetime import timedelta
from pathlib import Path, PureWindowsPath

from ._version import __version__
from .codex_mcp_hook import codex_mcp_hook_config
from .hook_state import HookStateStore, atomic_bytes, identity, no_links
from .host_guidance import REQUIRED_GUIDANCE_TOOLS
from .integration_lifecycle import IntegrationDiagnostic
from .processes import run_process
from .storage import SQLiteStore
from .workspace import WorkspaceResolver

SERVER = 'ai_security_runtime'
VERSION = 'codex-integration-v0.2'
CONTRACT = 'developer-guidance-v0.3'
BEGIN = '\n# BEGIN AI Security Runtime managed Codex v0.2\n'
END = '# END AI Security Runtime managed Codex v0.2\n'
MAX_CONFIG = 262_144
MAX_METADATA = 16_384
REQUIRED_TOOLS = REQUIRED_GUIDANCE_TOOLS | {'handle_hook_event', 'handle_readiness_event', 'handle_stop_event',
    'confirm_remediation'}


def fingerprint(value) -> str:
    return identity(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True))


def unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate configuration key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def validated_workspace(value: str | Path | None) -> Path:
    raw = str(value) if value is not None else str(Path.cwd())
    if not raw.strip() or len(raw) > 4096 or any(ord(c) < 32 for c in raw) or '${' in raw:
        raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH')
    if raw.startswith(('\\\\', '//')) or (os.name != 'nt' and PureWindowsPath(raw).drive):
        raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH')
    if os.name == 'nt' and (raw.startswith('/') or (PureWindowsPath(raw).drive and not PureWindowsPath(raw).is_absolute())):
        raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH')
    candidate = Path(os.path.abspath(raw))
    try:
        no_links(candidate)
        root = WorkspaceResolver().resolve(candidate).path
        no_links(root)
    except (ValueError, OSError):
        raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH') from None
    if not candidate.is_relative_to(root):
        raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH')
    return root


def current_runtime() -> dict:
    executable = Path(sys.executable).absolute()
    # sys.executable is our trusted interpreter, including normal POSIX venv
    # symlinks. Preserve that environment rather than resolving to base Python.
    if not executable.is_file():
        raise IntegrationDiagnostic('RUNTIME_MISSING')
    frozen = bool(getattr(sys, 'frozen', False))
    if frozen:
        from .delivery import stable_command
        stable = stable_command(executable)
        if stable:
            executable = Path(stable)
    kind = 'FROZEN' if frozen else ('PYTHON_VENV' if sys.prefix != sys.base_prefix else 'SYSTEM_PYTHON')
    return {'command': str(executable), 'prefix': [] if frozen else ['-I', '-m', 'security_runtime.cli'], 'kind': kind}


def check_capabilities(info: dict, tools: set[str]) -> dict:
    if not isinstance(info, dict) or info.get('version') != __version__:
        raise IntegrationDiagnostic('RUNTIME_STALE')
    features = info.get('features', {})
    if (info.get('capability_contract') != CONTRACT or not isinstance(features, dict)
        or any(features.get(k) != 'v0.1' for k in ('smart_auto_remediation', 'confirmation_handoff'))
        or features.get('cold_start_readiness') != 'v0.3'
        or not REQUIRED_TOOLS.issubset(tools)
        or not REQUIRED_GUIDANCE_TOOLS.issubset(set(info.get('required_guidance_tools', [])))):
        raise IntegrationDiagnostic('CAPABILITY_MISMATCH')
    return {'status': 'OK', 'version': info['version'], 'capabilities': 'OK',
            'capability_contract': CONTRACT, 'mode': info.get('remediation', {}).get('mode', 'UNKNOWN')}


def probe_runtime(runtime: dict, root: Path, env: dict) -> dict:
    """Only our own executable is probed, never an arbitrary config command."""
    command = [runtime['command'], *runtime['prefix']]
    try:
        result = run_process([*command, 'runtime-info', '--json'], cwd=root, env=env, timeout=30, max_output=65536)
    except FileNotFoundError:
        raise IntegrationDiagnostic('RUNTIME_MISSING') from None
    except PermissionError:
        raise IntegrationDiagnostic('RUNTIME_LAUNCH_PERMISSION_DENIED') from None
    except TimeoutError:
        raise IntegrationDiagnostic('RUNTIME_PROBE_TIMEOUT') from None
    except (ValueError, OSError):
        raise IntegrationDiagnostic('CAPABILITY_MISMATCH') from None
    if result.returncode != 0:
        raise IntegrationDiagnostic('CAPABILITY_MISMATCH')
    try:
        info = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise IntegrationDiagnostic('CAPABILITY_MISMATCH') from None
    if env.get('SECURITY_RUNTIME_GLOBAL') == '1' and (not isinstance(info, dict)
        or not isinstance(info.get('features'), dict)
        or info['features'].get('global_runtime_integration') != 'v0.1'):
        raise IntegrationDiagnostic('CAPABILITY_MISMATCH')

    async def discover():
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        # Never route child errors/config contents to CLI output or logs.
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            params = StdioServerParameters(command=runtime['command'], args=[*runtime['prefix'], 'mcp'], env=env, cwd=str(root))
            async with stdio_client(params, errlog=errors) as (reader, writer):
                async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=20)) as session:
                    await session.initialize()
                    tools = (await session.list_tools()).tools
                    if env.get('SECURITY_RUNTIME_GLOBAL') == '1':
                        result = await session.call_tool('get_runtime_info', {})
                        data = result.structuredContent or json.loads(result.content[0].text)
                        data = data.get('result', data)
                        if (result.isError or data.get('integration_scope') != 'GLOBAL'
                            or data.get('features', {}).get('global_runtime_integration') != 'v0.1'
                            or not any(t.name == 'get_findings' and 'workspace_path' in t.inputSchema.get('properties', {}) for t in tools)):
                            raise IntegrationDiagnostic('CAPABILITY_MISMATCH')
                    return {t.name for t in tools}
    try:
        tools = asyncio.run(asyncio.wait_for(discover(), timeout=30))
    except Exception as exc:
        def failure(error):
            if isinstance(error, IntegrationDiagnostic):
                return error.code
            if isinstance(error, TimeoutError):
                return 'MCP_PROBE_TIMEOUT'
            if isinstance(error, BaseExceptionGroup):
                for child in error.exceptions:
                    code = failure(child)
                    if code:
                        return code
            return None
        raise IntegrationDiagnostic(failure(exc) or 'MCP_PROBE_FAILED') from None
    return check_capabilities(info, tools)


def product_hooks() -> dict:
    # Definitions are stable between explicit event-contract upgrades. P0-7.3
    # adds invocation claims; its changed definition needs one new trust review.
    result = codex_mcp_hook_config()
    result['hooks']['PostToolUse'][0]['hooks'][0]['statusMessage'] = 'AI Security Runtime [codex-integration-v0.2]'
    result['hooks']['SessionStart'] = [{'hooks': [{
        'type': 'mcp_tool', 'server': SERVER, 'tool': 'handle_readiness_event',
        'input': {'event': '${hook_event_name}', 'workspace_path': '${cwd}', 'session_id': '${session_id}',
                  'permission_mode': '${permission_mode}'},
        'timeout': 30, 'statusMessage': 'AI Security Runtime [readiness-v0.3]',
    }]}]
    result['hooks']['Stop'] = [{'hooks': [{
        'type': 'mcp_tool', 'server': SERVER, 'tool': 'handle_stop_event',
        'input': {'event': '${hook_event_name}', 'workspace_path': '${cwd}',
                  'session_id': '${session_id}', 'stop_hook_active': '${stop_hook_active}',
                  'turn_id': '${turn_id}', 'permission_mode': '${permission_mode}'},
        'timeout': 30, 'statusMessage': 'AI Security Runtime [continuation-guard-v0.1]',
    }]}]
    return result


class CodexIntegrationAdapter:
    integration_id = 'codex'
    manifest_versions = {'codex-integration-v0.1', VERSION}

    def __init__(self, *, directory: Path | None = None, discover=None, probe=None, now=None, baseline_coordinator=None):
        self.store = HookStateStore(directory or SQLiteStore.default_path().parent / 'codex-integrations')
        self.discover = discover or current_runtime
        self.probe = probe or probe_runtime
        self.now = now or time.time
        self.write_observer = None
        from .baseline_seed import WorkspaceBaselineSeeds
        self.baselines = WorkspaceBaselineSeeds(self, coordinator=baseline_coordinator, now=self.now)

    def _state_path(self, root, name):
        path = self.store.workspace_directory(root) / name
        no_links(path)
        if path.is_relative_to(root):
            raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH')
        return path

    @staticmethod
    def _read(path, maximum=MAX_CONFIG) -> bytes:
        no_links(path)
        if not path.exists():
            return b''
        if not path.is_file() or path.stat().st_size > maximum:
            raise IntegrationDiagnostic('CONFIG_INVALID')
        with path.open('rb') as stream:
            result = stream.read(maximum + 1)
        if len(result) > maximum:
            raise IntegrationDiagnostic('CONFIG_INVALID')
        return result

    def _manifest(self, root):
        data = self._read(self._state_path(root, 'ownership.json'), MAX_METADATA)
        if not data:
            return None
        try:
            value = json.loads(data)
            signature = value.pop('signature')
            key = self._read(self._state_path(root, 'snapshot.key'), 32)
            if len(key) != 32 or not hmac.compare_digest(signature, hmac.new(key, self._encode(value), hashlib.sha256).hexdigest()):
                raise ValueError()
            if (value['integration_id'] != 'codex' or value['managed_version'] not in self.manifest_versions
                or value['workspace_hash'] != identity(os.path.normcase(str(root)))
                or value['server'] != SERVER or value['phase'] not in {'COMMITTED', 'UPDATING'}
                or not isinstance(value['records'], list) or not 1 <= len(value['records']) <= 2):
                raise ValueError()
            for record in value['records']:
                if set(record) != {'block', 'server', 'hooks'} or not isinstance(record['hooks'], dict):
                    raise ValueError()
                hashes = [record['block'], record['server'], *record['hooks'].values()]
                if any(not isinstance(s, str) or not re.fullmatch('[a-f0-9]{64}', s) for s in hashes):
                    raise ValueError()
            return value
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise IntegrationDiagnostic('OWNERSHIP_INVALID') from None

    @staticmethod
    def _encode(data):
        return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()

    def _save(self, root, manifest):
        key = self.store.key(root)
        result = {**manifest, 'signature': hmac.new(key, self._encode(manifest), hashlib.sha256).hexdigest()}
        content = self._encode(result)
        if len(content) > MAX_METADATA:
            raise IntegrationDiagnostic('CONFIG_INVALID')
        self._write(self._state_path(root, 'ownership.json'), content)

    def _write(self, path, content):
        if self.write_observer is not None:
            self.write_observer(path, content)
        if content is None:
            path.unlink(missing_ok=True)
        else:
            atomic_bytes(path, content)

    def _config(self, root, manifest=None):
        if manifest is None:
            manifest = self._manifest(root)
        toml_path, hook_path = self._config_paths(root)
        a, b = self._read(toml_path), self._read(hook_path)
        try:
            owned = self._owned_blocks(a, manifest, self._ownership_desired(root, manifest))
            parse_a = a
            if len(owned) > 1:
                for found in reversed(owned):
                    parse_a = parse_a[:found.start()] + parse_a[found.end():]
                # Parse only after removing independently attested duplicates.
                # An unowned same-name table still fails closed in the parser.
                parse_a += owned[0].group()
            document = tomllib.loads(parse_a.decode('utf-8')) if parse_a else {}
            hooks = unique_json(b) if b else {'hooks': {}}
            if not isinstance(document.get('mcp_servers', {}), dict) or not isinstance(document.get('features', {}), dict):
                raise ValueError()
            self._validate_hooks(hooks)
            self._inline_hooks(document)
            for entry in document.get('mcp_servers', {}).values():
                if not isinstance(entry, dict):
                    raise ValueError()
            return (toml_path, a, document), (hook_path, b, hooks)
        except IntegrationDiagnostic:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise IntegrationDiagnostic('CONFIG_INVALID') from None

    def _config_paths(self, root):
        return root / '.codex/config.toml', root / '.codex/hooks.json'

    @staticmethod
    def _inline_hooks(document):
        """Event-only view; Codex's TOML trust state is never a hook definition.

        HooksToml.state maps opaque host keys to HookStateToml objects. Known
        fields follow the official schema; additional state fields remain host
        owned. No other dictionary-valued [hooks] key gets this exception.
        The original parsed document and its on-disk bytes stay untouched.
        """
        hooks = document.get('hooks', {})
        if not isinstance(hooks, dict):
            raise ValueError()
        if 'state' in hooks:
            state = hooks['state']
            if not isinstance(state, dict):
                raise ValueError()
            for entry in state.values():
                if (not isinstance(entry, dict)
                    or ('enabled' in entry and not isinstance(entry['enabled'], bool))
                    or ('trusted_hash' in entry and not isinstance(entry['trusted_hash'], str))):
                    raise ValueError()
        definitions = {event: groups for event, groups in hooks.items() if event != 'state'}
        CodexIntegrationAdapter._validate_hooks({'hooks': definitions})
        return definitions

    @staticmethod
    def _validate_hooks(value):
        if not isinstance(value, dict) or not isinstance(value.get('hooks'), dict):
            raise ValueError()
        for groups in value['hooks'].values():
            if not isinstance(groups, list):
                raise ValueError()
            for group in groups:
                if (not isinstance(group, dict) or not isinstance(group.get('hooks'), list)
                    or ('matcher' in group and not isinstance(group['matcher'], str))):
                    raise ValueError()
                for hook in group['hooks']:
                    if not isinstance(hook, dict) or hook.get('type') not in {'command', 'mcp_tool', 'prompt', 'agent'}:
                        raise ValueError()
                    required = {'command': ('command',), 'mcp_tool': ('server', 'tool')}.get(hook['type'], ())
                    if any(not isinstance(hook.get(field), str) for field in required):
                        raise ValueError()
                    if (('input' in hook and hook['type'] == 'mcp_tool' and not isinstance(hook['input'], dict))
                        or ('timeout' in hook and (type(hook['timeout']) is not int or hook['timeout'] < 0))
                        or ('statusMessage' in hook and not isinstance(hook['statusMessage'], str))):
                        raise ValueError()

    def _desired(self, root):
        runtime = self.discover()
        directory = SQLiteStore.default_path().parent.absolute()
        no_links(directory)
        if directory.is_relative_to(root):
            raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH')
        env = {'SECURITY_RUNTIME_WORKSPACE': str(root), 'SECURITY_RUNTIME_INTEGRATION': 'codex',
               'SECURITY_RUNTIME_STATE_DIR': str(directory)}
        server = {'command': runtime['command'], 'args': [*runtime['prefix'], 'mcp'], 'cwd': str(root),
                  'enabled': True, 'required': True, 'startup_timeout_sec': 60, 'tool_timeout_sec': 120, 'env': env}
        q = lambda s: json.dumps(s, ensure_ascii=True)
        lines = [BEGIN.rstrip('\n'), f'[mcp_servers.{SERVER}]', 'command = ' + q(server['command']),
                 'args = ' + q(server['args']), 'cwd = ' + q(server['cwd']), 'enabled = true', 'required = true',
                 'startup_timeout_sec = 60', 'tool_timeout_sec = 120', f'[mcp_servers.{SERVER}.env]']
        lines.extend(k + ' = ' + q(v) for k, v in env.items())
        block = ('\n'.join(lines) + '\n' + END).encode()
        hooks = product_hooks()
        record = {'block': identity(block.decode()), 'server': fingerprint(server),
                  'hooks': {e: fingerprint(g[0]) for e, g in hooks['hooks'].items()}}
        return runtime, env, server, block, hooks, record

    def _ownership_desired(self, root, manifest):
        return self._desired(root)[2]

    @staticmethod
    def _validate_owned_block_semantics(document, manifest, desired):
        # No sibling servers or unrelated TOML may become Runtime-owned during
        # format recovery. Equality includes every field and nested env value.
        servers = document.get('mcp_servers')
        if (set(document) != {'mcp_servers'} or not isinstance(servers, dict)
                or set(servers) != {SERVER} or desired is None):
            raise IntegrationDiagnostic('MCP_CONFIGURATION_CONFLICT')
        server = servers[SERVER]
        if (server != desired or manifest is None
                or fingerprint(server) not in {r['server'] for r in manifest['records']}):
            raise IntegrationDiagnostic('MCP_CONFIGURATION_CONFLICT')
        return server

    @staticmethod
    def _owned_blocks(raw, manifest, desired=None):
        if raw.count(b'# BEGIN AI Security Runtime managed Codex') > 16:
            raise IntegrationDiagnostic('CONFIG_INVALID')
        pattern = re.compile(rb'(?m)\r?\n^# BEGIN AI Security Runtime managed Codex (v0\.[12])\r?\n'
                             rb'.*?^# END AI Security Runtime managed Codex \1\r?\n', re.DOTALL)
        matches = list(pattern.finditer(raw))
        starts = len(re.findall(rb'(?m)^# BEGIN AI Security Runtime managed Codex v0\.[12]\r?$', raw))
        ends = len(re.findall(rb'(?m)^# END AI Security Runtime managed Codex v0\.[12]\r?$', raw))
        marker_starts = len(re.findall(rb'(?m)^# BEGIN AI Security Runtime managed Codex[^\r\n]*', raw))
        marker_ends = len(re.findall(rb'(?m)^# END AI Security Runtime managed Codex[^\r\n]*', raw))
        if starts != len(matches) or ends != len(matches) or marker_starts != starts or marker_ends != ends:
            raise IntegrationDiagnostic('MCP_CONFIGURATION_CONFLICT')
        for found in matches:
            normalized = found.group().replace(b'\r\n', b'\n').decode('utf-8')
            document = tomllib.loads(normalized)
            parsed = document.get('mcp_servers', {}).get(SERVER)
            exact = manifest is not None and any(r['block'] == identity(normalized) and
                    r['server'] == fingerprint(parsed) for r in manifest['records'])
            if not exact:
                if len(matches) != 1:
                    raise IntegrationDiagnostic('MCP_CONFIGURATION_CONFLICT')
                CodexIntegrationAdapter._validate_owned_block_semantics(document, manifest, desired)
                effective = tomllib.loads(raw.decode('utf-8')).get('mcp_servers', {}).get(SERVER)
                if effective != parsed:
                    raise IntegrationDiagnostic('MCP_CONFIGURATION_CONFLICT')
        return matches

    @staticmethod
    def _owned_group(event, group, manifest):
        return bool(group['hooks']) and all(CodexIntegrationAdapter._owned_handler(event, group, h, manifest) for h in group['hooks'])

    @staticmethod
    def _owned_handler(event, group, handler, manifest):
        wrapper = {**group, 'hooks': [handler]}
        if manifest is None:
            return False
        if any(r['hooks'].get(event) == fingerprint(wrapper) for r in manifest['records']):
            return True
        # Exact released MCP POC shape only, anchored by the signed installation.
        # Similar server names, custom matchers/inputs/timeouts are not ownership.
        from .codex_mcp_hook import codex_mcp_hook_config
        return wrapper in codex_mcp_hook_config()['hooks'].get(event, [])

    @staticmethod
    def _related(event, group):
        return any((h.get('server') == SERVER and h.get('tool') in {'handle_hook_event', 'handle_readiness_event', 'handle_stop_event'})
                   or (h.get('type') == 'command' and ('security-check' in str(h.get('command', ''))
                       or h.get('statusMessage') == 'AI Security Runtime [hook-v1]')) for h in group['hooks'])

    def _legacy(self, root, hooks):
        """Legacy has no signed receipt. Require exact old generator + its Git marker.

        Similar commands/markers alone are not ownership. Modified or mixed entries
        remain unowned. Command transport implementation remains available.
        """
        from .hook_adapters import CodexHookAdapter
        expected = CodexHookAdapter().config(root)
        marker = '\n# AI Security Runtime: .codex/hooks.json\n/.codex/hooks.json\n# End AI Security Runtime: .codex/hooks.json\n'
        exclude = root / '.git/info/exclude'
        no_links(exclude)
        # Linked worktrees have no directory .git; do not guess their provenance.
        marked = exclude.is_file() and marker.encode() in self._read(exclude)
        present = marked and any(self._legacy_handler(e, g, h, expected)
            for e, groups in hooks.get('hooks', {}).items() for g in groups for h in g['hooks'])
        return expected if present else {}

    @staticmethod
    def _legacy_handler(event, group, handler, legacy):
        return {**group, 'hooks': [handler]} in legacy.get(event, [])

    def _inspect_mcp(self, root, raw, document, manifest, server):
        diagnostics = []
        current = document.get('mcp_servers', {}).get(SERVER)
        owned = self._owned_blocks(raw, manifest, server)
        if len(owned) > 1:
            diagnostics.append('MCP_DUPLICATE_MANAGED_BLOCK')
        if manifest and manifest['managed_version'] != VERSION:
            diagnostics.append('MANAGED_FORMAT_UPGRADE_REQUIRED')
        if current is None:
            diagnostics.append('MCP_NOT_CONFIGURED')
        elif manifest is None or owned is None or fingerprint(current) not in {r['server'] for r in manifest['records']}:
            raise IntegrationDiagnostic('MCP_CONFIGURATION_CONFLICT')
        elif current.get('env', {}).get('SECURITY_RUNTIME_WORKSPACE') != str(root):
            diagnostics.append('WORKSPACE_BINDING_MISMATCH')
        elif current != server:
            diagnostics.append('RUNTIME_MISSING' if not Path(current.get('command', '')).is_file() else 'RUNTIME_STALE')
        return diagnostics, owned

    def _inspection(self, root, configs, manifest, desired):
        (_, raw, document), (_, _, hooks) = configs
        runtime, env, server, block, wanted, record = desired
        diagnostics, owned = self._inspect_mcp(root, raw, document, manifest, server)
        if document.get('features', {}).get('hooks') is False:
            diagnostics.append('HOST_HOOKS_DISABLED')
        legacy = self._legacy(root, hooks)
        if legacy:
            diagnostics.append('LEGACY_HOOK_PRESENT')
        for event, groups in hooks['hooks'].items():
            for group in groups:
                foreign = {**group, 'hooks': [h for h in group['hooks'] if not self._owned_handler(event, group, h, manifest)
                    and not self._legacy_handler(event, group, h, legacy)]}
                if self._related(event, foreign) and group not in legacy.get(event, []):
                    diagnostics.append('POTENTIAL_DUPLICATE_HOOK')
        for event, groups in self._inline_hooks(document).items():
            if any(self._related(event, group) for group in groups):
                diagnostics.append('POTENTIAL_DUPLICATE_HOOK')
        for event, groups in wanted['hooks'].items():
            state = self._hook_status(event, hooks, wanted, manifest)
            if state != 'CONFIGURED':
                diagnostics.append(state)
        return list(dict.fromkeys(diagnostics)), owned, legacy

    def _hook_status(self, event, hooks, wanted, manifest):
        owned_count = sum(self._owned_handler(event, group, h, manifest)
                          for group in hooks['hooks'].get(event, []) for h in group['hooks'])
        if owned_count > 1:
            return 'HOOK_DUPLICATE'
        count = sum({**group, 'hooks': [h]} == wanted['hooks'][event][0] and self._owned_handler(event, group, h, manifest)
                    for group in hooks['hooks'].get(event, []) for h in group['hooks'])
        return 'HOOK_MISSING' if count == 0 else ('HOOK_DUPLICATE' if count > 1 else 'CONFIGURED')

    def status(self, root: Path) -> dict:
        manifest = self._manifest(root)
        configs = self._config(root, manifest)
        desired = self._desired(root)
        diagnostics, owned, legacy = self._inspection(root, configs, manifest, desired)
        runtime, env, *_ = desired
        capability = self.probe(runtime, root, {**os.environ, **env, 'SECURITY_RUNTIME_MCP_SELF_TEST': '1'})
        readiness = self.readiness_status(root, desired[-1], manifest)
        if diagnostics and readiness['status'] == 'READINESS_OBSERVED':
            readiness = {'status': 'READINESS_STALE'}
        readiness['hook_status'] = self._hook_status('SessionStart', configs[1][2], desired[4], manifest)
        diagnostics.append(readiness['status']) if readiness['status'] != 'READINESS_OBSERVED' else None
        absent = not manifest and configs[0][2].get('mcp_servers', {}).get(SERVER) is None
        configured = not any(d in diagnostics for d in ('MCP_NOT_CONFIGURED', 'RUNTIME_STALE', 'RUNTIME_MISSING',
            'WORKSPACE_BINDING_MISMATCH', 'HOOK_MISSING', 'HOOK_DUPLICATE', 'POTENTIAL_DUPLICATE_HOOK', 'LEGACY_HOOK_PRESENT', 'HOST_HOOKS_DISABLED',
            'MCP_DUPLICATE_MANAGED_BLOCK', 'MANAGED_FORMAT_UPGRADE_REQUIRED'))
        overall = 'NOT_INSTALLED' if absent else ('READY' if configured and readiness['status'] == 'READINESS_OBSERVED'
            else ('CONFIGURED' if configured else 'DEGRADED'))
        baseline = self.baselines.status(root)
        if not absent and baseline['status'] != 'READY':
            overall = 'DEGRADED'
            diagnostics.append('BASELINE_SEED_STALE' if baseline['status'] == 'STALE' else 'BASELINE_NOT_ESTABLISHED')
        return {'integration': 'codex', 'workspace_hash': identity(os.path.normcase(str(root))),
                'installation': 'NOT_INSTALLED' if absent else 'CONFIGURED', 'runtime': {**capability, 'kind': runtime['kind']},
                'mode': capability['mode'], 'mcp': {'status': 'CONFIGURED' if owned else 'MCP_NOT_CONFIGURED'},
                'post_tool_hook': {'status': self._hook_status('PostToolUse', configs[1][2], desired[4], manifest)},
                'stop_hook': {'status': self._hook_status('Stop', configs[1][2], desired[4], manifest)},
                'readiness': readiness, 'legacy_hook': {'status': 'LEGACY_HOOK_PRESENT' if legacy else ('POTENTIAL_DUPLICATE_HOOK' if 'POTENTIAL_DUPLICATE_HOOK' in diagnostics else 'NONE')},
                'overall': overall, 'diagnostics': diagnostics, 'live_connection': 'UNKNOWN', 'baseline': baseline,
                'hook_trust': 'HOST_MANAGED_UNKNOWN',
                'cold_start_host_trial': 'PENDING_ACTUAL_DESKTOP', 'project_trust': 'HOST_MANAGED_PREREQUISITE'}

    def readiness_status(self, root, record, manifest):
        try:
            raw = self._read(self._state_path(root, 'readiness.json'), 4096)
        except IntegrationDiagnostic:
            return {'status': 'READINESS_STALE'}
        if not raw:
            return {'status': 'READINESS_NOT_OBSERVED'}
        try:
            value = json.loads(raw)
            signature = value.pop('signature')
            key = self._read(self._state_path(root, 'snapshot.key'), 32)
            valid = len(key) == 32 and hmac.compare_digest(signature, hmac.new(key, self._encode(value), hashlib.sha256).hexdigest())
            valid = valid and manifest is not None and manifest['phase'] == 'COMMITTED' and manifest['records'] == [record]
            valid = valid and value['config_hash'] == fingerprint(record) and value['runtime_version'] == __version__ and value['capability_contract'] == CONTRACT
            valid = valid and value['workspace_hash'] == identity(os.path.normcase(str(root))) and value['host'] == 'codex'
            valid = valid and isinstance(value['observed_at'], (int, float)) and 0 <= self.now() - value['observed_at'] <= 900
            if not valid:
                raise ValueError()
            return {'status': 'READINESS_OBSERVED', 'observed_at': value['observed_at'], 'observation': 'UNTRUSTED_HOST_CLAIM_VALIDATED_BINDING'}
        except (ValueError, TypeError, KeyError):
            return {'status': 'READINESS_STALE'}

    def setup(self, root):
        return self._mutate(root, 'setup')

    def repair(self, root):
        return self._mutate(root, 'repair')

    def remove(self, root):
        return self._mutate(root, 'remove')

    def _patch_mcp(self, raw, document, owned, block, server, action):
        result = raw
        for found in reversed(owned):
            result = result[:found.start()] + result[found.end():]
        if action != 'remove':
            result += block
        if len(owned) == 1 and owned[0].group().replace(b'\r\n', b'\n') == block and action != 'remove':
            result = raw
        return result

    def _new_manifest(self, root, record):
        return {'integration_id': 'codex', 'managed_version': VERSION,
                'workspace_hash': identity(os.path.normcase(str(root))),
                'server': SERVER, 'phase': 'COMMITTED', 'records': [record]}

    def _mutate(self, root, action):
        self._state_path(root, 'ownership.json')
        with self.store.lock(root, wait_seconds=5) as acquired:
            if not acquired:
                raise IntegrationDiagnostic('INTEGRATION_BUSY')
            manifest = self._manifest(root)
            configs = self._config(root, manifest)
            desired = self._desired(root)
            diagnostics, owned, legacy = self._inspection(root, configs, manifest, desired)
            if 'POTENTIAL_DUPLICATE_HOOK' in diagnostics:
                raise IntegrationDiagnostic('POTENTIAL_DUPLICATE_HOOK')
            runtime, env, server, block, wanted, record = desired
            if action != 'remove':
                capability = self.probe(runtime, root, {**os.environ, **env, 'SECURITY_RUNTIME_MCP_SELF_TEST': '1'})
            else:
                capability = None
            (a_path, a, document), (b_path, b, hooks) = configs
            new_a = self._patch_mcp(a, document, owned, block, server, action)
            merged = copy.deepcopy(hooks)
            for event, groups in list(merged['hooks'].items()):
                kept = []
                for group in groups:
                    if group in legacy.get(event, []):
                        continue
                    handlers = [h for h in group['hooks'] if not self._owned_handler(event, group, h, manifest)
                                and not self._legacy_handler(event, group, h, legacy)]
                    if handlers:
                        kept.append({**group, 'hooks': handlers})
                if kept:
                    merged['hooks'][event] = kept
                else:
                    del merged['hooks'][event]
            if action != 'remove':
                for event, groups in wanted['hooks'].items():
                    merged['hooks'].setdefault(event, []).extend(groups)
            new_b = (json.dumps(merged, ensure_ascii=True, indent=2) + '\n').encode() if merged != hooks else b
            parsed = tomllib.loads(new_a.decode()) if new_a else {}
            self._validate_hooks(merged)
            if action != 'remove' and parsed.get('mcp_servers', {}).get(SERVER) != server:
                raise IntegrationDiagnostic('CONFIG_INVALID')
            if max(len(new_a), len(new_b)) > MAX_CONFIG:
                raise IntegrationDiagnostic('CONFIG_INVALID')
            changed = (new_a != a or new_b != b)
            new_manifest = self._new_manifest(root, record)
            if action != 'remove' and (changed or manifest != new_manifest):
                previous = manifest['records'][-1] if manifest else record
                pending = {**new_manifest, 'phase': 'UPDATING', 'records': [previous] if previous == record else [previous, record]}
                self._save(root, pending)
            # Concurrent non-Runtime edits are never blindly overwritten.
            if self._read(a_path) != a or self._read(b_path) != b:
                raise IntegrationDiagnostic('CONFIG_CHANGED_RETRY')
            written = []
            try:
                for path, before, after in ((a_path, a, new_a), (b_path, b, new_b)):
                    if before != after:
                        no_links(path)
                        if self._read(path) != before:
                            raise IntegrationDiagnostic('CONFIG_CHANGED_RETRY')
                        existed = path.exists()
                        self._write(path, after)
                        written.append((path, before, after, existed))
                        if self._read(path) != after:
                            raise IntegrationDiagnostic('CONFIG_CHANGED_RETRY')
                if self._read(a_path) != new_a or self._read(b_path) != new_b:
                    raise IntegrationDiagnostic('CONFIG_CHANGED_RETRY')
                if action == 'remove':
                    self.baselines.remove(root)
                    # Retain signing keys across migration; never recreate an
                    # invalid installation's identity as an upgrade shortcut.
                    self._write(self._state_path(root, 'ownership.json'), None)
                    self._state_path(root, 'readiness.json').unlink(missing_ok=True)
                elif changed or manifest != new_manifest:
                    self._save(root, new_manifest)
            except (ValueError, OSError):
                # In-memory rollback only when no other writer touched our bytes.
                for path, before, after, existed in reversed(written):
                    if self._read(path) == after:
                        if existed:
                            self._write(path, before)
                        else:
                            self._write(path, None)
                raise
            if action == 'remove':
                return {'integration': 'codex', 'overall': 'NOT_INSTALLED', 'operation': 'REMOVED' if changed or manifest else 'ALREADY_REMOVED', 'diagnostics': []}
            try:
                baseline = self.baselines.ensure(root, reestablish=manifest is not None or action == 'repair')
            except (ValueError, OSError):
                baseline = self.baselines.status_value('INCONCLUSIVE', 'BASELINE_CHECK_INCONCLUSIVE')
            result = self.status(root)
            result['baseline'] = baseline
            if baseline['status'] != 'READY':
                result['overall'] = 'DEGRADED'
            result['operation'] = 'ALREADY_CONFIGURED' if not changed and manifest == new_manifest else ('REPAIRED' if action == 'repair' else 'CONFIGURED')
            return result
