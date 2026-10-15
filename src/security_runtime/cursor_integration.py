"""Owned, preservation-aware user-level Cursor command Hooks. No MCP migration."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shlex
from pathlib import Path

from .codex_integration import unique_json, fingerprint
from .global_integration import installed_runtime
from .hook_state import HookStateStore, atomic_bytes, no_links
from .storage import SQLiteStore
from .cursor_event_adapter import EVENTS


def cursor_home(value=None):
    raw = str(value if value is not None else os.getenv('SECURITY_RUNTIME_CURSOR_HOME', Path.home() / '.cursor'))
    path = Path(raw)
    if (not path.is_absolute() or '${' in raw or any(ord(c) < 32 for c in raw)
            or path == Path(path.anchor) or path == Path.home() or raw.startswith(('\\\\', '//'))):
        raise ValueError('CURSOR_HOME_INVALID')
    no_links(path)
    return path


PRODUCTION_EVENTS = ('sessionStart', 'afterFileEdit', 'afterShellExecution', 'stop')
AUTOMATIC_EVENTS = (*PRODUCTION_EVENTS, 'preToolUse', 'postToolUse')


def launcher(runtime, *, automatic=False):
    args = [runtime['command'], *runtime['prefix'], 'cursor-hook', *(['--automatic'] if automatic else [])]
    if os.name == 'nt':
        if any(any(c in value for c in '%!"\r\n') for value in args):
            raise ValueError('UNSAFE_LAUNCHER_PATH')
        return ' '.join('"'+value+'"' for value in args)
    return shlex.join(args)


class GlobalCursorIntegration:
    def __init__(self, *, home=None, directory=None, discover=None, allow_dev=False, automatic=False):
        self.home = cursor_home(home)
        self.store = HookStateStore(directory or SQLiteStore.default_path().parent / 'cursor-integrations')
        self.discover = discover or installed_runtime
        self.allow_dev = allow_dev
        self.automatic = automatic
        self.write_observer = None

    def _load(self):
        path = self.home / 'hooks.json'
        no_links(path)
        raw = path.read_bytes() if path.exists() else None
        if raw is not None and len(raw) > 262144:
            raise ValueError('CONFIG_INVALID')
        value = unique_json(raw) if raw is not None else {'version': 1, 'hooks': {}}
        if (not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1
                or not isinstance(value.get('hooks'), dict)):
            raise ValueError('CONFIG_INVALID')
        for groups in value['hooks'].values():
            if not isinstance(groups, list):
                raise ValueError('CONFIG_INVALID')
            for group in groups:
                if not isinstance(group, dict) or (group.get('type', 'command') == 'command'
                        and not isinstance(group.get('command'), str)) or (group.get('type') == 'prompt'
                        and not isinstance(group.get('prompt'), str)) or group.get('type', 'command') not in {'command', 'prompt'}:
                    raise ValueError('CONFIG_INVALID')
        return path, raw, value

    def _manifest(self):
        path = self.store.workspace_directory(self.home) / 'ownership.json'
        no_links(path)
        if not path.exists():
            return path, None
        if path.stat().st_size > 64000:
            raise ValueError('OWNERSHIP_INVALID')
        value = unique_json(path.read_bytes())
        signature = value.pop('signature')
        key_path = self.store.workspace_directory(self.home) / 'snapshot.key'
        no_links(key_path)
        key = key_path.read_bytes()
        if (len(key) != 32 or set(value) != {'version', 'records'} or value['version'] != 'cursor-global-v1'
                or not isinstance(value['records'], dict) or set(value['records']) not in (set(AUTOMATIC_EVENTS), set(PRODUCTION_EVENTS), set(PRODUCTION_EVENTS)|{'postToolUse'})
                or not hmac.compare_digest(signature, hmac.new(key, encode(value), hashlib.sha256).hexdigest())):
            raise ValueError('OWNERSHIP_INVALID')
        return path, value

    def execute(self, action):
        if action not in {'setup', 'status', 'repair', 'remove'}:
            raise ValueError('UNSUPPORTED_INTEGRATION')
        with self.store.lock(self.home, wait_seconds=2) as locked:
            if not locked:
                raise ValueError('CONFIGURATION_BUSY')
            return self._execute(action)

    def _execute(self, action):
        path, original, value = self._load()
        manifest_path, manifest = self._manifest()
        runtime = self.discover()
        if runtime['kind'] == 'DEV' and not self.allow_dev and action in {'setup', 'repair'} and manifest is None:
            raise ValueError('INSTALLED_RUNTIME_REQUIRED')
        cmd = launcher(runtime, automatic=self.automatic)
        events = AUTOMATIC_EVENTS if self.automatic else PRODUCTION_EVENTS
        # Only the four observed reliable event surfaces are installed.
        expected = {e: {'command': cmd, 'type': 'command', 'timeout': 120,
                       **({'loop_limit': 1} if e == 'stop' else {})} for e in events}
        actual = {}
        if manifest:
            for event, record in manifest['records'].items():
                matches = [g for g in value['hooks'].get(event, []) if fingerprint(g) == fingerprint(record)]
                if len(matches) > 1:
                    raise ValueError('POTENTIAL_DUPLICATE_HOOK')
                actual[event] = matches
        # An unowned lookalike is related, not evidence of ownership.
        for event, groups in value['hooks'].items():
            for group in groups:
                if 'cursor-hook' in group.get('command', '') and group not in actual.get(event, []):
                    raise ValueError('UNOWNED_RUNTIME_HOOK')
        configured = manifest is not None and set(manifest['records']) == set(events) and all(actual.get(e) == [expected[e]] for e in events)
        report = dict(integration='cursor', scope='GLOBAL', overall='CONFIGURED' if configured else 'NOT_INSTALLED' if not manifest else 'NEEDS_REPAIR',
            implementation='IMPLEMENTED', config_path=str(path), fresh_host_trial='PENDING_ACTUAL_CURSOR_DESKTOP',
            continuation_status='PENDING_CURSOR_CONTINUATION_CAPABILITY', mcp_status='UNCHANGED', changed=False,
            post_tool_use_mode='NOT_ENABLED_BY_DEFAULT',
            supports_detection=True, supports_advisory_remediation=True,
            supports_user_visible_feedback=False, supports_agent_continuation=False,
            feedback_status='HOST_CAPABILITY_UNAVAILABLE_ON_OBSERVED_PATH')
        if action == 'status':
            return report
        merged = json.loads(json.dumps(value))
        for event, groups in actual.items():
            merged['hooks'][event] = [g for g in merged['hooks'].get(event, []) if g not in groups]
            if not merged['hooks'][event]:
                del merged['hooks'][event]
        if action != 'remove':
            for event, group in expected.items():
                merged['hooks'].setdefault(event, []).append(group)
        desired = encode(merged) + b'\n'
        changed = merged != value
        before_manifest = manifest_path.read_bytes() if manifest_path.exists() else None
        try:
            if (path.read_bytes() if path.exists() else None) != original:
                raise ValueError('CONFIGURATION_CHANGED')
            if changed:
                if self.write_observer:
                    self.write_observer(path, desired)
                atomic_bytes(path, desired)
            if (manifest_path.read_bytes() if manifest_path.exists() else None) != before_manifest:
                raise ValueError('CONFIGURATION_CHANGED')
            if action == 'remove':
                if self.write_observer:
                    self.write_observer(manifest_path, None)
                manifest_path.unlink(missing_ok=True)
            else:
                new = dict(version='cursor-global-v1', records=expected)
                key = self.store.key(self.home)
                signed = encode({**new, 'signature': hmac.new(key, encode(new), hashlib.sha256).hexdigest()})
                if signed != before_manifest:
                    if self.write_observer:
                        self.write_observer(manifest_path, signed)
                    atomic_bytes(manifest_path, signed)
        except Exception:
            # Roll back our write only if no external editor changed it.
            if changed and path.exists() and path.read_bytes() == desired:
                if original is None:
                    path.unlink()
                else:
                    atomic_bytes(path, original)
            raise
        report.update(overall='REMOVED' if action == 'remove' else 'CONFIGURED', changed=changed)
        return report


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
