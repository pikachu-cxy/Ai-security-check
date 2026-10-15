"""One owned JSON MCP subtree with signed identity and compare-before-write."""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path, PureWindowsPath

from .codex_integration import unique_json
from .hook_state import atomic_bytes, no_links


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


def related(name, entry):
    if name in {'ai-security-runtime', 'ai_security_runtime'}:
        return True
    if not isinstance(entry, dict):
        return False
    command, args = entry.get('command', ''), entry.get('args', [])
    return (isinstance(command, str) and PureWindowsPath(command).name.lower() in {'security-check', 'security-check.exe'}
            or isinstance(args, list) and 'security_runtime.cli' in args and 'mcp' in args)


class WriteTransaction:
    """Undo only bytes this operation actually wrote; preserve concurrent edits."""
    def __init__(self):
        self.writes = []
        self.created_directories = set()

    def observe(self, path, content):
        no_links(path)
        before = path.read_bytes() if path.exists() else None
        self.writes.append((path, before, content))
        parent = path.parent
        while not parent.exists() and parent != parent.parent:
            self.created_directories.add(parent)
            parent = parent.parent

    def rollback(self):
        clean = True
        for path, before, desired in reversed(self.writes):
            try:
                no_links(path)
                current = path.read_bytes() if path.exists() else None
                if current == before:
                    continue
                if current != desired:
                    clean = False
                    continue
                if before is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_bytes(path, before)
            except (OSError, ValueError):
                clean = False
        for directory in sorted(self.created_directories, key=lambda p: len(p.parts), reverse=True):
            try:
                no_links(directory)
                directory.rmdir()  # Only newly created, empty directories.
            except (OSError, ValueError):
                pass
        return clean


class OwnedJsonServer:
    def __init__(self, home, store, desired, *, observer=None):
        self.home, self.store, self.desired = home, store, desired
        self.path = home / 'mcp.json'
        self.manifest = store.workspace_directory(home) / 'mcp-ownership.json'
        self.observer = observer
        self.name = 'ai-security-runtime'

    def inspect(self):
        no_links(self.path)
        no_links(self.manifest)
        raw = self.path.read_bytes() if self.path.exists() else None
        if raw is not None and len(raw) > 262144:
            raise ValueError('CONFIG_INVALID')
        value = unique_json(raw) if raw is not None else {'mcpServers': {}}
        if not isinstance(value, dict) or not isinstance(value.get('mcpServers'), dict):
            raise ValueError('CONFIG_INVALID')
        ownership = self.manifest.read_bytes() if self.manifest.exists() else None
        record = None
        if ownership is not None:
            if len(ownership) > 64000:
                raise ValueError('OWNERSHIP_INVALID')
            signed = unique_json(ownership)
            signature = signed.pop('signature')
            key_path = self.store.workspace_directory(self.home) / 'snapshot.key'
            no_links(key_path)
            key = key_path.read_bytes()
            if (len(key) != 32 or set(signed) != {'contract', 'server'} or signed['contract'] != 'owned-json-mcp-v1'
                    or not isinstance(signature, str) or not hmac.compare_digest(signature,
                        hmac.new(key, encode(signed), hashlib.sha256).hexdigest())):
                raise ValueError('OWNERSHIP_INVALID')
            record = signed['server']
        servers = value['mcpServers']
        for name, entry in servers.items():
            if related(name, entry) and not (name == self.name and record is not None and entry == record):
                raise ValueError('UNOWNED_RUNTIME_MCP')
        return raw, value, ownership, record

    def status(self):
        _, value, _, record = self.inspect()
        return 'CONFIGURED' if record == self.desired and value['mcpServers'].get(self.name) == record else 'NEEDS_REPAIR' if record else 'NOT_INSTALLED'

    def write(self, path, before, desired):
        no_links(path)
        if (path.read_bytes() if path.exists() else None) != before:
            raise ValueError('CONFIGURATION_CHANGED')
        if before == desired:
            return
        if self.observer:
            self.observer(path, desired)
        if desired is None:
            path.unlink(missing_ok=True)
        else:
            atomic_bytes(path, desired)

    def execute(self, action):
        raw, value, ownership, record = self.inspect()
        desired = json.loads(json.dumps(value))
        if record is not None:
            desired['mcpServers'].pop(self.name, None)
        if action != 'remove':
            desired['mcpServers'][self.name] = self.desired
        self.write(self.path, raw, encode(desired)+b'\n' if desired != value else raw)
        signed = None
        if action != 'remove':
            data = dict(contract='owned-json-mcp-v1', server=self.desired)
            signed = encode({**data, 'signature': hmac.new(self.store.key(self.home), encode(data), hashlib.sha256).hexdigest()})
        self.write(self.manifest, ownership, signed)
