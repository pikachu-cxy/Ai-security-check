from __future__ import annotations

import os
import subprocess
import hashlib
import hmac
import json
import shlex
from enum import StrEnum
from pathlib import Path

from .workspace import WorkspaceResolver
from .hook_state import HookStateStore, atomic_bytes, no_links
from .storage import SQLiteStore


class HookEvent(StrEnum):
    SESSION_START = "SESSION_START"
    FILE_CHANGED = "FILE_CHANGED"
    AGENT_STOP = "AGENT_STOP"
    BEFORE_COMMAND = "BEFORE_COMMAND"
    BEFORE_MCP = "BEFORE_MCP"
    PRE_COMMIT = "PRE_COMMIT"


def gate_exit(result, policy):
    if result.release_status == 'BLOCKED':
        return 1
    if result.status == 'NO_CHANGES':
        return 0  # No index additions/modifications, not a repository verdict.
    complete = result.status == 'COMPLETED' and result.execution_state == 'EXECUTED' and result.coverage in {'FULL', 'SCOPED'}
    if not complete:
        return 2 if policy == 'strict' else 0
    return 0


def hook_path(root):
    proc = subprocess.run(["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root), "rev-parse", "--git-path", "hooks"], capture_output=True, text=True, timeout=5, check=True)
    hooks = Path(proc.stdout.strip())
    if not hooks.is_absolute():
        hooks = root / hooks
    destination = hooks / "pre-commit"
    no_links(destination)
    return destination


class GitHookManager:
    def __init__(self, root, *, directory=None, discover=None):
        self.root = WorkspaceResolver().resolve(root).path
        self.path = hook_path(self.root)
        self.store = HookStateStore(directory or SQLiteStore.default_path().parent / 'git-hooks')
        from .codex_integration import current_runtime
        self.discover = discover or current_runtime

    def _read(self, path):
        no_links(path)
        if not path.exists():
            return None
        if not path.is_file() or path.stat().st_size > 65536:
            raise ValueError('GIT_HOOK_FILE_INVALID')
        return path.read_bytes()

    def manifest(self):
        path = self.store.workspace_directory(self.root) / 'ownership.json'
        raw = self._read(path)
        if raw is None:
            return None
        try:
            value = json.loads(raw)
            signature = value.pop('signature')
            key = self._read(path.with_name('snapshot.key'))
            if (not key or len(key) != 32 or value['contract'] != 'git-pre-commit-v1'
                or value['path'] != str(self.path) or value['root'] != str(self.root)
                or not hmac.compare_digest(signature, hmac.new(key, json.dumps(value, sort_keys=True).encode(), hashlib.sha256).hexdigest())):
                raise ValueError()
            return value
        except (ValueError, TypeError, KeyError):
            raise ValueError('GIT_HOOK_OWNERSHIP_INVALID') from None

    def script(self, policy):
        runtime = self.discover()
        command = Path(runtime['command']).absolute()
        if not command.is_file() or any(ord(c) < 32 for c in str(command)):
            raise ValueError('GIT_HOOK_RUNTIME_MISSING')
        argv = [command.as_posix(), *runtime['prefix'], 'scan', '--mode', 'quick', '--staged', '--gate', policy, '--no-progress']
        return ('#!/bin/sh\n# AI Security Runtime managed pre-commit v1\n'
                + 'if [ ! -x ' + shlex.quote(argv[0]) + ' ]; then\n'
                + '  echo "AI Security Runtime unavailable: repair the owned Git hook after installing the Runtime." >&2\n'
                + '  exit 2\nfi\nexec ' + shlex.join(argv) + '\n').encode()

    def execute(self, action, policy='strict'):
        if action not in {'install', 'status', 'repair', 'remove'} or policy not in {'strict', 'report'}:
            raise ValueError('GIT_HOOK_ACTION_INVALID')
        raw = self._read(self.path)
        manifest = self.manifest()
        owned = manifest is not None and (raw is None or hashlib.sha256(raw).hexdigest() in
                                          {manifest['digest'], manifest.get('previous_digest')})
        if action == 'status':
            return {'status': 'INSTALLED' if owned and raw else 'REPAIR_REQUIRED' if owned else 'USER_MANAGED' if raw else 'NOT_INSTALLED',
                    'path': str(self.path), 'policy': manifest.get('policy') if manifest else None}
        with self.store.lock(self.root) as acquired:
            if not acquired:
                raise ValueError('GIT_HOOK_BUSY')
            if self._read(self.path) != raw:
                raise ValueError('GIT_HOOK_CONCURRENT_CHANGE')
            if self.manifest() != manifest:
                raise ValueError('GIT_HOOK_CONCURRENT_CHANGE')
            if raw is not None and not owned:
                raise ValueError('GIT_HOOK_USER_CONTENT_PRESERVED')
            receipt = self.store.workspace_directory(self.root) / 'ownership.json'
            if action == 'remove':
                if owned:
                    self.path.unlink(missing_ok=True)
                    receipt.unlink(missing_ok=True)
                return {'status': 'REMOVED' if owned else 'NOT_INSTALLED', 'path': str(self.path)}
            content = self.script(policy)
            value = {'contract': 'git-pre-commit-v1', 'root': str(self.root), 'path': str(self.path),
                     'digest': hashlib.sha256(content).hexdigest(), 'policy': policy, 'phase': 'UPDATING',
                     'previous_digest': hashlib.sha256(raw).hexdigest() if raw is not None else None}
            key = self.store.key(self.root)
            signature = hmac.new(key, json.dumps(value, sort_keys=True).encode(), hashlib.sha256).hexdigest()
            # Signed intent is persisted first. A missing script is repairable;
            # a partial/different script is always preserved for user review.
            atomic_bytes(receipt, json.dumps(value | {'signature': signature}).encode())
            if self._read(self.path) != raw:
                raise ValueError('GIT_HOOK_CONCURRENT_CHANGE')
            atomic_bytes(self.path, content)
            self.path.chmod(self.path.stat().st_mode | 0o111)
            value.update(phase='COMMITTED', previous_digest=None)
            signature = hmac.new(key, json.dumps(value, sort_keys=True).encode(), hashlib.sha256).hexdigest()
            atomic_bytes(receipt, json.dumps(value | {'signature': signature}).encode())
            return {'status': 'INSTALLED', 'path': str(self.path), 'policy': policy}


def install_pre_commit(root: Path, *, policy='strict') -> Path:
    return Path(GitHookManager(root).execute('install', policy)['path'])
