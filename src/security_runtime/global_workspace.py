"""Canonical global workspace admission and bounded bootstrap observations."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path, PureWindowsPath

from .hook_state import HookStateStore, atomic_bytes, identity, no_links
from .workspace import WorkspaceResolver
from .storage import SQLiteStore

WORKSPACE_REJECTIONS = {
    'WORKSPACE_CANONICALIZATION_MISMATCH', 'WORKSPACE_NOT_REGISTERED',
    'WORKSPACE_SESSION_BINDING_MISSING', 'WORKSPACE_OUTSIDE_ALLOWED_ROOT',
    'WORKSPACE_REFERENCE_STALE', 'WORKSPACE_LINK_REJECTED',
    'WORKSPACE_RESOLUTION_FAILED', 'WORKSPACE_CONFIGURATION_REJECTED',
    'WORKSPACE_ADMISSION_FAILED', 'WORKSPACE_SESSION_MISMATCH',
    'WORKSPACE_TOOL_REJECTED', 'INSTALLED_RUNTIME_REQUIRED',
    'GLOBAL_CONFIGURATION_NOT_READY', 'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR',
    'CONFIG_INVALID', 'OWNERSHIP_INVALID', 'MCP_CONFIGURATION_CONFLICT', 'POTENTIAL_DUPLICATE_MCP',
    'POTENTIAL_DUPLICATE_HOOK', 'WORKSPACE_CONNECTION_BUDGET_EXCEEDED',
    'SESSION_CONNECTION_BUDGET_EXCEEDED', 'TOOL_USE_CLAIM_REPLAYED',
    'HOST_CLAIM_BUDGET_EXCEEDED', 'RUNTIME_MISSING',
}
WORKSPACE_STAGES = {'RESOLVING_ROOT', 'VALIDATING_CONFIGURATION', 'ADMITTING_WORKSPACE',
                    'BINDING_SESSION', 'VALIDATING_INVOCATION', 'BOOTSTRAPPING',
                    'FORWARDING_TOOL', 'COMPLETE'}


def workspace_rejection(exc, stage):
    """Fixed reasons only; an integration error is not a path mismatch."""
    reason = getattr(exc, 'code', None) or str(exc)
    if reason in WORKSPACE_REJECTIONS:
        return reason
    if reason == 'Hook state/configuration links are not supported':
        return 'WORKSPACE_LINK_REJECTED'
    if reason in {'INVALID_WORKSPACE_CLAIM', 'WORKSPACE_DIRECTORY_REQUIRED'}:
        return 'WORKSPACE_CANONICALIZATION_MISMATCH'
    if reason in {'RUNTIME_STATE_IS_NOT_A_WORKSPACE', 'UNSAFE_WORKSPACE', 'WORKSPACE_BOUNDARY_REJECTED'}:
        return 'WORKSPACE_OUTSIDE_ALLOWED_ROOT'
    if reason == 'SESSION_WORKSPACE_MISMATCH':
        return 'WORKSPACE_SESSION_MISMATCH'
    return {'RESOLVING_ROOT': 'WORKSPACE_RESOLUTION_FAILED',
            'VALIDATING_CONFIGURATION': 'WORKSPACE_CONFIGURATION_REJECTED',
            'ADMITTING_WORKSPACE': 'WORKSPACE_ADMISSION_FAILED',
            'BINDING_SESSION': 'WORKSPACE_SESSION_BINDING_MISSING'}.get(stage, 'WORKSPACE_TOOL_REJECTED')


def resolve_workspace(value, *, excluded=()):
    raw = str(value) if isinstance(value, (str, Path)) else ''
    if (not raw.strip() or len(raw) > 4096 or '${' in raw or any(ord(c) < 32 for c in raw)
        or raw.startswith(('\\\\', '//')) or not Path(raw).is_absolute()
        or '..' in Path(raw).parts or (os.name != 'nt' and PureWindowsPath(raw).drive)):
        raise ValueError('INVALID_WORKSPACE_CLAIM')
    candidate = Path(raw)
    no_links(candidate)
    candidate = candidate.resolve(strict=True)
    no_links(candidate)
    forbidden = [SQLiteStore.default_path().parent.absolute(), *map(lambda p: Path(p).absolute(), excluded)]
    configured_home = os.getenv('SECURITY_RUNTIME_CODEX_HOME') or os.getenv('CODEX_HOME')
    forbidden.append(Path(configured_home).absolute() if configured_home else Path.home() / '.codex')
    if any(candidate == p or candidate.is_relative_to(p) for p in forbidden):
        raise ValueError('RUNTIME_STATE_IS_NOT_A_WORKSPACE')
    resolver = WorkspaceResolver()
    # Reject home/drive/system before Git or ancestor project discovery.
    if resolver._unsafe(candidate):
        raise ValueError('UNSAFE_WORKSPACE')
    if not candidate.is_dir():
        raise ValueError('WORKSPACE_DIRECTORY_REQUIRED')
    try:
        root = resolver.resolve(candidate).path
    except ValueError:
        # Bounded name-only layout discovery; no repository-wide traversal.
        root = None
        markers = {'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle',
                   'package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml'}
        for parent in (candidate, *list(candidate.parents)[:12]):
            if resolver._unsafe(parent):
                break
            related_src = (parent / 'src').is_dir() and (
                parent == candidate or candidate.is_relative_to(parent / 'src'))
            if any((parent / name).is_file() for name in markers) or related_src:
                no_links(parent)
                root = parent
                break
        if root is None:
            root = resolver.resolve(candidate, allow_non_git_source=True).path
    no_links(root)
    if resolver._unsafe(root):
        raise ValueError('UNSAFE_WORKSPACE')
    if not candidate.is_relative_to(root) or any(root == p or root.is_relative_to(p) or p.is_relative_to(root) for p in forbidden):
        raise ValueError('WORKSPACE_BOUNDARY_REJECTED')
    return root


def workspace_state(root, base=None):
    base = Path(base or SQLiteStore.default_path().parent / 'global-workspaces').absolute()
    no_links(base)
    if base.is_relative_to(root):
        raise ValueError('STATE_INSIDE_WORKSPACE')
    return base / identity(os.path.normcase(str(root)))


def source_snapshot(root, key):
    """Non-Git fallback only. No source survives this bounded snapshot call."""
    from .hook_runtime import MAX_FILES, MAX_BYTES, CapturedSnapshot
    from .target import TargetDetector
    profile = TargetDetector(max_files=MAX_FILES).detect(root, select_scan_targets=True)
    files = profile.files
    digest = hmac.new(key, b'global-non-git-snapshot-v1', hashlib.sha256)
    consumed = 0
    file_digests = {}
    for name in sorted(files):
        p = root / name
        no_links(p)
        digest.update(name.encode())
        before = p.stat()
        size = before.st_size
        consumed += size
        if size > 1_000_000 or consumed > MAX_BYTES:
            raise ValueError('SNAPSHOT_BUDGET_EXCEEDED')
        raw = p.read_bytes()
        after = p.stat()
        if (len(raw) != size or
                (before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError('SNAPSHOT_CHANGED')
        digest.update(hmac.new(key, raw, hashlib.sha256).digest())
        file_digests[name] = hmac.new(key, b'hook-file-v1' + raw, hashlib.sha256).hexdigest()
    from .target import selection_summary
    return CapturedSnapshot(digest.hexdigest(), sorted(files), file_digests, selection_summary(profile))


def write_bootstrap(root, status, baseline_status, *, base=None, reason_code=None,
                    session_id=None, recovered_from=None):
    from .codex_integration import fingerprint, product_hooks
    from .bootstrap_diagnostics import BASELINE_REASONS
    if any(code is not None and code not in BASELINE_REASONS for code in (reason_code, recovered_from)):
        raise ValueError('Invalid bootstrap diagnostic')
    directory = workspace_state(root, base)
    store = HookStateStore(directory / 'hooks')
    key = store.key(root)
    value = {'version': 'global-bootstrap-v1', 'workspace_id': identity(os.path.normcase(str(root))),
             'status': status, 'baseline_status': baseline_status,
             'observed_at': time.time(), 'hook_definition_hash': fingerprint(product_hooks()),
             'security_proof': False}
    if reason_code is not None:
        value['reason_code'] = reason_code
    if recovered_from is not None:
        value['recovered_from'] = recovered_from
    if session_id is not None:
        value['session_hash'] = identity(session_id)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    value['signature'] = hmac.new(key, raw, hashlib.sha256).hexdigest()
    atomic_bytes(directory / 'bootstrap.json', json.dumps(value, sort_keys=True).encode())


def read_bootstrap(root, *, base=None):
    from .codex_integration import fingerprint, product_hooks
    from .bootstrap_diagnostics import BASELINE_REASONS
    directory = workspace_state(root, base)
    path = directory / 'bootstrap.json'
    try:
        no_links(path)
        if not path.exists():
            return {'status': 'NEW_WORKSPACE', 'security_proof': False}
        if path.stat().st_size > 4096:
            raise ValueError()
        value = json.loads(path.read_bytes())
        signature = value.pop('signature')
        key_path = HookStateStore(directory / 'hooks').workspace_directory(root) / 'snapshot.key'
        no_links(key_path)
        key = key_path.read_bytes()
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        if (len(key) != 32 or not hmac.compare_digest(signature, hmac.new(key, raw, hashlib.sha256).hexdigest())
            or value['version'] != 'global-bootstrap-v1'
            or value['workspace_id'] != identity(os.path.normcase(str(root)))
            or value['hook_definition_hash'] != fingerprint(product_hooks())
            or value['status'] not in {'INITIALIZING', 'READY', 'DEGRADED', 'ERROR'}
            or value['security_proof'] is not False
            or any(value.get(field) is not None and value[field] not in BASELINE_REASONS
                   for field in ('reason_code', 'recovered_from'))
            or 'session_hash' in value and (not isinstance(value['session_hash'], str)
                or len(value['session_hash']) != 64 or any(c not in '0123456789abcdef' for c in value['session_hash']))
            or not 0 <= time.time() - value['observed_at'] <= 900):
            raise ValueError()
        return value
    except (ValueError, OSError, KeyError, TypeError, RecursionError):
        return {'status': 'DEGRADED', 'reason_code': 'BOOTSTRAP_OBSERVATION_STALE', 'security_proof': False}
