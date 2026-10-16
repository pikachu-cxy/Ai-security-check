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


def _git_metadata_target(path, *, prefix=''):
    """Read one bounded Git pointer, checking lexical and canonical links."""
    no_links(path)
    if not path.is_file() or not 0 < path.stat().st_size <= 4096:
        raise ValueError('INVALID_WORKTREE_METADATA')
    with path.open('rb') as source:
        raw = source.read(4097)
    text = raw.decode('utf-8')
    lines = text.splitlines()
    if (len(raw) > 4096 or len(lines) != 1 or not lines[0].startswith(prefix)):
        raise ValueError('INVALID_WORKTREE_METADATA')
    target = lines[0][len(prefix):]
    if (not target or any(ord(c) < 32 for c in target)
            or target.startswith(('\\\\', '//'))
            or (os.name != 'nt' and PureWindowsPath(target).drive)):
        raise ValueError('INVALID_WORKTREE_METADATA')
    target = Path(target)
    lexical = target if target.is_absolute() else path.parent / target
    no_links(lexical)
    canonical = lexical.resolve(strict=True)
    no_links(canonical)
    no_links(path)
    return canonical


def _codex_linked_worktree(candidate, home, forbidden):
    """Verify only home/worktrees/<id>/<repo>, never the state tree itself.

    Git's external administration record must point back to this exact .git
    file. A name, project marker, standalone repo or copied one-way pointer is
    insufficient. No commands, source traversal or registration writes occur.
    """
    try:
        relative = candidate.relative_to(home / 'worktrees')
        if len(relative.parts) < 2:
            return None
        root = home / 'worktrees' / relative.parts[0] / relative.parts[1]
        no_links(root)
        git_file = root / '.git'
        admin = _git_metadata_target(git_file, prefix='gitdir: ')
        common = _git_metadata_target(admin / 'commondir')
        if (not admin.is_dir() or not common.is_dir()
                or admin.parent != common / 'worktrees'
                or any(p == boundary or p.is_relative_to(boundary)
                       or boundary.is_relative_to(p)
                       for p in (admin, common) for boundary in forbidden)):
            return None
        if _git_metadata_target(admin / 'gitdir') != git_file:
            return None
        for metadata in (admin / 'HEAD', common / 'HEAD', common / 'config'):
            no_links(metadata)
            if not metadata.is_file():
                return None
        no_links(common / 'objects')
        if not (common / 'objects').is_dir():
            return None
        return root
    except (ValueError, OSError, UnicodeError, RuntimeError):
        return None


def resolve_workspace(value, *, excluded=(), codex_home=None):
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
    homes = list(dict.fromkeys(Path(p).absolute() for p in
                 (Path.home() / '.codex', configured_home, codex_home) if p is not None))
    containing = [home for home in homes if candidate == home or candidate.is_relative_to(home)]
    worktree_root = None
    if len(containing) == 1:
        worktree_root = _codex_linked_worktree(candidate, containing[0], forbidden + homes)
    # Explicit excludes and Runtime state are never exempted. Only the verified
    # project's containing Codex home can be omitted from this one admission.
    forbidden += [home for home in homes if worktree_root is None or home != containing[0]]
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
        if worktree_root is not None:
            raise ValueError('WORKSPACE_BOUNDARY_REJECTED') from None
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
    if (worktree_root is not None and root != worktree_root
            or not candidate.is_relative_to(root)
            or any(root == p or root.is_relative_to(p) or p.is_relative_to(root) for p in forbidden)):
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


def write_bootstrap(root, status, baseline_status, *, base=None):
    from .codex_integration import fingerprint, product_hooks
    directory = workspace_state(root, base)
    store = HookStateStore(directory / 'hooks')
    key = store.key(root)
    value = {'version': 'global-bootstrap-v1', 'workspace_id': identity(os.path.normcase(str(root))),
             'status': status, 'baseline_status': baseline_status,
             'observed_at': time.time(), 'hook_definition_hash': fingerprint(product_hooks()),
             'security_proof': False}
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    value['signature'] = hmac.new(key, raw, hashlib.sha256).hexdigest()
    atomic_bytes(directory / 'bootstrap.json', json.dumps(value, sort_keys=True).encode())


def read_bootstrap(root, *, base=None):
    from .codex_integration import fingerprint, product_hooks
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
            or not 0 <= time.time() - value['observed_at'] <= 900):
            raise ValueError()
        return value
    except (ValueError, OSError, KeyError, TypeError, RecursionError):
        return {'status': 'DEGRADED', 'reason_code': 'BOOTSTRAP_OBSERVATION_STALE', 'security_proof': False}
