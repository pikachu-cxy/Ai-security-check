"""Managed task source copies. Host activation and OS write isolation are separate."""
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import uuid

from .hook_state import HookStateStore, no_links
from .storage import SQLiteStore
from .tasks.durable import SignedRecords
from .tasks.closeout_queue import fingerprint
from .tasks.ownership import valid_owner
from .workspace import WorkspaceResolver

MAX_FILES = 10000
MAX_BYTES = 64_000_000
EXCLUDED = frozenset({'.git', '.codex', '.cursor', '.security-runtime', '.venv', 'node_modules',
    '__pycache__', '.pytest_cache', 'dist', 'build', '.workbuddy', '.aws', '.ssh'})


def registry():
    base = SQLiteStore.default_path().parent / 'task-workspaces'
    return SignedRecords(HookStateStore(base/'keys'), base, 'workspaces.db')


def root_key(root):
    return hashlib.sha256(os.path.normcase(str(root)).encode()).hexdigest()


def snapshot(root):
    """Bounded complete copy of supported regular project files; no linked bytes."""
    files, excluded, total, directories = {}, [], 0, 0
    for directory, children, names in os.walk(root, followlinks=False):
        directories += 1
        if directories > 2000:
            raise ValueError('Workspace seed directory limit exceeded')
        children.sort()
        names.sort()
        for name in list(children):
            path = Path(directory)/name
            if name in EXCLUDED or name.startswith('.test-tmp'):
                children.remove(name)
                if name != '.git':
                    excluded.append(path.relative_to(root).as_posix()+'/')
            else:
                no_links(path)
        for name in names:
            path = Path(directory)/name
            relative = path.relative_to(root).as_posix()
            if name == '.git':
                continue
            if name == '.env' or name.startswith('.env.') or name.endswith(('.pem', '.key')):
                excluded.append(relative)
                continue
            no_links(path)
            before = path.stat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError('Workspace seed contains a linked or non-regular file')
            if len(files) >= MAX_FILES or before.st_size > 8_000_000 or total+before.st_size > MAX_BYTES:
                raise ValueError('Workspace seed size limit exceeded')
            with path.open('rb') as stream:
                raw = stream.read(min(8_000_001, MAX_BYTES-total+1))
            after = path.stat()
            if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError('Workspace changed during initialization')
            total += len(raw)
            if len(raw) != before.st_size or total > MAX_BYTES:
                raise ValueError('Workspace changed during initialization')
            files[relative] = (raw, bool(before.st_mode & stat.S_IXUSR))
    return files, excluded


def manifest(files):
    return {name:dict(sha256=hashlib.sha256(raw).hexdigest(), executable=executable)
            for name, (raw, executable) in files.items()}


def _git(root, *args):
    # No shell, hooks, worktree checkout filters or fsmonitor execution.
    command = ['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
               '-c', 'core.hooksPath=', '-C', str(root), *args]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError('Managed worktree Git operation failed')
    return result.stdout.decode('utf-8').strip()


def prepare(workspace, task_key, owner):
    if not valid_owner(owner) or not isinstance(task_key, str) or not 1 <= len(task_key) <= 200:
        raise ValueError('Workspace preparation requires an owner and short task key')
    resolved = WorkspaceResolver().resolve(workspace, allow_non_git_explicit=True)
    root = resolved.path
    store = registry()
    store.hooks.key(store.root)
    key = 'request:'+fingerprint(dict(root=str(root), owner=owner, task_key=task_key))
    with store.transaction() as db:
        prior = store._get(db, key)
        if prior:
            return view(prior, owner)
        ref = 'wi1-'+uuid.uuid4().hex
        base = root.parent/(root.name+'.security-workspaces')
        no_links(base)
        target = base/ref
        row = store._put(db, key, dict(isolation_ref=ref, origin_root=str(root),
            execution_root=str(target), prepared_by=owner, task_key=task_key,
            state='PREPARING', created_at=store.now(), kind='WORKTREE' if resolved.is_git else 'SOURCE_COPY',
            task_ref=None, claimed_by=None))
    try:
        files, excluded = snapshot(root)
        seed = manifest(files)
        no_links(base)
        if not base.exists():
            try:
                if os.name == 'nt':
                    from .private_directories import windows_private_directory
                    windows_private_directory(base)
                else:
                    base.mkdir(mode=0o700)
            except FileExistsError:
                no_links(base)
        if os.name == 'nt':
            from .private_directories import windows_private_directory
            windows_private_directory(target)
        else:
            target.mkdir(mode=0o700)
        if resolved.is_git:
            commit = _git(root, 'rev-parse', '--verify', 'HEAD')
            _git(root, 'worktree', 'add', '--detach', '--no-checkout', str(target), commit)
            _git(target, 'read-tree', commit)
        else:
            commit = None
        for name, (raw, executable) in files.items():
            path = target/name
            no_links(path)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(raw)
            if executable and os.name != 'nt':
                path.chmod(0o700)
        verified, omitted = snapshot(root)
        if manifest(verified) != seed or omitted != excluded:
            raise ValueError('Source changed while preparing worktree')
        actual, _ = snapshot(target)
        if manifest(actual) != seed:
            raise ValueError('Prepared workspace differs from seed')
        info = target.stat()
        with store.transaction() as db:
            row = store._put(db, key, dict(row, state='PREPARED', seed=seed,
                seed_revision=fingerprint(seed), exclusions=excluded, origin_commit=commit,
                directory_identity=[info.st_dev, info.st_ino]))
            store._put(db, 'root:'+root_key(target), dict(request_key=key))
        return view(row, owner)
    except Exception:
        with store.transaction() as db:
            store._put(db, key, dict(row, state='PREPARATION_FAILED', reason='INITIALIZATION_UNAVAILABLE'))
        raise


def view(row, owner):
    if row['prepared_by'] != owner:
        raise ValueError('Workspace preparation owner mismatch')
    return {**{k:row.get(k) for k in ('isolation_ref', 'state', 'execution_root', 'kind',
        'seed_revision', 'exclusions', 'task_ref', 'reason')},
        'source_isolation':'ISOLATED_DIRECTORY' if row['state'] in {'PREPARED', 'ACTIVE'} else 'NOT_READY',
        'host_activation':'OPEN_TARGET_WORKSPACE_REQUIRED', 'write_boundary':'HOST_ENFORCEMENT_UNSUPPORTED',
        'automatic_host_switch':False, 'baseline_created':bool(row.get('task_ref'))}


def _entry(store, db, root):
    pointer = store._get(db, 'root:'+root_key(root))
    return store._get(db, pointer['request_key']) if pointer else None


def admit(root, owner, task_key, setup_ref):
    """Claim a prepared directory BEFORE baseline capture; never resume by recapture."""
    store = registry()
    if not store.path.exists():
        return
    # Only registered directories enter a write transaction.
    if not store.read('root:'+root_key(root)):
        return
    if not valid_owner(owner):
        raise ValueError('Managed workspace requires an explicit task owner')
    with store.transaction() as db:
        row = _entry(store, db, root)
        if row['claimed_by'] is not None:
            raise ValueError('Managed directory already bound; resume its original task, never rebuild baseline')
        if row['state'] != 'PREPARED' or row['isolation_ref'] != setup_ref or row['task_key'] != task_key:
            raise ValueError('Prepared workspace activation reference required')
        no_links(root)
        info = root.stat()
        if [info.st_dev, info.st_ino] != row['directory_identity']:
            raise ValueError('Prepared workspace directory replaced')
        current, _ = snapshot(root)
        if manifest(current) != row['seed']:
            raise ValueError('Prepared workspace edited before original task baseline')
        store._put(db, row['key'], dict(row, state='CLAIMING', claimed_by=owner))
        return dict(isolation_ref=row['isolation_ref'], seed_revision=row['seed_revision'],
                    origin_root=row['origin_root'], mode='ISOLATED_DIRECTORY',
                    host_write_sandbox=False, exclusions=row['exclusions'])


def validate_binding(root, record):
    if not record.get('workspace_isolation'):
        return
    store = registry()
    pointer = store.read('root:'+root_key(root))
    row = store.read(pointer['request_key']) if pointer else None
    no_links(root)
    info = root.stat()
    if (not row or row['claimed_by'] != record.get('task_owner')
            or row.get('task_ref') not in {None, record['task_ref']}
            or [info.st_dev, info.st_ino] != row['directory_identity']):
        raise ValueError('Original isolated workspace unavailable; never rebuild baseline')


def bind(root, record):
    store = registry()
    if not store.path.exists() or not store.read('root:'+root_key(root)):
        return
    with store.transaction() as db:
        row = _entry(store, db, root)
        if row['claimed_by'] != record.get('task_owner') or row.get('task_ref') not in {None, record['task_ref']}:
            raise ValueError('Managed workspace task binding mismatch')
        store._put(db, row['key'], dict(row, state='ACTIVE', task_ref=record['task_ref']))


def capability():
    return dict(contract='task-workspace-isolation-v1', git_worktrees=True, non_git_copies=True,
        seed_includes_dirty_files=True, baseline_reconstruction=False,
        automatic_host_switch=False, host_write_sandbox=False,
        merge_automation=False, activation='OPEN_TARGET_AND_BEGIN_WITH_SETUP_REF')
