"""Install-time derivation of a verified, private OpenGrep executable tree."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import stat
import tempfile

from .hook_state import HookStateStore, no_links
from .tasks.durable import SignedRecords


def _store(wrapper):
    root = wrapper.parent
    return SignedRecords(HookStateStore(root/'payload-state'), root, 'payload.db')


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink)


def _inventory(root, cache=None):
    no_links(root)
    files = {}
    total = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = Path(directory)/name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or path.is_junction():
                raise ValueError('OPENGREP_PAYLOAD_LINK')
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('OPENGREP_PAYLOAD_FILE')
            total += info.st_size
            if len(files) >= 2000 or total > 512_000_000:
                raise ValueError('OPENGREP_PAYLOAD_LIMIT')
            # Reuse only hashes established by this live manager. Inspect every
            # path on every call; ctime also catches equal-size/restored-mtime
            # rewrites. No persisted stat-only trust or user cache is accepted.
            previous = cache.get(str(path)) if cache is not None else None
            stamp = _stamp(info)
            if previous is not None and previous[0] == stamp:
                digest = previous[1]
            else:
                with path.open('rb') as stream:
                    if _stamp(os.fstat(stream.fileno())) != stamp:
                        raise ValueError('OPENGREP_PAYLOAD_CHANGED')
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                    if _stamp(os.fstat(stream.fileno())) != stamp or _stamp(path.stat()) != stamp:
                        raise ValueError('OPENGREP_PAYLOAD_CHANGED')
                if cache is not None:
                    if len(cache) >= 2000:
                        cache.clear()
                    cache[str(path)] = stamp, digest
            files[path.relative_to(root).as_posix()] = [info.st_size, stat.S_IMODE(info.st_mode), digest]
    return files


def resolve(wrapper, checksum, version, *, cache=None):
    """Never extract here. Verify exact contents including unexpected additions."""
    store = _store(wrapper)
    if not store.path.exists():
        return None
    record = store.read('active')
    if not record or record.get('wrapper') != checksum or record.get('version') != version:
        return None
    slot = record['slot']
    if not isinstance(slot, str) or not slot.startswith('payload-') or Path(slot).name != slot:
        raise ValueError('OPENGREP_PAYLOAD_RECORD')
    root = wrapper.parent/slot
    if _inventory(root, cache) != record['files']:
        raise ValueError('OPENGREP_PAYLOAD_CHANGED')
    entry = root/'opengrep.bin'
    if not entry.is_file():
        raise ValueError('OPENGREP_PAYLOAD_ENTRY')
    digest = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
    return entry, digest


def identity(path, manager):
    """Return None for ordinary executables, fail closed for managed payloads."""
    if not path.parent.name.startswith('payload-') or path.name != 'opengrep.bin':
        return None
    from .toolchain import sha256_file
    wrapper = manager.managed_path('opengrep')
    if path.parent.parent != wrapper.parent:
        raise ValueError('OPENGREP_PAYLOAD_LOCATION')
    checksum = sha256_file(wrapper)
    if checksum != manager.manifest('opengrep').sha256:
        raise ValueError('OPENGREP_WRAPPER_CHANGED')
    result = resolve(wrapper, checksum, manager.versions['opengrep'], cache=manager._payload_hash_cache)
    if result is None or result[0] != path:
        raise ValueError('OPENGREP_PAYLOAD_IDENTITY')
    return result[1]


def prepare(manager):
    """Only invoked during installation/preparation, never from scan or Stop."""
    from .toolchain import sha256_file, tool_environment, run_process, matches_version
    import sys
    if sys.platform != 'darwin':
        return {'status': 'NOT_APPLICABLE'}
    wrapper = manager.managed_path('opengrep')
    no_links(wrapper)
    expected = manager.manifest('opengrep').sha256
    if not wrapper.is_file() or sha256_file(wrapper) != expected:
        return {'status': 'NOT_APPLICABLE'}
    current = resolve(wrapper, expected, manager.versions['opengrep'])
    if current:
        return {'status': 'READY', 'reused': True}
    # A fresh cache prevents inheriting an untrusted user's extracted files.
    with tempfile.TemporaryDirectory(prefix='opengrep-derive-', dir=wrapper.parent) as temporary:
        temporary = Path(temporary)
        env = tool_environment(wrapper)
        env.update(XDG_CACHE_HOME=str(temporary), CACHE_DIR=str(temporary),
                   SEMGREP_ENABLE_VERSION_CHECK='0', OPENGREP_ENABLE_VERSION_CHECK='0')
        result = run_process([str(wrapper), '--version'], cwd=temporary, env=env, timeout=120, max_output=16000)
        source = temporary/'opengrep'/manager.versions['opengrep']
        if not source.exists():
            source = temporary/'opengrep'/('v'+manager.versions['opengrep'])
        if result.returncode or not matches_version(manager.versions['opengrep'], result.stdout) or not (source/'opengrep.bin').is_file():
            raise ValueError('OPENGREP_PAYLOAD_DERIVATION_FAILED')
        if sha256_file(wrapper) != expected:
            raise ValueError('OPENGREP_WRAPPER_CHANGED')
        files = _inventory(source)
        slot = Path(tempfile.mkdtemp(prefix='payload-', dir=wrapper.parent))
        try:
            shutil.copytree(source, slot, dirs_exist_ok=True)
            if _inventory(slot) != files:
                raise ValueError('OPENGREP_PAYLOAD_COPY_FAILED')
            record = dict(wrapper=expected, version=manager.versions['opengrep'], slot=slot.name, files=files)
            store = _store(wrapper)
            store.hooks.key(store.root)
            with store.transaction() as db:
                store._put(db, 'active', record)
        except BaseException:
            shutil.rmtree(slot)
            raise
    return {'status': 'READY', 'reused': False}
