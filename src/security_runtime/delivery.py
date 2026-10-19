"""Version slots behind a stable frozen launcher; no in-place EXE replacement.

Local hashes verify package integrity, not publisher authenticity. Only explicit
delivery activation executes the supplied package's capability probe.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import stat
import copy
import posixpath
import re
from contextvars import ContextVar
from contextlib import contextmanager
from functools import wraps
from pathlib import Path, PurePosixPath

from .build_identity import STATE_SCHEMA
from .hook_state import HookStateStore, atomic_bytes, no_links
from .integration_lifecycle import IntegrationDiagnostic
from .install_progress import report_progress

CONTRACT = 'stable-delivery-v1'
EXE = 'security-check.exe' if os.name == 'nt' else 'security-check'
_verification_cache = ContextVar('delivery_verification', default=None)

if os.name == 'nt':
    import ctypes
    from ctypes import wintypes
    class _BasicInfo(ctypes.Structure):
        _fields_ = [('creation', ctypes.c_longlong), ('access', ctypes.c_longlong),
            ('write', ctypes.c_longlong), ('change', ctypes.c_longlong), ('attributes', wintypes.DWORD)]
    _kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    _kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _kernel.CreateFileW.restype = wintypes.HANDLE
    _kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _kernel.CloseHandle.argtypes = [wintypes.HANDLE]


def _change_time(path, info):
    # Windows st_ctime currently means creation time. FILE_BASIC_INFO ChangeTime
    # also detects same-length edits followed by restoration of last-write time.
    if os.name != 'nt':
        return info.st_ctime_ns
    handle = _kernel.CreateFileW(str(path), 0x80, 7, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError('Package identity cannot be read')
    try:
        basic = _BasicInfo()
        if not _kernel.GetFileInformationByHandleEx(handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)):
            raise OSError('Package identity cannot be read')
        if basic.attributes & 0x400:
            raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID')
        return basic.change
    finally:
        _kernel.CloseHandle(handle)


@contextmanager
def verification_session():
    """Reuse verified bytes only within one operation and unchanged file identities."""
    if _verification_cache.get() is not None:
        yield
        return
    token = _verification_cache.set({})
    try:
        yield
    finally:
        _verification_cache.reset(token)


def verified_operation(function):
    @wraps(function)
    def run(*args, **kwargs):
        with verification_session():
            return function(*args, **kwargs)
    return run


def bundle_link_name(name, target):
    """Only relative links inside the frozen dependency directory are allowed."""
    if (not isinstance(name, str) or not isinstance(target, str) or not target
            or not name.startswith('_internal/') or target.startswith('/')
            or any(c in name + target for c in ('\\', ':', '\x00', '\n', '\r'))
            or PurePosixPath(name).as_posix() != name or '..' in PurePosixPath(name).parts):
        raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID')
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
    if not resolved.startswith('_internal/'):
        raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID')
    return resolved


def package_inventory(bundle, *, allow_internal_links=False):
    """One bounded no-follow tree walk, instead of rechecking every ancestor."""
    no_links(bundle)
    rows, total = [], 0
    pending = [bundle]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                path = Path(entry.path)
                name = path.relative_to(bundle).as_posix()
                link = ''
                if entry.is_symlink():
                    if not allow_internal_links or os.name == 'nt':
                        raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID')
                    link = os.readlink(path)
                    bundle_link_name(name, link)
                    # Lexical and final containment are both needed for link chains.
                    try:
                        target = path.resolve(strict=True)
                    except (OSError, RuntimeError):
                        raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID') from None
                    if (not target.is_relative_to(bundle / '_internal')
                            or not (target.is_file() or target.is_dir())):
                        raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID')
                    no_links(target)
                elif (getattr(info, 'st_file_attributes', 0) & 0x400
                        or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
                    raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID')
                rows.append((name, info.st_mode, info.st_dev,
                    info.st_ino, info.st_size, info.st_mtime_ns, _change_time(path, info), link))
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                else:
                    total += info.st_size
                if len(rows) > 20_000 or total > 2_000_000_000:
                    raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID')
    return tuple(sorted(rows))


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def is_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def file_digest(path):
    no_links(path)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _valid_storage_contracts(value):
    return (isinstance(value, list) and len(value) <= 64
            and all(isinstance(item, str) and len(item) <= 96
                and re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*-v[1-9][0-9]*', item) for item in value)
            and len(set(value)) == len(value))


def _require_storage_compatibility(current, target):
    # Missing legacy metadata is unknown, never an assertion that the package
    # can read/write a newly introduced authority. Do not infer from semver or
    # inspect private state to relax this conservative downgrade boundary.
    required, available = current.get('storage_contracts'), target.get('storage_contracts')
    if required and (available is None or not set(required) <= set(available)):
        raise IntegrationDiagnostic('DELIVERY_STATE_SCHEMA_INCOMPATIBLE')


def package_metadata(bundle, *, _retry=True):
    bundle = Path(bundle).absolute()
    no_links(bundle)
    path = bundle / 'version.json'
    try:
        no_links(path)
        if path.stat().st_size > 2_000_000:
            raise ValueError()
        value = json.loads(path.read_bytes())
        identity = value.pop('build_id')
        files = value['files']
        links = value.get('links', {})
        if (not is_digest(identity) or hashlib.sha256(encode(value)).hexdigest() != identity
            or value['format'] != 'pyinstaller-onedir' or value['state_schema'] != STATE_SCHEMA
            or value['capability_contract'] != 'developer-guidance-v0.3'
            or value['launcher_contract'] != CONTRACT or type(value['source_dirty']) is not bool
            or not isinstance(value['source_commit'], str) or len(value['source_commit']) != 40
            or not isinstance(value['version'], str) or not isinstance(value['experience_contract'], str)
            or not isinstance(files, dict) or not 1 <= len(files) <= 10_000 or EXE not in files
            or not {'LICENSE', 'THIRD_PARTY_NOTICES.md', 'SOURCE_OFFER.md'}.issubset(files)
            or not isinstance(links, dict) or len(links) > 2_000
            or (links and value.get('bundle_link_contract') != 'internal-relative-v1')):
            raise ValueError()
        if 'storage_contracts' in value and not _valid_storage_contracts(value['storage_contracts']):
            raise ValueError()
        inventory = package_inventory(bundle, allow_internal_links=bool(links))
        cache = _verification_cache.get()
        cached = cache.get(str(bundle)) if cache is not None else None
        if cached and cached[0] == inventory:
            return copy.deepcopy(cached[1])
        actual_links = {r[0]: r[7] for r in inventory if stat.S_ISLNK(r[1])}
        if actual_links != links:
            raise ValueError()
        actual = {r[0] for r in inventory if stat.S_ISREG(r[1])}
        for name, digest in files.items():
            relative = PurePosixPath(name)
            if (not name or relative.is_absolute() or '..' in relative.parts or ':' in name or '\\' in name
                or relative.as_posix() != name or not is_digest(digest)):
                raise ValueError()
            target = bundle / name
            if name not in actual:
                raise ValueError()
            digest_value = hashlib.sha256()
            with target.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest_value.update(block)
            if digest_value.hexdigest() != digest:
                raise ValueError()
        if actual != set(files) | {'version.json'}:
            raise ValueError()
        if package_inventory(bundle, allow_internal_links=bool(links)) != inventory:
            if _retry:
                if cache is not None:
                    cache.pop(str(bundle), None)
                return package_metadata(bundle, _retry=False)
            raise ValueError()
        result = value | {'build_id': identity}
        if cache is not None:
            cache[str(bundle)] = (inventory, copy.deepcopy(result))
        return result
    except (ValueError, OSError, KeyError, TypeError, RecursionError):
        raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID') from None


def launcher_metadata(directory):
    """Accept the immutable legacy bootstrap or a checksum-verified tiny launcher."""
    directory = Path(directory)
    path = directory / 'launcher.json'
    if not path.exists():
        return package_metadata(directory)
    try:
        inventory = package_inventory(directory)
        if {r[0] for r in inventory} != {EXE, 'launcher.json'} or path.stat().st_size > 4096:
            raise ValueError()
        data = json.loads(path.read_bytes())
        if data['contract'] != 'native-launcher-v1' or file_digest(directory / EXE) != data['sha256']:
            raise ValueError()
        return {'build_id': data['sha256'], 'launcher_contract': CONTRACT}
    except (ValueError, OSError, KeyError, TypeError):
        raise IntegrationDiagnostic('DELIVERY_LAUNCHER_INVALID') from None


class StableDelivery:
    def __init__(self, root, *, probe=None):
        raw = Path(root)
        if (not raw.is_absolute() or '..' in raw.parts or raw in {Path.home(), Path(raw.anchor)}
            or str(root).startswith(('\\\\', '//')) or any(ord(c) < 32 for c in str(root))):
            raise IntegrationDiagnostic('DELIVERY_ROOT_INVALID')
        self.root = raw.absolute()
        no_links(self.root)
        self.store = HookStateStore(self.root / '.launcher-state')
        self.probe = probe

    def slot(self, identity):
        if not is_digest(identity):
            raise IntegrationDiagnostic('DELIVERY_POINTER_INVALID')
        path = self.root / 'versions' / identity / 'bundle'
        no_links(path)
        return path

    def pointer(self):
        path = self.root / 'active.json'
        no_links(path)
        if not path.exists():
            return None
        try:
            if path.stat().st_size > 4096:
                raise ValueError()
            value = json.loads(path.read_bytes())
            signature = value.pop('signature')
            key_path = self.store.workspace_directory(self.root) / 'snapshot.key'
            no_links(key_path)
            key = key_path.read_bytes()
            if (len(key) != 32 or value['contract'] != CONTRACT or value['root'] != str(self.root)
                or value['state_schema'] != STATE_SCHEMA or not is_digest(value['active'])
                or value['previous'] is not None and not is_digest(value['previous'])
                or not hmac.compare_digest(signature, hmac.new(key, encode(value), hashlib.sha256).hexdigest())):
                raise ValueError()
            return value
        except (ValueError, OSError, KeyError, TypeError):
            raise IntegrationDiagnostic('DELIVERY_POINTER_INVALID') from None

    def _switch(self, identity, previous, *, cleanup_ready=None):
        existing = self.pointer()
        if cleanup_ready is None:
            cleanup_ready = bool(existing and existing['active'] == identity and existing.get('cleanup_ready'))
        launcher = 'launcher-v2' if (self.root / 'launcher-v2/launcher.json').is_file() else 'launcher'
        value = {'contract': CONTRACT, 'root': str(self.root), 'active': identity, 'previous': previous,
                 'state_schema': STATE_SCHEMA, 'launcher': launcher,
                 'key_id': self.store.workspace_directory(self.root).name,
                 'manifest_sha256': file_digest(self.slot(identity) / 'version.json'),
                 'cleanup_ready': cleanup_ready}
        key = self.store.key(self.root)
        atomic_bytes(self.root / 'active.json', encode(value | {'signature': hmac.new(key, encode(value), hashlib.sha256).hexdigest()}))

    def _installed_metadata(self, identity):
        metadata = package_metadata(self.slot(identity))
        if metadata['build_id'] != identity:
            # A locally rehashed old package is still not the package pinned
            # by this signed slot identity. Never use it to lower the floor.
            raise IntegrationDiagnostic('DELIVERY_SLOT_CONFLICT')
        return metadata

    def _probe(self, bundle):
        if self.probe:
            return self.probe(bundle)
        from .codex_integration import probe_runtime
        from .trial import TrialProfile, isolated_environment
        with tempfile.TemporaryDirectory(prefix='runtime-delivery-probe-') as directory:
            # macOS's OS-owned /var temporary root aliases /private/var. Only
            # normalize this newly-created private directory; user configuration
            # paths still pass the original strict no-links validation.
            root = Path(directory)
            if sys.platform == 'darwin':
                root = root.resolve(strict=True)
            root = root / 'profile'
            TrialProfile(root).create()
            env = isolated_environment(root)
            env.update(SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_WORKSPACE='',
                       SECURITY_RUNTIME_INTEGRATION='codex', SECURITY_RUNTIME_MCP_SELF_TEST='1')
            return probe_runtime({'kind': 'FROZEN', 'command': str(bundle / EXE), 'prefix': []}, root / 'codex-home', env)

    @verified_operation
    def activate(self, bundle, *, progress=None):
        bundle = Path(bundle).absolute()
        report_progress(progress, 'PACKAGE_VERIFY')
        metadata = package_metadata(bundle)
        if bundle.is_relative_to(self.root) or self.root.is_relative_to(bundle):
            raise IntegrationDiagnostic('DELIVERY_SOURCE_OVERLAPS_INSTALLATION')
        with self.store.lock(self.root) as acquired:
            if not acquired:
                raise IntegrationDiagnostic('DELIVERY_BUSY')
            pointer = self.pointer()
            if pointer is not None:
                current = self._installed_metadata(pointer['active'])
                _require_storage_compatibility(current, metadata)
            identity = metadata['build_id']
            target = self.slot(identity)
            reused = target.exists()
            if not reused:
                report_progress(progress, 'COPY_RUNTIME')
                target.parent.mkdir(parents=True, exist_ok=True)
                # An interrupted copy stays inactive; explicit retry must not
                # overwrite a potentially running/externally modified slot.
                shutil.copytree(bundle, target, symlinks=True)
            report_progress(progress, 'VERIFY_INSTALLED')
            if package_metadata(target) != metadata:
                raise IntegrationDiagnostic('DELIVERY_SLOT_CONFLICT')
            report_progress(progress, 'CAPABILITY_CHECK')
            capability = self._probe(target)
            if capability.get('status') != 'OK':
                raise IntegrationDiagnostic('DELIVERY_CAPABILITY_MISMATCH')
            report_progress(progress, 'PREPARE_LAUNCHER')
            launcher = self.root / 'launcher'
            no_links(launcher)
            tiny = target / '_launcher/security-launcher.exe'
            if tiny.is_file():
                # Do not replace a running legacy executable. Give the tiny
                # launcher a new stable path when migrating an old bootstrap.
                if launcher.exists() and not (launcher / 'launcher.json').is_file():
                    launcher = self.root / 'launcher-v2'
                no_links(launcher)
                if not launcher.exists():
                    launcher.mkdir()
                    shutil.copy2(tiny, launcher / EXE)
                    atomic_bytes(launcher / 'launcher.json', encode({'contract': 'native-launcher-v1',
                        'sha256': metadata['files']['_launcher/security-launcher.exe']}))
            if not launcher.exists():
                shutil.copytree(target, launcher, symlinks=True)
            # The bootstrap bundle is immutable. Future upgrades never replace
            # its EXE; dispatch validates and invokes only signed version slots.
            launcher_metadata(launcher)
            if pointer is None or pointer['active'] != identity or pointer.get('launcher', 'launcher') != launcher.name:
                self._switch(identity, pointer['active'] if pointer else None)
            report_progress(progress, 'VERIFY_ACTIVATION')
            return self.status() | {'status': 'ACTIVATED', 'reconnect_required': True,
                                   'package_reused': reused, 'network_download': False,
                                   'publisher_authenticity': 'USER_SUPPLIED_PACKAGE_NOT_ATTESTED'}

    @verified_operation
    def cleanup(self, *, in_use=None):
        """Remove only verified historical slots after successful personal setup.

        Unknown/tampered contents and live slots are preserved. The caller's
        download ZIPs, extracted sources, launcher and scanner cache are out of scope.
        """
        from .delivery_processes import running_slot_builds
        removed, deferred, preserved = [], [], []
        bootstrap = 'NOT_APPLICABLE'
        with self.store.lock(self.root) as acquired:
            if not acquired:
                raise IntegrationDiagnostic('DELIVERY_BUSY')
            pointer = self.pointer()
            if not pointer:
                raise IntegrationDiagnostic('DELIVERY_NOT_ACTIVE')
            package_metadata(self.slot(pointer['active']))
            versions = self.root / 'versions'
            no_links(versions)
            busy = (in_use or running_slot_builds)(self.root)
            for directory in list(versions.iterdir()):
                if directory.name == pointer['active']:
                    continue
                if not is_digest(directory.name):
                    preserved.append(directory.name)
                    continue
                try:
                    no_links(directory)
                    candidate = self.slot(directory.name)
                    metadata = package_metadata(candidate)
                    if metadata['build_id'] != directory.name or set(p.name for p in directory.iterdir()) != {'bundle'}:
                        raise IntegrationDiagnostic('DELIVERY_SLOT_CONFLICT')
                    if busy is None or directory.name in busy:
                        deferred.append(directory.name)
                        continue
                    # Resolve and validate the exact narrow target before deletion.
                    resolved = directory.resolve()
                    if resolved.parent != versions.resolve() or not is_digest(resolved.name):
                        raise IntegrationDiagnostic('DELIVERY_ROOT_INVALID')
                    shutil.rmtree(resolved)
                    removed.append(directory.name)
                except (ValueError, OSError):
                    preserved.append(directory.name)
            previous = pointer['previous'] if pointer['previous'] in deferred or pointer['previous'] in preserved else None
            if previous != pointer['previous'] or pointer.get('cleanup_ready') is not True:
                self._switch(pointer['active'], previous, cleanup_ready=True)
            legacy = self.root / 'launcher'
            if pointer.get('launcher') == 'launcher-v2' and legacy.exists():
                try:
                    package_metadata(legacy)
                    if busy is None or '@legacy-launcher' in busy:
                        bootstrap = 'DEFERRED_IN_USE'
                    else:
                        no_links(legacy)
                        if legacy.resolve().parent != self.root.resolve() or legacy.name != 'launcher':
                            raise IntegrationDiagnostic('DELIVERY_ROOT_INVALID')
                        shutil.rmtree(legacy.resolve())
                        bootstrap = 'REMOVED'
                except (ValueError, OSError):
                    bootstrap = 'PRESERVED'
        return {'status': 'DEFERRED' if deferred else 'COMPLETED', 'removed_builds': removed,
                'deferred_builds': deferred, 'preserved_builds': preserved,
                'rollback_retention': False, 'legacy_bootstrap': bootstrap, 'scanner_cache_modified': False}

    def rollback(self):
        with self.store.lock(self.root) as acquired:
            if not acquired:
                raise IntegrationDiagnostic('DELIVERY_BUSY')
            pointer = self.pointer()
            if not pointer or not pointer['previous']:
                raise IntegrationDiagnostic('DELIVERY_ROLLBACK_UNAVAILABLE')
            current = self._installed_metadata(pointer['active'])
            previous = self._installed_metadata(pointer['previous'])
            if current['state_schema'] != previous['state_schema'] or previous['state_schema'] != STATE_SCHEMA:
                raise IntegrationDiagnostic('DELIVERY_STATE_SCHEMA_INCOMPATIBLE')
            _require_storage_compatibility(current, previous)
            if self._probe(self.slot(pointer['previous'])).get('status') != 'OK':
                raise IntegrationDiagnostic('DELIVERY_CAPABILITY_MISMATCH')
            self._switch(pointer['previous'], pointer['active'])
            return self.status() | {'status': 'ROLLED_BACK', 'reconnect_required': True,
                                   'ephemeral_authorizations_restored': False}

    @verified_operation
    def status(self):
        pointer = self.pointer()
        if pointer is None:
            return {'status': 'NOT_INSTALLED', 'root': str(self.root)}
        package = self._installed_metadata(pointer['active'])
        launcher = self.root / pointer.get('launcher', 'launcher')
        if launcher.name not in {'launcher', 'launcher-v2'} or launcher.parent != self.root:
            raise IntegrationDiagnostic('DELIVERY_POINTER_INVALID')
        launcher_metadata(launcher)
        return {'status': 'INSTALLED', 'root': str(self.root), 'active_build': package['build_id'],
                'previous_build': pointer['previous'], 'version': package['version'],
                'launcher': str(launcher / EXE), 'state_schema': STATE_SCHEMA,
                'storage_contracts': package.get('storage_contracts'),
                'running_connections': 'UNCHANGED_UNTIL_RECONNECT', 'scan_state_modified': False}


def stable_command(executable=None):
    """Infer only the rigid installed layout; never trust an env-provided path."""
    executable = Path(executable or sys.executable).absolute()
    if executable.parent.name != 'bundle' or len(executable.parents) < 4 or executable.parents[2].name != 'versions':
        return None
    identity = executable.parents[1].name
    if not is_digest(identity):
        return None
    delivery = StableDelivery(executable.parents[3])
    pointer = delivery.pointer()
    if pointer is None or identity not in {pointer['active'], pointer['previous']}:
        return None  # Candidate capability probe, not an active installation.
    launcher = delivery.root / pointer.get('launcher', 'launcher')
    if launcher.name not in {'launcher', 'launcher-v2'}:
        raise IntegrationDiagnostic('DELIVERY_POINTER_INVALID')
    launcher_metadata(launcher)
    return str(launcher / EXE)


def dispatch(*, progress=None):
    if not getattr(sys, 'frozen', False) or Path(sys.executable).parent.name != 'launcher':
        return None
    try:
        report_progress(progress, 'LAUNCHER_VERIFY')
        delivery = StableDelivery(Path(sys.executable).absolute().parents[1])
        pointer = delivery.pointer()
        if pointer is None:
            raise IntegrationDiagnostic('DELIVERY_NOT_ACTIVE')
        target = delivery.slot(pointer['active'])
        package_metadata(target)
        if progress is not None:
            # The active child owns feedback from here; no duplicate heartbeats.
            progress.close()
        return subprocess.run([str(target / EXE), *sys.argv[1:]], check=False).returncode
    except (ValueError, OSError):
        if progress is not None:
            progress.finish(False)
        print('security-check: DELIVERY_NOT_READY; inspect delivery status or restore a verified version.', file=sys.stderr)
        return 2


def cleanup_after_reconnect():
    """Only completed personal installs opt into maintenance at a real MCP start."""
    if (not getattr(sys, 'frozen', False) or sys.argv[1:] != ['mcp']
            or os.getenv('SECURITY_RUNTIME_MCP_SELF_TEST') == '1'):
        return
    executable = Path(sys.executable).absolute()
    if executable.parent.name != 'bundle' or len(executable.parents) < 4 or executable.parents[2].name != 'versions':
        return
    try:
        delivery = StableDelivery(executable.parents[3])
        pointer = delivery.pointer()
        if pointer and pointer.get('cleanup_ready') is True and pointer['active'] == executable.parents[1].name:
            if pointer['previous'] or (delivery.root / 'launcher-v2').exists() and (delivery.root / 'launcher').exists():
                delivery.cleanup()
    except (ValueError, OSError):
        # Maintenance never turns a verified connection into a fake success or
        # a startup failure. Explicit delivery cleanup reports deferred states.
        pass
