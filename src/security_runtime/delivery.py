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
from pathlib import Path, PurePosixPath

from .build_identity import STATE_SCHEMA
from .hook_state import HookStateStore, atomic_bytes, no_links
from .integration_lifecycle import IntegrationDiagnostic

CONTRACT = 'stable-delivery-v1'
EXE = 'security-check.exe' if os.name == 'nt' else 'security-check'


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


def package_metadata(bundle):
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
        if (not is_digest(identity) or hashlib.sha256(encode(value)).hexdigest() != identity
            or value['format'] != 'pyinstaller-onedir' or value['state_schema'] != STATE_SCHEMA
            or value['capability_contract'] != 'developer-guidance-v0.3'
            or value['launcher_contract'] != CONTRACT or type(value['source_dirty']) is not bool
            or not isinstance(value['source_commit'], str) or len(value['source_commit']) != 40
            or not isinstance(value['version'], str) or not isinstance(value['experience_contract'], str)
            or not isinstance(files, dict) or not 1 <= len(files) <= 10_000 or EXE not in files
            or not {'LICENSE', 'THIRD_PARTY_NOTICES.md', 'SOURCE_OFFER.md'}.issubset(files)):
            raise ValueError()
        for name, digest in files.items():
            relative = PurePosixPath(name)
            if (not name or relative.is_absolute() or '..' in relative.parts or ':' in name or '\\' in name
                or relative.as_posix() != name or not is_digest(digest)):
                raise ValueError()
            target = bundle / name
            no_links(target)
            if not target.is_file() or file_digest(target) != digest:
                raise ValueError()
        actual, size = set(), 0
        for target in bundle.rglob('*'):
            no_links(target)
            if target.is_file():
                actual.add(target.relative_to(bundle).as_posix())
                size += target.stat().st_size
                if size > 2_000_000_000 or len(actual) > 10_001:
                    raise ValueError()
        if actual != set(files) | {'version.json'}:
            raise ValueError()
        return value | {'build_id': identity}
    except (ValueError, OSError, KeyError, TypeError, RecursionError):
        raise IntegrationDiagnostic('DELIVERY_PACKAGE_INVALID') from None


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

    def _switch(self, identity, previous):
        value = {'contract': CONTRACT, 'root': str(self.root), 'active': identity, 'previous': previous,
                 'state_schema': STATE_SCHEMA}
        key = self.store.key(self.root)
        atomic_bytes(self.root / 'active.json', encode(value | {'signature': hmac.new(key, encode(value), hashlib.sha256).hexdigest()}))

    def _probe(self, bundle):
        if self.probe:
            return self.probe(bundle)
        from .codex_integration import probe_runtime
        from .trial import TrialProfile, isolated_environment
        with tempfile.TemporaryDirectory(prefix='runtime-delivery-probe-') as directory:
            root = Path(directory) / 'profile'
            TrialProfile(root).create()
            env = isolated_environment(root)
            env.update(SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_WORKSPACE='',
                       SECURITY_RUNTIME_INTEGRATION='codex', SECURITY_RUNTIME_MCP_SELF_TEST='1')
            return probe_runtime({'kind': 'FROZEN', 'command': str(bundle / EXE), 'prefix': []}, root / 'codex-home', env)

    def activate(self, bundle):
        bundle = Path(bundle).absolute()
        metadata = package_metadata(bundle)
        if bundle.is_relative_to(self.root) or self.root.is_relative_to(bundle):
            raise IntegrationDiagnostic('DELIVERY_SOURCE_OVERLAPS_INSTALLATION')
        with self.store.lock(self.root) as acquired:
            if not acquired:
                raise IntegrationDiagnostic('DELIVERY_BUSY')
            pointer = self.pointer()
            identity = metadata['build_id']
            target = self.slot(identity)
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                # An interrupted copy stays inactive; explicit retry must not
                # overwrite a potentially running/externally modified slot.
                shutil.copytree(bundle, target)
            if package_metadata(target) != metadata:
                raise IntegrationDiagnostic('DELIVERY_SLOT_CONFLICT')
            capability = self._probe(target)
            if capability.get('status') != 'OK':
                raise IntegrationDiagnostic('DELIVERY_CAPABILITY_MISMATCH')
            launcher = self.root / 'launcher'
            no_links(launcher)
            if not launcher.exists():
                shutil.copytree(target, launcher)
            # The bootstrap bundle is immutable. Future upgrades never replace
            # its EXE; dispatch validates and invokes only signed version slots.
            package_metadata(launcher)
            if pointer is None or pointer['active'] != identity:
                self._switch(identity, pointer['active'] if pointer else None)
            return self.status() | {'status': 'ACTIVATED', 'reconnect_required': True,
                                   'publisher_authenticity': 'USER_SUPPLIED_PACKAGE_NOT_ATTESTED'}

    def rollback(self):
        with self.store.lock(self.root) as acquired:
            if not acquired:
                raise IntegrationDiagnostic('DELIVERY_BUSY')
            pointer = self.pointer()
            if not pointer or not pointer['previous']:
                raise IntegrationDiagnostic('DELIVERY_ROLLBACK_UNAVAILABLE')
            current = package_metadata(self.slot(pointer['active']))
            previous = package_metadata(self.slot(pointer['previous']))
            if current['state_schema'] != previous['state_schema'] or previous['state_schema'] != STATE_SCHEMA:
                raise IntegrationDiagnostic('DELIVERY_STATE_SCHEMA_INCOMPATIBLE')
            if self._probe(self.slot(pointer['previous'])).get('status') != 'OK':
                raise IntegrationDiagnostic('DELIVERY_CAPABILITY_MISMATCH')
            self._switch(pointer['previous'], pointer['active'])
            return self.status() | {'status': 'ROLLED_BACK', 'reconnect_required': True,
                                   'ephemeral_authorizations_restored': False}

    def status(self):
        pointer = self.pointer()
        if pointer is None:
            return {'status': 'NOT_INSTALLED', 'root': str(self.root)}
        package = package_metadata(self.slot(pointer['active']))
        package_metadata(self.root / 'launcher')
        return {'status': 'INSTALLED', 'root': str(self.root), 'active_build': package['build_id'],
                'previous_build': pointer['previous'], 'version': package['version'],
                'launcher': str(self.root / 'launcher' / EXE), 'state_schema': STATE_SCHEMA,
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
    package_metadata(delivery.root / 'launcher')
    return str(delivery.root / 'launcher' / EXE)


def dispatch():
    if not getattr(sys, 'frozen', False) or Path(sys.executable).parent.name != 'launcher':
        return None
    try:
        delivery = StableDelivery(Path(sys.executable).absolute().parents[1])
        pointer = delivery.pointer()
        if pointer is None:
            raise IntegrationDiagnostic('DELIVERY_NOT_ACTIVE')
        target = delivery.slot(pointer['active'])
        package_metadata(target)
        return subprocess.run([str(target / EXE), *sys.argv[1:]], check=False).returncode
    except (ValueError, OSError):
        print('security-check: DELIVERY_NOT_READY; inspect delivery status or restore a verified version.', file=sys.stderr)
        return 2
