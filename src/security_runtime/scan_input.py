"""Bounded private scan views; source applicability is checked separately.

No provider may fall back to the live workspace when a view lacks a file.
This module captures bytes, not scanner coverage or repair authority.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import stat
import sys
import tempfile
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path

from .hook_state import native_io_path, no_links
from .progress import checkpoint
from .scan_request import ScanBinding, ScanInputError, ScanRequest, SourceKind, paths, relative_path

INPUT_CONTRACT = 'scan-input-v1'
# Leave room for source/rules and provider-generated report/config filenames.
# CreateProcess cwd and third-party native arguments do not share Python's
# extended-path filesystem support. Fail before writing private source bytes.
_PRIVATE_PATH_LIMIT = 236


def _check_private_path(path):
    if os.name == 'nt' and len(str(path)) > _PRIVATE_PATH_LIMIT:
        raise ScanInputError('SCAN_INPUT_PRIVATE_PATH_BUDGET')


def check_private_input_parent(parent):
    """Reserve the complete attempt plus provider subdirectory path budget."""
    _check_private_path(Path(parent) / ('i-' + '0' * 32) / ('i-' + '0' * 32))


def scoped_request(workspace, names, *, dependency_changes=None):
    """Adapter boundary: preserve real removed inputs without resurrecting bytes."""
    root = Path(workspace).resolve(strict=True)
    names = paths(tuple(names))
    no_links(root)
    present, absent = [], []
    for name in names:
        path = root / name
        no_links(path)
        if path.is_file():
            present.append(name)
        elif not path.exists():
            absent.append(name)
        else:
            raise ScanInputError('SCAN_INPUT_NOT_REGULAR')
    return ScanRequest(root, 'quick', SourceKind.WORKTREE, tuple(present),
        absent_files=tuple(absent), dependency_changes=None if dependency_changes is None
        else tuple(dependency_changes))


@dataclass(frozen=True)
class ScanInputLimits:
    files: int = 10_000
    bytes: int = 128_000_000
    file_bytes: int = 4_000_000
    index_bytes: int = 8_000_000

    def __post_init__(self):
        if any(type(value) is not int or value < 1 for value in
               (self.files, self.bytes, self.file_bytes, self.index_bytes)):
            raise ScanInputError('SCAN_INPUT_LIMIT_INVALID')


@dataclass(frozen=True)
class InputEntry:
    path: str
    role: str
    size: int
    content_id: str
    source_oid: str | None = None
    source_mode: str | None = None


@dataclass(frozen=True)
class InputApplicability:
    input_id: str
    source_kind: SourceKind
    state: str
    reason_code: str | None = None
    # CURRENT covers this input, never the entire project or provider proof.
    scope: str = 'CAPTURED_INPUT'


@dataclass
class _Lifetime:
    active: bool = True


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def _digest(key, raw):
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def _signature(info):
    # Windows Python's path stat can expose creation time while fstat exposes
    # change time through deprecated st_ctime. They are not comparable there.
    identity = info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    return identity if os.name == 'nt' else (*identity, info.st_ctime_ns)


def _read_file(path, maximum):
    """Reject links/replacements, and never read beyond the per-file allowance."""
    checkpoint()
    no_links(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ScanInputError('SCAN_INPUT_NOT_REGULAR')
    if before.st_size > maximum:
        raise ScanInputError('SCAN_INPUT_FILE_BUDGET')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(native_io_path(path), flags), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if _signature(before) != _signature(opened):
            raise ScanInputError('SCAN_INPUT_SOURCE_MOVING')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    no_links(path)
    if (len(raw) > maximum or len(raw) != before.st_size
            or _signature(before) != _signature(after)
            or _signature(before) != _signature(path.stat())):
        raise ScanInputError('SCAN_INPUT_SOURCE_MOVING')
    return raw


def _windows_private_directory(path):
    from .private_directories import windows_private_directory
    try:
        windows_private_directory(path)
    except FileExistsError:
        raise
    except OSError:
        raise ScanInputError('SCAN_INPUT_PRIVATE_DIRECTORY_UNAVAILABLE') from None


@contextmanager
def _private_directory(workspace, parent, *, on_created=None, on_removed=None):
    if parent is None and sys.platform == 'darwin':
        from .install_platform import temporary_parent
        parent = temporary_parent()
    else:
        parent = Path(parent) if parent is not None else Path(tempfile.gettempdir())
    no_links(parent)
    parent = parent.resolve(strict=True)
    if parent == workspace or parent.is_relative_to(workspace):
        raise ScanInputError('SCAN_INPUT_PRIVATE_DIRECTORY_IN_WORKSPACE')
    directory = None
    directory_identity = None
    try:
        for _ in range(8):
            candidate = parent / ('i-' + uuid.uuid4().hex)
            _check_private_path(candidate)
            try:
                if os.name == 'nt':
                    _windows_private_directory(candidate)
                else:
                    candidate.mkdir(mode=0o700)
                directory = candidate
                break
            except FileExistsError:
                continue
        if directory is None:
            raise ScanInputError('SCAN_INPUT_PRIVATE_DIRECTORY_UNAVAILABLE')
        no_links(directory)
        created = directory.stat()
        directory_identity = (created.st_dev, created.st_ino)
        if on_created is not None:
            on_created(directory)  # Durable cleanup intent before any raw bytes.
        yield directory
    finally:
        if directory is not None:
            no_links(directory)
            try:
                current = directory.stat()
            except FileNotFoundError:
                current = None
            if current is not None and directory_identity is not None and (current.st_dev, current.st_ino) != directory_identity:
                raise ScanInputError('SCAN_INPUT_PRIVATE_DIRECTORY_CHANGED')
            # Windows read-only source files still need deletion on normal exit.
            def remove_readonly(function, path, _):
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                function(path)
            if current is not None:
                try:
                    shutil.rmtree(native_io_path(directory), onexc=remove_readonly)
                except FileNotFoundError:
                    if directory.exists():
                        raise
            if on_removed is not None:
                on_removed(directory)


def _write(root, name, raw, *, readonly=True):
    target = root / relative_path(name)
    no_links(target)
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_BINARY', 0)
    with os.fdopen(os.open(native_io_path(target), flags, 0o600), 'wb') as stream:
        stream.write(raw)
    if readonly:
        target.chmod(stat.S_IREAD)


def _absent(root, names):
    for name in names:
        path = root / name
        no_links(path)
        if path.exists():
            raise ScanInputError('SCAN_INPUT_ABSENCE_CHANGED')


def _inventory(reader):
    return tuple(sorted(paths(tuple(reader()))))


def _view_files(root, limit):
    result = []
    visited = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        checkpoint()
        visited += len(directories) + len(files) + 1
        if visited > limit * 4 + 1:
            raise ScanInputError('SCAN_INPUT_VIEW_CHANGED')
        for name in (*directories, *files):
            no_links(Path(directory) / name)
        result.extend((Path(directory) / name).relative_to(root).as_posix() for name in files)
        if len(result) > limit:
            raise ScanInputError('SCAN_INPUT_VIEW_CHANGED')
    return tuple(sorted(result))


def _rule_files(root, limit):
    no_links(root)
    if not root.is_dir():
        raise ScanInputError('SCAN_INPUT_RULE_DIRECTORY_REQUIRED')
    result = []
    visited = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        checkpoint()
        # A rules directory may itself be adversarial; bound name-only walking.
        visited += len(directories) + len(files) + 1
        if visited > limit * 4:
            raise ScanInputError('SCAN_INPUT_RULE_INVENTORY_BUDGET')
        for name in directories:
            no_links(Path(directory) / name)
        for name in files:
            if (Path(name).suffix.lower() not in {'.yml', '.yaml'}
                    and name not in {'catalog.json', 'capabilities.json', 'LICENSE'}):
                continue
            result.append(relative_path((Path(directory) / name).relative_to(root).as_posix()))
            if len(result) > limit:
                raise ScanInputError('SCAN_INPUT_FILE_COUNT_BUDGET')
    return tuple(sorted(result))


def _index(git, limits):
    raw = git._run_bytes('ls-files', '--stage', '-z', maximum=limits.index_bytes)
    if len(raw) > limits.index_bytes:
        raise ScanInputError('SCAN_INPUT_INDEX_BYTE_BUDGET')
    entries = raw.split(b'\0')
    if len(entries) > limits.files + 1:
        raise ScanInputError('SCAN_INPUT_FILE_COUNT_BUDGET')
    values = {}
    try:
        for entry in entries:
            if not entry:
                continue
            metadata, name = entry.split(b'\t', 1)
            mode, oid, stage = metadata.decode('ascii').split(' ')
            name = relative_path(name.decode('utf-8'))
            if (stage != '0' or mode not in {'100644', '100755'} or
                    len(oid) not in {40, 64} or any(char not in '0123456789abcdef' for char in oid)):
                raise ValueError()
            if name in values:
                raise ValueError()
            values[name] = (mode, oid)
        paths(tuple(values))
    except (UnicodeError, ValueError):
        raise ScanInputError('SCAN_INPUT_INDEX_ENTRY_UNSUPPORTED') from None
    return raw, values


def index_inventory(git, *, limits=None):
    """Bounded name/OID selection anchor; no checkout or working-tree reads."""
    raw, values = _index(git, limits or ScanInputLimits())
    return tuple(values), hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CapturedScanInput:
    request: ScanRequest
    execution_root: Path
    input_id: str
    source_revision: str
    manifest: tuple[InputEntry, ...]
    rules_path: Path | None
    source_inventory: tuple[str, ...]
    contract: str = INPUT_CONTRACT
    _key: bytes = field(default=b'', repr=False, compare=False)
    _index_raw: bytes | None = field(default=None, repr=False, compare=False)
    _git: object = field(default=None, repr=False, compare=False)
    _inventory_reader: object = field(default=None, repr=False, compare=False)
    _limits: ScanInputLimits = field(default_factory=ScanInputLimits, repr=False, compare=False)
    _lifetime: _Lifetime = field(default_factory=_Lifetime, repr=False, compare=False)

    def _require_active(self):
        if not self._lifetime.active:
            raise ScanInputError('SCAN_INPUT_CLOSED')

    def assert_intact(self):
        """Detect changed view bytes; same-user plugins are not a sandbox."""
        self._require_active()
        expected = tuple(sorted(entry.path for entry in self.manifest if entry.role in {'TARGET', 'CONTEXT'}))
        if _view_files(self.execution_root, self._limits.files) != expected:
            raise ScanInputError('SCAN_INPUT_VIEW_CHANGED')
        if self.rules_path is not None:
            expected_rules = tuple(entry.path for entry in self.manifest if entry.role == 'RULES')
            if _view_files(self.rules_path, self._limits.files) != expected_rules:
                raise ScanInputError('SCAN_INPUT_VIEW_CHANGED')
        for entry in self.manifest:
            if entry.role == 'ABSENT':
                _absent(self.execution_root, (entry.path,))
                continue
            root = self.rules_path if entry.role == 'RULES' else self.execution_root
            raw = _read_file(root / entry.path, self._limits.file_bytes)
            if len(raw) != entry.size or not hmac.compare_digest(_digest(self._key, raw), entry.content_id):
                raise ScanInputError('SCAN_INPUT_VIEW_CHANGED')

    def validate_bindings(self, current):
        """Call with real execution-time identities, never with echoed claims."""
        self._require_active()
        if (not isinstance(current, tuple) or any(not isinstance(value, ScanBinding) for value in current)
                or sorted(current, key=lambda x: (x.kind, x.name)) !=
                sorted(self.request.bindings, key=lambda x: (x.kind, x.name))):
            raise ScanInputError('SCAN_INPUT_BINDING_CHANGED')

    @contextmanager
    def derive(self, names):
        """Writable provider transformations start only from captured bytes."""
        self._require_active()
        names = paths(tuple(names))
        available = {entry.path: entry for entry in self.manifest if entry.role in {'TARGET', 'CONTEXT'}}
        if not set(names).issubset(available):
            raise ScanInputError('SCAN_INPUT_DERIVATION_SCOPE_UNAVAILABLE')
        with _private_directory(self.request.workspace_root, self.execution_root.parent) as directory:
            for name in names:
                entry = available[name]
                raw = _read_file(self.execution_root / name, self._limits.file_bytes)
                if len(raw) != entry.size or _digest(self._key, raw) != entry.content_id:
                    raise ScanInputError('SCAN_INPUT_VIEW_CHANGED')
                _write(directory, name, raw, readonly=False)
            yield directory

    @contextmanager
    def artifacts(self):
        """Ephemeral provider reports/configs share the registered parent life.

        They are siblings of the fixed source, never part of its inventory or
        input identity. Protected creation and inode-checked cleanup use the
        same implementation as the input itself.
        """
        self._require_active()
        with _private_directory(self.request.workspace_root, self.execution_root.parent) as directory:
            yield directory

    def check_current(self):
        """Read-only source check; never grants freshness or coverage by itself."""
        try:
            self.assert_intact()
        except (OSError, ValueError, RuntimeError) as error:
            reason = 'SCAN_INPUT_CLOSED' if isinstance(error, ScanInputError) and error.reason_code == 'SCAN_INPUT_CLOSED' else 'SCAN_INPUT_VIEW_CHANGED'
            return InputApplicability(self.input_id, self.request.source_kind, 'UNVERIFIABLE', reason)
        try:
            _verify_source(self)
        except ScanInputError as error:
            return InputApplicability(self.input_id, self.request.source_kind, 'STALE', error.reason_code)
        except (OSError, ValueError, RuntimeError):
            return InputApplicability(self.input_id, self.request.source_kind, 'UNVERIFIABLE',
                                      'SCAN_INPUT_SOURCE_UNAVAILABLE')
        return InputApplicability(self.input_id, self.request.source_kind, 'CURRENT')

    @contextmanager
    def with_rules(self, source):
        """Finish the input before providers start, reusing the fixed source root.

        The caller chooses providers using captured bytes first. Deferred rule
        packs need no copy, and adding rules never recaptures workspace bytes.
        """
        self._require_active()
        if self.rules_path is not None:
            raise ScanInputError('SCAN_INPUT_RULES_ALREADY_CAPTURED')
        source = Path(source).resolve(strict=True)
        request = replace(self.request, rules_path=source)
        with _private_directory(request.workspace_root, self.execution_root.parent) as directory:
            rules = directory / 'rules'
            rules.mkdir(mode=0o700)
            entries = []
            consumed = sum(entry.size for entry in self.manifest)
            for name in _rule_files(source, self._limits.files):
                raw = _read_file(source / name, self._limits.file_bytes)
                consumed += len(raw)
                if consumed > self._limits.bytes:
                    raise ScanInputError('SCAN_INPUT_BYTE_BUDGET')
                if len(self.manifest) + len(entries) >= self._limits.files:
                    raise ScanInputError('SCAN_INPUT_FILE_COUNT_BUDGET')
                _write(rules, name, raw)
                entries.append(InputEntry(name, 'RULES', len(raw), _digest(self._key, raw)))
            revision = _digest(self._key, _encode(dict(source=self.source_revision,
                rules=[entry.__dict__ for entry in entries], contract=INPUT_CONTRACT)))
            extended = replace(self, request=request, rules_path=rules,
                manifest=(*self.manifest, *entries), source_revision=revision,
                input_id='si1-' + uuid.uuid4().hex)
            _verify_source(extended)
            extended.assert_intact()
            yield extended


def _verify_source(view):
    request = view.request
    if request.source_kind == SourceKind.INDEX:
        if _index(view._git, view._limits)[0] != view._index_raw:
            raise ScanInputError('SCAN_INPUT_INDEX_CHANGED')
    else:
        _absent(request.workspace_root, request.absent_files)
    if view._inventory_reader is not None and _inventory(view._inventory_reader) != view.source_inventory:
        raise ScanInputError('SCAN_INPUT_INVENTORY_CHANGED')
    rules = tuple(entry.path for entry in view.manifest if entry.role == 'RULES')
    if request.rules_path is not None and _rule_files(request.rules_path, view._limits.files) != rules:
        raise ScanInputError('SCAN_INPUT_RULES_CHANGED')
    for entry in view.manifest:
        checkpoint()
        if entry.role == 'ABSENT' or request.source_kind == SourceKind.INDEX and entry.role != 'RULES':
            continue
        root = request.rules_path if entry.role == 'RULES' else request.workspace_root
        raw = _read_file(root / entry.path, view._limits.file_bytes)
        if len(raw) != entry.size or not hmac.compare_digest(_digest(view._key, raw), entry.content_id):
            raise ScanInputError('SCAN_INPUT_SOURCE_CHANGED')


@contextmanager
def capture_scan_input(request, *, git=None, identity_key=None, private_parent=None,
                       limits=None, inventory_reader=None, on_created=None, on_removed=None):
    """Capture exact requested inputs; missing context never reads live later.

    A PROJECT caller supplies its bounded inventory reader to detect additions.
    Without one, applicability is deliberately scoped to the requested paths.
    Rules are a local rule-pack directory; only rule/catalog/license files are
    copied. Tool/database binaries stay outside the view and require actual
    execution-time binding validation by their adapters.
    """
    if not isinstance(request, ScanRequest):
        raise ScanInputError('SCAN_INPUT_REQUEST_INVALID')
    limits = limits or ScanInputLimits()
    if not isinstance(limits, ScanInputLimits):
        raise ScanInputError('SCAN_INPUT_LIMIT_INVALID')
    key = secrets.token_bytes(32) if identity_key is None else identity_key
    if not isinstance(key, bytes) or len(key) < 32:
        raise ScanInputError('SCAN_INPUT_IDENTITY_KEY_INVALID')
    no_links(request.workspace_root)
    root = request.workspace_root.resolve(strict=True)
    if root != request.workspace_root or not root.is_dir():
        raise ScanInputError('SCAN_INPUT_WORKSPACE_INVALID')
    source_inventory = (_inventory(inventory_reader) if inventory_reader is not None
                        else tuple(sorted(request.source_paths)))
    if len(source_inventory) > limits.files or len(request.source_paths) + len(request.absent_files) > limits.files:
        raise ScanInputError('SCAN_INPUT_FILE_COUNT_BUDGET')
    index_raw, index_values = None, {}
    if request.source_kind == SourceKind.INDEX:
        if git is None:
            from .git import GitService
            git = GitService(root)
        if Path(git.root).resolve() != root:
            raise ScanInputError('SCAN_INPUT_INDEX_WORKSPACE_MISMATCH')
        index_raw, index_values = _index(git, limits)
        if (request.selection_revision is not None
                and hashlib.sha256(index_raw).hexdigest() != request.selection_revision):
            raise ScanInputError('SCAN_INPUT_INDEX_CHANGED')
        if any(name in index_values for name in request.absent_files):
            raise ScanInputError('SCAN_INPUT_ABSENCE_CHANGED')
    else:
        _absent(root, request.absent_files)
    with _private_directory(root, private_parent, on_created=on_created, on_removed=on_removed) as directory:
        lifetime = _Lifetime()
        try:
            execution = directory / 'source'
            execution.mkdir(mode=0o700)
            rules = None
            manifest = []
            consumed = 0

            def retain(name, role, raw, *, oid=None, mode=None):
                nonlocal consumed
                if len(raw) > limits.file_bytes:
                    raise ScanInputError('SCAN_INPUT_FILE_BUDGET')
                consumed += len(raw)
                if consumed > limits.bytes:
                    raise ScanInputError('SCAN_INPUT_BYTE_BUDGET')
                if len(manifest) >= limits.files:
                    raise ScanInputError('SCAN_INPUT_FILE_COUNT_BUDGET')
                _write(rules if role == 'RULES' else execution, name, raw)
                manifest.append(InputEntry(name, role, len(raw), _digest(key, raw), oid, mode))
                try:
                    from .product_metrics import observe_input
                    observe_input(name, role, raw)
                except Exception:
                    pass  # Optional counts never change the captured input.

            for name in request.source_paths:
                checkpoint()
                role = 'TARGET' if name in request.files else 'CONTEXT'
                if request.source_kind == SourceKind.INDEX:
                    if name not in index_values:
                        raise ScanInputError('SCAN_INPUT_REQUIRED_FILE_MISSING')
                    mode, oid = index_values[name]
                    raw = git._run_bytes('cat-file', 'blob', oid, maximum=limits.file_bytes)
                    retain(name, role, raw, oid=oid, mode=mode)
                else:
                    try:
                        raw = _read_file(root / name, limits.file_bytes)
                    except FileNotFoundError:
                        raise ScanInputError('SCAN_INPUT_REQUIRED_FILE_MISSING') from None
                    retain(name, role, raw)
            for name in request.absent_files:
                manifest.append(InputEntry(name, 'ABSENT', 0, _digest(key, b'ABSENT')))
            if request.rules_path is not None:
                rules = directory / 'rules'
                rules.mkdir(mode=0o700)
                for name in _rule_files(request.rules_path, limits.files):
                    retain(name, 'RULES', _read_file(request.rules_path / name, limits.file_bytes))
            serialized = dict(contract=INPUT_CONTRACT, workspace=os.path.normcase(str(root)),
                source_kind=str(request.source_kind), mode=str(request.mode),
                inventory=source_inventory, dependencies=request.dependency_changes,
                entries=[entry.__dict__ for entry in manifest],
                bindings=[binding.__dict__ for binding in request.bindings],
                index_identity=_digest(key, index_raw) if index_raw is not None else None)
            view = CapturedScanInput(request, execution, 'si1-' + uuid.uuid4().hex,
                _digest(key, _encode(serialized)), tuple(manifest), rules, source_inventory,
                _key=key, _index_raw=index_raw, _git=git, _inventory_reader=inventory_reader,
                _limits=limits, _lifetime=lifetime)
            _verify_source(view)
            view.assert_intact()
        except ScanInputError:
            raise
        except (OSError, ValueError, RuntimeError):
            raise ScanInputError('SCAN_INPUT_CAPTURE_UNAVAILABLE') from None
        try:
            yield view
        finally:
            lifetime.active = False
