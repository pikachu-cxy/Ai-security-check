"""Bounded project profiling based primarily on names and manifests."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Iterable

from .models import TargetProfile
from .dependency_inputs import DEPENDENCIES


EXTENSIONS = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".vue": "Vue", ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".php": "PHP"}
from .rule_catalog import EXTENSIONS as RULE_EXTENSIONS
for _language, _extensions in RULE_EXTENSIONS.items():
    for _extension in _extensions - {'*'}:
        EXTENSIONS.setdefault(_extension, _language.title())
IGNORED = {".git", ".venv", "venv", "env", ".tools", ".security-runtime", "node_modules", ".idea", ".vscode", "dist", "build", "target", "coverage", ".cache", ".pytest_cache", ".mypy_cache", "__pycache__", ".next", ".nuxt", "vendor"}
MAX_FILES = 10_000
MAX_DIRECTORIES = 2_000
MAX_DEPTH = 32
MAX_FILE_SIZE = 1_000_000
CONFIG_MAX_BYTES = 65_536
LIMIT_SETTINGS = {
    'max_files': 'SECURITY_RUNTIME_MAX_FILES',
    'max_directories': 'SECURITY_RUNTIME_MAX_DIRECTORIES',
    'max_depth': 'SECURITY_RUNTIME_MAX_DEPTH',
    'max_file_size': 'SECURITY_RUNTIME_MAX_FILE_SIZE',
}

# Only formats for which this Runtime has no document/content analyzer. Match
# both extension and bounded magic bytes: a text credential file named .docx
# still belongs to Secret scanning. Archives/JARs and arbitrary binary inputs
# are not globally excluded; providers may have their own supported analyzers.
BINARY_DOCUMENTS = {
    '.docx': (b'PK\x03\x04',), '.xlsx': (b'PK\x03\x04',), '.pptx': (b'PK\x03\x04',),
    '.odt': (b'PK\x03\x04',), '.ods': (b'PK\x03\x04',), '.odp': (b'PK\x03\x04',),
    '.pdf': (b'%PDF-',), '.png': (b'\x89PNG\r\n\x1a\n',),
    '.jpg': (b'\xff\xd8\xff',), '.jpeg': (b'\xff\xd8\xff',),
    '.gif': (b'GIF87a', b'GIF89a'), '.bmp': (b'BM',),
    '.ico': (b'\x00\x00\x01\x00',), '.woff': (b'wOFF',), '.woff2': (b'wOF2',),
}


def selection_summary(profile, limit=20):
    """Bounded display; the complete relative-path ledger stays in the snapshot."""
    from .diagnostics import sanitize
    files = profile.get('files', []) if isinstance(profile, dict) else profile.files
    skipped = profile.get('skipped_files', []) if isinstance(profile, dict) else profile.skipped_files
    return {'policy': 'bounded-target-selection-v1', 'selected_files': len(files),
            'excluded_count': len(skipped), 'exclusions_truncated': len(skipped) > limit,
            'excluded_files': [{'path': sanitize(row['path'], 300), 'reason': row['reason'],
                                'source': row['source'], 'size_bytes': row['size_bytes']}
                               for row in skipped[:limit]],
            'notice': 'Excluded binary document contents were not inspected; exclusions are not clean findings.'}


class DiscoveryLimitError(ValueError):
    def __init__(self, detail: str, *, code='TARGET_DISCOVERY_LIMIT_EXCEEDED', relative_path=None,
                 limit=None, limit_kind=None, observed=None, observed_is_lower_bound=False):
        super().__init__(f"Scan target discovery failed. {detail}")
        self.detail = detail
        self.code, self.relative_path, self.limit = code, relative_path, limit
        self.limit_kind, self.observed = limit_kind, observed
        self.observed_is_lower_bound = observed_is_lower_bound

    def to_dict(self):
        from .diagnostics import sanitize
        result = {'status': 'INCONCLUSIVE', 'reason_code': self.code,
                  'failure_stage': 'TARGET_DISCOVERY', 'coverage': 'UNKNOWN',
                  'scanner_run': False, 'source_modified': False, 'security_proof': False,
                  'message': sanitize(str(self)), 'detail': sanitize(self.detail),
                  'remediation': 'Correct the user scan-limits.toml or discovery environment settings, then retry. No vulnerability rules were executed.'}
        if self.relative_path is not None:
            result['relative_path'] = sanitize(self.relative_path, 300)
        if self.limit is not None:
            result['limit'] = self.limit
        if self.limit_kind is not None:
            result['limit_kind'] = self.limit_kind
            result['configuration'] = {
                'environment_variable': LIMIT_SETTINGS[self.limit_kind],
                'file_key': 'discovery.' + self.limit_kind,
            }
            result['remediation'] = (
                f"Review the requested scope or adjust {LIMIT_SETTINGS[self.limit_kind]} "
                f"or discovery.{self.limit_kind} in the user scan-limits.toml, then retry. "
                "No vulnerability rules were executed.")
        if self.observed is not None:
            result['observed'] = self.observed
            result['observed_is_lower_bound'] = self.observed_is_lower_bound
        return result


def _config_error(detail):
    return DiscoveryLimitError(detail, code='TARGET_DISCOVERY_CONFIG_INVALID')


def discovery_config() -> dict:
    """Read only user configuration, never a file chosen by the scanned project."""
    from .storage import SQLiteStore
    configured = os.getenv('SECURITY_RUNTIME_SCAN_LIMITS_FILE')
    path = Path(configured) if configured is not None else SQLiteStore.default_path().parent / 'scan-limits.toml'
    if configured is not None and (not configured or not path.is_absolute()):
        raise _config_error('SECURITY_RUNTIME_SCAN_LIMITS_FILE must be an absolute file path.')
    try:
        with path.open('rb') as stream:
            content = stream.read(CONFIG_MAX_BYTES + 1)
    except FileNotFoundError:
        if configured is None:
            return {}
        raise _config_error('The configured SECURITY_RUNTIME_SCAN_LIMITS_FILE does not exist.') from None
    except OSError:
        raise _config_error('The user scan-limits.toml could not be read. Check its path and permissions.') from None
    if len(content) > CONFIG_MAX_BYTES:
        raise _config_error(f'The user scan-limits.toml exceeds {CONFIG_MAX_BYTES} bytes.')
    try:
        document = tomllib.loads(content.decode('utf-8'))
    except (ValueError, UnicodeError):
        raise _config_error('The user scan-limits.toml must contain valid UTF-8 TOML.') from None
    settings = document.get('discovery', {})
    if set(document) - {'discovery'} or not isinstance(settings, dict) or set(settings) - set(LIMIT_SETTINGS):
        raise _config_error('scan-limits.toml accepts only [discovery] with max_files, max_directories, max_depth and max_file_size.')
    for name, value in settings.items():
        if type(value) is not int or value < 1:
            raise _config_error(f'discovery.{name} must be a positive integer.')
    return settings


def _limit(name: str, default: int, configured: dict, override=None) -> int:
    key = name.lower()
    environment = LIMIT_SETTINGS[key]
    raw = os.getenv(environment)
    if override is not None:
        value = override
    elif raw is not None:
        try:
            value = int(raw)
        except ValueError:
            raise _config_error(f'{environment} must be a positive integer.') from None
    else:
        value = configured.get(key, default)
    if type(value) is not int or value < 1:
        raise _config_error(f'{environment} / discovery.{key} must be a positive integer.')
    return value


class TargetDetector:
    def __init__(self, *, max_files: int | None = None, max_directories: int | None = None,
                 max_depth: int | None = None, max_file_size: int | None = None,
                 ignored_dirs: Iterable[str] = ()):
        configured = discovery_config()
        self.max_files = _limit("MAX_FILES", MAX_FILES, configured, max_files)
        self.max_directories = _limit("MAX_DIRECTORIES", MAX_DIRECTORIES, configured, max_directories)
        self.max_depth = _limit("MAX_DEPTH", MAX_DEPTH, configured, max_depth)
        self.max_file_size = _limit("MAX_FILE_SIZE", MAX_FILE_SIZE, configured, max_file_size)
        self.ignored = IGNORED | set(ignored_dirs) | {name.strip() for name in os.getenv("SECURITY_RUNTIME_EXCLUDE_DIRS", "").split(",") if name.strip()}
        if min(self.max_files, self.max_directories, self.max_depth, self.max_file_size) < 1:
            raise ValueError("Discovery limits must be positive")

    def detect(self, root: Path, files: list[str] | None = None, *, select_scan_targets=False) -> TargetProfile:
        root = root.resolve(strict=True)
        explicit = files is not None
        if files is None:
            files = []
            directory_count = 0
            def walk_error(error: OSError) -> None:
                raise ValueError(f"Cannot inspect project directory: {error.filename}") from error

            for directory, subdirs, names in os.walk(root, onerror=walk_error):
                directory_count += 1
                depth = len(Path(directory).relative_to(root).parts)
                subdirs[:] = [name for name in subdirs if name not in self.ignored
                              and not (Path(directory) / name).is_symlink()
                              and not (Path(directory) / name).is_junction()]
                if depth >= self.max_depth and subdirs:
                    child = (Path(directory) / subdirs[0]).relative_to(root).as_posix()
                    raise DiscoveryLimitError(f"Detected directories deeper than {self.max_depth} levels.",
                                              relative_path=child, limit=self.max_depth, limit_kind='max_depth',
                                              observed=depth + 1, observed_is_lower_bound=True)
                if directory_count + len(subdirs) > self.max_directories:
                    raise DiscoveryLimitError(f"Detected more than {self.max_directories} directories.",
                                              relative_path=Path(directory).relative_to(root).as_posix(),
                                              limit=self.max_directories, limit_kind='max_directories',
                                              observed=directory_count + len(subdirs), observed_is_lower_bound=True)
                if len(files) + len(names) > self.max_files:
                    raise DiscoveryLimitError(f"Detected more than {self.max_files} files.",
                                              relative_path=Path(directory).relative_to(root).as_posix(),
                                              limit=self.max_files, limit_kind='max_files',
                                              observed=len(files) + len(names), observed_is_lower_bound=True)
                files.extend((Path(directory) / name).relative_to(root).as_posix() for name in names)
        else:
            files = [name for name in files if not set(Path(name).parts) & self.ignored]
            if len(files) > self.max_files:
                raise DiscoveryLimitError(f"Detected more than {self.max_files} files.",
                                          limit=self.max_files, limit_kind='max_files', observed=len(files))
            # An explicit Git/workspace list has a boundary already. Depth is
            # only a limit on unbounded recursive discovery.
        bounded, skipped = [], []
        for name in files:
            relative = Path(name)
            source = root / relative
            if relative.is_absolute() or '..' in relative.parts or not source.resolve().is_relative_to(root):
                raise ValueError("Target path is outside the workspace")
            if any(item.is_symlink() or item.is_junction() for item in (source, *source.parents) if item != root and item.is_relative_to(root)):
                raise ValueError("Target symlinks and junctions are not supported")
            if source.is_file():
                size = source.stat().st_size
                signatures = BINARY_DOCUMENTS.get(relative.suffix.lower(), ())
                if select_scan_targets and signatures:
                    with source.open('rb') as stream:
                        prefix = stream.read(16)
                    if prefix.startswith(signatures):
                        skipped.append({'path': relative.as_posix(), 'reason': 'UNSUPPORTED_BINARY_DOCUMENT',
                                        'source': 'RUNTIME_TARGET_SELECTION', 'size_bytes': size})
                        continue
                if (explicit or select_scan_targets) and size > self.max_file_size:
                    raise DiscoveryLimitError(f"File exceeds {self.max_file_size} bytes: {name}",
                                              code='TARGET_FILE_SIZE_LIMIT_EXCEEDED',
                                              relative_path=relative.as_posix(), limit=self.max_file_size,
                                              limit_kind='max_file_size', observed=size)
                bounded.append(relative.as_posix())
        files = bounded
        languages, ecosystems, frameworks = set(), set(), set()
        for name in files:
            path = Path(name)
            if path.name.lower() == 'dockerfile':
                languages.add('Dockerfile')
            if path.suffix.lower() in EXTENSIONS:
                languages.add(EXTENSIONS[path.suffix.lower()])
            if path.name in DEPENDENCIES:
                ecosystems.add(DEPENDENCIES[path.name])
            if path.name in {"main.py", "app.py"}:
                source = root / name
                try:
                    if source.stat().st_size <= self.max_file_size:
                        content = source.read_bytes()
                        if b"\0" not in content and b"fastapi" in content.lower():
                            frameworks.add("FastAPI")
                except OSError:
                    pass
        return TargetProfile(str(root), languages=sorted(languages), frameworks=sorted(frameworks), ecosystems=sorted(ecosystems), files=sorted(files),
                             skipped_files=sorted(skipped, key=lambda row: row['path']))
