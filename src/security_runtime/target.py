"""Bounded project profiling based primarily on names and manifests."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from .models import TargetProfile
from .dependency_inputs import DEPENDENCIES


EXTENSIONS = {".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".vue": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".go": "Go", ".php": "PHP"}
IGNORED = {".git", ".venv", "venv", "env", ".tools", ".security-runtime", "node_modules", ".idea", ".vscode", "dist", "build", "target", "coverage", ".cache", ".pytest_cache", ".mypy_cache", "__pycache__", ".next", ".nuxt", "vendor"}
MAX_FILES = 10_000
MAX_DIRECTORIES = 2_000
MAX_DEPTH = 12
MAX_FILE_SIZE = 1_000_000

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
    def __init__(self, detail: str, *, code='TARGET_DISCOVERY_LIMIT_EXCEEDED', relative_path=None, limit=None):
        super().__init__(f"Project is too large for automatic discovery. {detail} Use configuration to adjust scan limits.")
        self.code, self.relative_path, self.limit = code, relative_path, limit

    def to_dict(self):
        from .diagnostics import sanitize
        result = {'status': 'INCONCLUSIVE', 'reason_code': self.code,
                  'failure_stage': 'TARGET_DISCOVERY', 'coverage': 'UNKNOWN',
                  'scanner_run': False, 'source_modified': False, 'security_proof': False}
        if self.relative_path is not None:
            result['relative_path'] = sanitize(self.relative_path, 300)
        if self.limit is not None:
            result['limit'] = self.limit
        return result


def _limit(name: str, default: int) -> int:
    raw = os.getenv(f"SECURITY_RUNTIME_{name}")
    value = int(raw) if raw is not None else default
    if value < 1:
        raise ValueError(f"SECURITY_RUNTIME_{name} must be positive")
    return value


class TargetDetector:
    def __init__(self, *, max_files: int | None = None, max_directories: int | None = None,
                 max_depth: int | None = None, max_file_size: int | None = None,
                 ignored_dirs: Iterable[str] = ()):
        self.max_files = max_files if max_files is not None else _limit("MAX_FILES", MAX_FILES)
        self.max_directories = max_directories if max_directories is not None else _limit("MAX_DIRECTORIES", MAX_DIRECTORIES)
        self.max_depth = max_depth if max_depth is not None else _limit("MAX_DEPTH", MAX_DEPTH)
        self.max_file_size = max_file_size if max_file_size is not None else _limit("MAX_FILE_SIZE", MAX_FILE_SIZE)
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
                    raise DiscoveryLimitError(f"Detected directories deeper than {self.max_depth} levels.")
                if directory_count + len(subdirs) > self.max_directories:
                    raise DiscoveryLimitError(f"Detected more than {self.max_directories} directories.")
                if len(files) + len(names) > self.max_files:
                    raise DiscoveryLimitError(f"Detected more than {self.max_files} files.")
                files.extend((Path(directory) / name).relative_to(root).as_posix() for name in names)
        else:
            files = [name for name in files if not set(Path(name).parts) & self.ignored]
            if len(files) > self.max_files:
                raise DiscoveryLimitError(f"Detected more than {self.max_files} files.")
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
                                              relative_path=relative.as_posix(), limit=self.max_file_size)
                bounded.append(relative.as_posix())
        files = bounded
        languages, ecosystems, frameworks = set(), set(), set()
        for name in files:
            path = Path(name)
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
