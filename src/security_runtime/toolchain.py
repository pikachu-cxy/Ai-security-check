"""Pinned, per-user scanner tool lifecycle. No system installation is changed."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
import importlib.metadata
import json
import logging
import os
import platform
import re
import shutil
import sys
import sysconfig
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
import venv
import zipfile
import queue
import threading
from dataclasses import asdict, dataclass
from contextlib import contextmanager
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from .engines import BUILTIN_ENGINES, ON_DEMAND_ENGINES
from .licensing import LicenseMetadata, LicensePolicy, MANAGED_PYTHON_LICENSE
from .plugin_api import discover_plugin_directory
from .diagnostics import DiagnosticError, ErrorDiagnostic, classify_network_error, sanitize
from .processes import run_process, ProcessIdleTimeout
from .preparation_budget import current_budget, bounded_timeout
from .install_progress import parse_download_progress
from .progress import emit, checkpoint, ScanCancelled
from .scanner_observation import span, cache as cache_observed, count, workspace as scan_workspace


class ToolStatus(StrEnum):
    READY = "READY"
    MISSING = "MISSING"
    INSTALLING = "INSTALLING"
    BROKEN = "BROKEN"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    UPDATE_AVAILABLE = "UPDATE_AVAILABLE"
    OFFLINE = "OFFLINE"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"


class ToolSource(StrEnum):
    MANAGED = "MANAGED"
    SYSTEM = "SYSTEM"
    EXPLICIT = "EXPLICIT"


@dataclass(frozen=True)
class ToolManifest:
    tool_id: str
    display_name: str
    version: str
    platform: str
    architecture: str
    download_url: str
    sha256: str
    archive_type: str
    executable_name: str
    homepage: str
    license: str
    license_metadata: LicenseMetadata


@dataclass(frozen=True)
class ResolvedTool:
    tool_id: str
    version: str
    path: str
    source: ToolSource | None
    status: ToolStatus
    detail: str = ""
    diagnostic: ErrorDiagnostic | None = None

    def __post_init__(self):
        object.__setattr__(self, 'detail', sanitize(self.detail, 500))

    def to_dict(self) -> dict:
        return asdict(self)


def _manifest(tool: str, version: str, platform_name: str, arch: str, asset: str, digest: str, homepage: str, license_name: str) -> ToolManifest:
    owner = {"gitleaks": "gitleaks/gitleaks", "trivy": "aquasecurity/trivy", "osv-scanner": "google/osv-scanner"}[tool]
    return ToolManifest(tool, tool.title(), version, platform_name, arch,
                        f"https://github.com/{owner}/releases/download/v{version}/{asset}", digest,
                        "binary" if tool == "osv-scanner" else "zip" if asset.endswith(".zip") else "tar.gz",
                        tool + (".exe" if platform_name == "windows" else ""), homepage, license_name,
                        BUILTIN_ENGINES[tool].license_metadata)


_ASSETS = {
    ("osv-scanner", "windows", "x64"): ("osv-scanner_windows_amd64.exe", "e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6"),
    ("osv-scanner", "linux", "x64"): ("osv-scanner_linux_amd64", "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108"),
    ("osv-scanner", "macos", "x64"): ("osv-scanner_darwin_amd64", "60c5296637e977b28eeda5c7f13573e447659a632922737f94d11fa7e30ad6ca"),
    ("osv-scanner", "macos", "arm64"): ("osv-scanner_darwin_arm64", "98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4"),
    ("gitleaks", "windows", "x64"): ("gitleaks_8.30.0_windows_x64.zip", "54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573"),
    ("gitleaks", "linux", "x64"): ("gitleaks_8.30.0_linux_x64.tar.gz", "79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e"),
    ("gitleaks", "macos", "x64"): ("gitleaks_8.30.0_darwin_x64.tar.gz", "ca221d012d247080c2f6f61f4b7a83bffa2453806b0c195c795bbe9a8c775ed5"),
    ("gitleaks", "macos", "arm64"): ("gitleaks_8.30.0_darwin_arm64.tar.gz", "b251ab2bcd4cd8ba9e56ff37698c033ebf38582b477d21ebd86586d927cf87e7"),
    ("trivy", "windows", "x64"): ("trivy_0.74.0_windows-64bit.zip", "94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842"),
    ("trivy", "linux", "x64"): ("trivy_0.74.0_Linux-64bit.tar.gz", "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"),
    ("trivy", "macos", "x64"): ("trivy_0.74.0_macOS-64bit.tar.gz", "472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485"),
    ("trivy", "macos", "arm64"): ("trivy_0.74.0_macOS-ARM64.tar.gz", "1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11"),
}
VERSIONS = {name: descriptor.version for name, descriptor in BUILTIN_ENGINES.items()}
HOMEPAGES = {name: descriptor.homepage for name, descriptor in BUILTIN_ENGINES.items()}
LICENSES = {name: descriptor.license for name, descriptor in BUILTIN_ENGINES.items()}
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PythonEngineSpec:
    tool_id: str
    version: str
    requirement: str
    executable_name: str | None = None
    no_index: bool = False
    license_metadata: LicenseMetadata | None = None


def platform_key() -> tuple[str, str]:
    system = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux" if sys.platform.startswith("linux") else "unknown")
    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64" if platform.machine().lower() in {"amd64", "x86_64"} else "unknown"
    return system, arch


def default_data_root() -> Path:
    configured = os.getenv("SECURITY_RUNTIME_DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt":
        return Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "AI-Security-Runtime"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "AI-Security-Runtime"
    return Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "ai-security-runtime"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tool_environment(executable: Path) -> dict[str, str]:
    """Keep helper commands in the selected engine's environment.

    In particular, Semgrep delegates to pysemgrep on PATH. A frozen Runtime's
    library search path must also not leak into external Python processes.
    """
    env = dict(os.environ)
    env["PATH"] = str(executable.resolve().parent) + os.pathsep + env.get("PATH", "")
    for name in ("PYTHONHOME", "PYTHONPATH"):
        env.pop(name, None)
    if getattr(sys, "frozen", False):
        for name in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
            original = env.get(name + "_ORIG")
            if original is None:
                env.pop(name, None)
            else:
                env[name] = original
    return env


def matches_version(expected: str, output: str) -> bool:
    return bool(re.search(r"(?<![0-9.])" + re.escape(expected) + r"(?![0-9.])", output))


@contextmanager
def external_tool_loader():
    """Do not pass PyInstaller's DLL directory to independent executables."""
    reset = getattr(sys, "frozen", False) and os.name == "nt"
    if reset:
        import ctypes
        ctypes.windll.kernel32.SetDllDirectoryW(None)
    try:
        yield
    finally:
        if reset:
            ctypes.windll.kernel32.SetDllDirectoryW(str(sys._MEIPASS))


class ToolSourceProvider(Protocol):
    def download(self, manifest: ToolManifest, destination: Path) -> None: ...


class OfficialReleaseProvider:
    def download(self, manifest: ToolManifest, destination: Path) -> None:
        checkpoint()
        emit('ENGINE_DOWNLOAD_STARTED', scanner=manifest.tool_id, scanner_version=manifest.version)
        try:
            self._download(manifest, destination)
            emit('ENGINE_DOWNLOAD_COMPLETED', scanner=manifest.tool_id, scanner_version=manifest.version)
        except ScanCancelled:
            destination.unlink(missing_ok=True)
            raise
        except Exception as exc:
            destination.unlink(missing_ok=True)
            diagnostic = classify_network_error(exc, url=manifest.download_url, fallback='DOWNLOAD_FAILED')
            emit('ENGINE_DOWNLOAD_FAILED', scanner=manifest.tool_id, scanner_version=manifest.version,
                 error_code=diagnostic.error_code, source=diagnostic.source)
            raise DiagnosticError(diagnostic) from None

    def _download(self, manifest: ToolManifest, destination: Path) -> None:
        if not manifest.download_url.startswith("https://github.com/"):
            raise ValueError("Only pinned official HTTPS release assets are accepted")
        request = urllib.request.Request(manifest.download_url, headers={"User-Agent": "ai-security-runtime"})
        digest = hashlib.sha256()
        size = 0
        # A blocking TLS connect/read cannot consume Ctrl+C in a pool worker.
        # One bounded daemon reader owns the response; only this worker writes
        # the destination. Cancellation closes/unlinks it immediately.
        chunks = queue.Queue(maxsize=2)
        stop = threading.Event()
        network_timeout = bounded_timeout(60)
        budget = current_budget()
        total_size = 0
        last_chunk = time.monotonic()
        def send(kind, value=None):
            while not stop.is_set():
                try:
                    chunks.put((kind, value), timeout=.1)
                    return
                except queue.Full:
                    continue
        def receive():
            try:
                with urllib.request.urlopen(request, timeout=network_timeout) as response:
                    if not response.url.startswith('https://'):
                        raise ValueError('Insecure release redirect')
                    declared = getattr(response, 'headers', {}).get('Content-Length', '')
                    if str(declared).isdigit() and 0 < int(declared) <= 200_000_000:
                        send('total', int(declared))
                    while not stop.is_set():
                        chunk = response.read(64 * 1024)
                        if not chunk:
                            break
                        send('chunk', chunk)
                send('done')
            except Exception as exc:
                send('error', exc)
        reader = threading.Thread(target=receive, name='security-download', daemon=True)
        reader.start()
        try:
            with destination.open('wb') as output:
                while True:
                    checkpoint()
                    bounded_timeout(60)
                    if budget and time.monotonic() - last_chunk >= budget.idle_seconds:
                        raise ProcessIdleTimeout('release download made no progress')
                    try:
                        kind, value = chunks.get(timeout=.1)
                    except queue.Empty:
                        continue
                    if kind == 'done':
                        break
                    if kind == 'error':
                        raise value
                    if kind == 'total':
                        total_size = value
                        continue
                    size += len(value)
                    last_chunk = time.monotonic()
                    if size > 200_000_000:
                        raise ValueError('Release asset exceeds 200 MB')
                    digest.update(value)
                    output.write(value)
                    if budget and total_size:
                        budget.report(dict(event='DOWNLOAD_PROGRESS', component=manifest.tool_id,
                            received_bytes=size, total_bytes=total_size))
        finally:
            stop.set()
            reader.join(timeout=.1)
        if digest.hexdigest() != manifest.sha256:
            destination.unlink(missing_ok=True)
            raise ValueError("Release SHA256 mismatch")


class ToolManager:
    def __init__(self, root: Path | None = None, provider: ToolSourceProvider | None = None, *, now=None):
        self.root = root if root is not None else default_data_root()
        self.provider = provider or OfficialReleaseProvider()
        self.data_diagnostics: dict[str, ErrorDiagnostic] = {}
        self.now = now or (lambda: datetime.now(timezone.utc))
        self._database_lock = threading.RLock()
        self._engine_locks = {tool_id: threading.RLock() for tool_id in VERSIONS}
        self._lock_guard = threading.Lock()
        self._version_cache = {}  # Process-local successful probes only, <=16.
        self._version_cache_lock = threading.RLock()
        self.versions = dict(VERSIONS)
        self.python_engines = {"semgrep"}
        self.python_requirements = {"semgrep": (f"semgrep=={VERSIONS['semgrep']}", False, None)}
        self.extra_manifests: dict[tuple[str, str, str], ToolManifest] = {}
        self.extra_licenses: dict[str, LicenseMetadata] = {}
        discover_plugin_directory(self.root / "plugins")
        self._load_external_engines()

    def register_manifest(self, manifest: ToolManifest) -> None:
        if manifest.tool_id in VERSIONS:
            raise ValueError("External manifest cannot replace a built-in tool")
        if not isinstance(manifest.license_metadata, LicenseMetadata):
            raise ValueError("External manifest requires LicenseMetadata")
        self.versions[manifest.tool_id] = manifest.version
        self.extra_licenses[manifest.tool_id] = manifest.license_metadata
        self.extra_manifests[(manifest.tool_id, manifest.platform, manifest.architecture)] = manifest

    def _load_external_engines(self) -> None:
        for entry in importlib.metadata.entry_points(group="ai_security_runtime.tool_manifests"):
            try:
                loaded = entry.load()
                manifests = loaded() if callable(loaded) else loaded
                for manifest in manifests if isinstance(manifests, (list, tuple)) else (manifests,):
                    if not isinstance(manifest, ToolManifest):
                        raise TypeError("Expected ToolManifest")
                    self.register_manifest(manifest)
            except Exception as exc:
                logger.warning("engine_manifest_skipped name=%s reason=%s", entry.name, type(exc).__name__)
        for entry in importlib.metadata.entry_points(group="ai_security_runtime.python_engines"):
            try:
                loaded = entry.load()
                spec = loaded() if callable(loaded) else loaded
                if not isinstance(spec, PythonEngineSpec) or spec.tool_id in VERSIONS:
                    raise TypeError("Expected external PythonEngineSpec")
                self.register_python_engine(spec.tool_id, spec.version, spec.requirement,
                                            no_index=spec.no_index, executable_name=spec.executable_name,
                                            license_metadata=spec.license_metadata)
            except Exception as exc:
                logger.warning("python_engine_skipped name=%s reason=%s", entry.name, type(exc).__name__)

    def register_python_engine(self, tool_id: str, version: str, requirement: str, *, no_index: bool = False, executable_name: str | None = None, license_metadata: LicenseMetadata | None = None) -> None:
        if tool_id in VERSIONS:
            raise ValueError("External Python engine cannot replace a built-in tool")
        if not isinstance(license_metadata, LicenseMetadata):
            raise ValueError("External Python engine requires LicenseMetadata")
        self.versions[tool_id] = version
        self.python_engines.add(tool_id)
        self.python_requirements[tool_id] = (requirement, no_index, executable_name)
        if license_metadata:
            self.extra_licenses[tool_id] = license_metadata

    def license_metadata(self, tool_id: str) -> LicenseMetadata | None:
        descriptor = BUILTIN_ENGINES.get(tool_id)
        return descriptor.license_metadata if descriptor else self.extra_licenses.get(tool_id)

    def manifest(self, tool_id: str) -> ToolManifest | None:
        system, arch = platform_key()
        external = self.extra_manifests.get((tool_id, system, arch))
        if external:
            return external
        asset = _ASSETS.get((tool_id, system, arch))
        if not asset:
            return None
        return _manifest(tool_id, VERSIONS[tool_id], system, arch, *asset, HOMEPAGES[tool_id], LICENSES[tool_id])

    def managed_path(self, tool_id: str) -> Path:
        manifest = self.manifest(tool_id)
        python_executable = self.python_requirements.get(tool_id, ("", False, None))[2]
        executable = manifest.executable_name if manifest else python_executable or tool_id + (".exe" if os.name == "nt" else "")
        base = self.root / ("engines" if tool_id == "semgrep" else "tools") / tool_id / self.versions[tool_id]
        runtime = "runtime" if tool_id == "semgrep" else "venv"
        return base / runtime / ("Scripts" if os.name == "nt" else "bin") / executable if tool_id in self.python_engines else base / executable

    def trivy_cache_dir(self) -> Path:
        return Path(os.getenv("SECURITY_RUNTIME_TRIVY_CACHE_DIR") or os.getenv("TRIVY_CACHE_DIR") or self.root / "cache" / "trivy")

    def database_status(self) -> ToolStatus:
        directory = self.trivy_cache_dir() / "db"
        return ToolStatus.READY if (directory / "trivy.db").is_file() and (directory / "metadata.json").is_file() else ToolStatus.MISSING

    def database_freshness(self, directory=None) -> dict:
        """Presence is not freshness. Honor expiry and bound metadata validity."""
        directory = Path(directory) if directory is not None else self.trivy_cache_dir() / 'db'
        if not (directory / 'trivy.db').is_file():
            return {'status': 'MISSING'}
        try:
            path = directory / 'metadata.json'
            if path.stat().st_size > 64_000:
                raise ValueError()
            metadata = json.loads(path.read_bytes())
            def timestamp(name):
                value = datetime.fromisoformat(metadata[name].replace('Z', '+00:00'))
                if value.tzinfo is None:
                    raise ValueError()
                return value.astimezone(timezone.utc)
            updated, expiry = timestamp('UpdatedAt'), timestamp('NextUpdate')
            now = self.now()
            if expiry <= updated or updated > now:
                raise ValueError()
            return {'status': 'FRESH' if now < expiry else 'STALE',
                    'updated_at': updated.isoformat(), 'next_update': expiry.isoformat()}
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return {'status': 'UNKNOWN', 'reason': 'DATABASE_TIMESTAMP_INVALID'}

    def trivy_data_statuses(self) -> dict[str, str]:
        java = self.trivy_cache_dir() / 'java-db'
        return {'vulnerability_db': self.database_status(),
                'vulnerability_db_freshness': self.database_freshness()['status'],
                'java_db': 'READY' if (java / 'trivy-java.db').is_file() and (java / 'metadata.json').is_file() else 'MISSING',
                # Do not infer completed misconfiguration scanning from a log
                # or from the binary alone. Embedded-policy availability varies.
                'checks': 'UNKNOWN'}

    def _configured_path(self, tool_id: str) -> Path | None:
        value = os.getenv(f"SECURITY_RUNTIME_{tool_id.upper().replace('-', '_')}_PATH")
        if value:
            return Path(value).expanduser()
        config = Path(os.getenv("SECURITY_RUNTIME_CONFIG", self.root / "config.toml"))
        try:
            if config.is_file():
                value = tomllib.loads(config.read_text(encoding="utf-8")).get("tools", {}).get(tool_id, {}).get("path")
                return Path(value).expanduser() if value else None
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            raise DiagnosticError(ErrorDiagnostic('CONFIG_CORRUPTED', 'Invalid tool configuration.', 'Repair the local tool configuration before retrying.')) from None
        return None

    def _probe_identity(self, tool_id, path):
        """Content-keyed probe reuse, not an engine integrity check bypass."""
        files = [path]
        if tool_id in self.python_engines:
            # Unknown/custom Python launch layouts are never cached.
            runtime = path.parent.parent
            packages = [runtime/'Lib/site-packages'] + list((runtime/'lib').glob('python*/site-packages'))
            package = next((p/'semgrep' for p in packages if (p/'semgrep').is_dir()), None)
            if tool_id != 'semgrep' or package is None:
                return None
            files.extend(p for p in package.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
            files.extend(p for p in path.parent.glob('*semgrep*') if p.is_file())
            for base in packages:
                files.extend(base.glob('semgrep-*.dist-info/METADATA'))
            files.extend(p for p in (runtime/'python.exe', runtime/'bin/python', runtime/'pyvenv.cfg') if p.is_file())
        if len(files) > 2000:
            return None
        if sum(file.stat().st_size for file in set(files)) > 512_000_000:
            return None
        digest = hashlib.sha256()
        for file in sorted(set(files)):
            if file.is_symlink() or file.is_junction():
                return None
            digest.update(str(file).encode());digest.update(sha256_file(file).encode())
        # Version behavior may depend on env/config/workspace. Hash only in RAM.
        digest.update(repr(sorted(tool_environment(path).items())).encode())
        digest.update(str(scan_workspace() or os.getcwd()).encode())
        return tool_id, self.versions[tool_id], str(path), digest.digest()

    def _version(self, tool_id: str, path: Path) -> str:
        from .scanner_cache import preparation_bucket
        bucket = preparation_bucket('version:' + tool_id, os.path.normcase(str(self.root.resolve())))
        self._version_cache = bucket.values
        self._version_cache_lock = bucket.lock
        with self._lock_guard:
            lock = self._engine_locks.setdefault(tool_id,threading.RLock())
        with lock, bucket.lock:
            try:
                with span('capability_cache_validation'):
                    key = self._probe_identity(tool_id, path)
            except (OSError, ValueError):
                key = None
            from .first_scan_attribution import record_probe
            record_probe(tool_id, key)
            with bucket.lock:
                cached = bucket.values.get(key) if key is not None else None
            if cached is not None:
                cache_observed('version_probe', True)
                return cached
            cache_observed('version_probe', False)
            output = self._probe_version(tool_id, path)
            if key is not None and matches_version(self.versions[tool_id], output):
                try:
                    unchanged = self._probe_identity(tool_id, path) == key
                except (OSError, ValueError):
                    unchanged = False
                if unchanged:
                    with bucket.lock:
                        if len(bucket.values) >= 16:
                            bucket.values.pop(next(iter(bucket.values)))
                        bucket.values[key] = output
            return output

    def _probe_version(self, tool_id: str, path: Path) -> str:
        try:
            with external_tool_loader():
                with span('version_probe_invocation'):
                    count('version_probe_invocations')
                    from .scanner_observation import invocation
                    invocation('VERSION_PROBE', 0)
                    proc = run_process([str(path.resolve()), "--version"], timeout=8, max_output=16_000,
                                       env=tool_environment(path))
            if proc.returncode:
                return ""
            return sanitize((proc.stdout + proc.stderr).strip(), 160)
        except (OSError, TimeoutError, ValueError):
            return ""

    def _check(self, tool_id: str, path: Path, source: ToolSource) -> ResolvedTool:
        path = path.expanduser().resolve()
        if not path.is_file():
            return ResolvedTool(tool_id, "", str(path), source, ToolStatus.MISSING)
        if source == ToolSource.MANAGED and tool_id in self.python_engines and path.is_relative_to(self.root / ("engines" if tool_id == "semgrep" else "tools")):
            install_dir = path.parents[2]
            if not all((install_dir / name).is_file() for name in ("install.json", "metadata.json", "LICENSE", "NOTICE")):
                return ResolvedTool(tool_id, "", str(path), source, ToolStatus.BROKEN, "Python package installation is incomplete")
            if tool_id == "semgrep":
                try:
                    metadata = json.loads((install_dir / "metadata.json").read_text(encoding="utf-8"))
                    if metadata["version"] != self.versions[tool_id]:
                        return ResolvedTool(tool_id, metadata["version"], str(path), source,
                                            ToolStatus.VERSION_MISMATCH, f"expected {self.versions[tool_id]}")
                    if metadata["executable_sha256"] != sha256_file(path):
                        return ResolvedTool(tool_id, "", str(path), source, ToolStatus.BROKEN, "managed Python executable checksum mismatch")
                except (OSError, ValueError, KeyError):
                    return ResolvedTool(tool_id, "", str(path), source, ToolStatus.BROKEN, "managed Python metadata invalid")
        if source == ToolSource.MANAGED and tool_id not in self.python_engines:
            marker = path.parent / "install.json"
            try:
                data = json.loads(marker.read_text(encoding="utf-8"))
                if data["archive_sha256"] != self.manifest(tool_id).sha256 or data["binary_sha256"] != sha256_file(path):
                    return ResolvedTool(tool_id, "", str(path), source, ToolStatus.BROKEN, "managed binary checksum mismatch")
                metadata = json.loads((path.parent / "metadata.json").read_text(encoding="utf-8"))
                if metadata["license"] != self.license_metadata(tool_id).license_spdx or not (path.parent / "LICENSE").is_file():
                    return ResolvedTool(tool_id, "", str(path), source, ToolStatus.BROKEN, "managed license metadata missing")
                if self.license_metadata(tool_id).notice_required and not (path.parent / "NOTICE").is_file():
                    return ResolvedTool(tool_id, "", str(path), source, ToolStatus.BROKEN, "managed notice missing")
            except (OSError, ValueError, KeyError):
                return ResolvedTool(tool_id, "", str(path), source, ToolStatus.BROKEN, "missing or invalid install marker")
        output = self._version(tool_id, path)
        if not output:
            return ResolvedTool(tool_id, "", str(path), source, ToolStatus.BROKEN, "executable failed version check")
        expected = self.versions[tool_id]
        if not matches_version(expected, output):
            return ResolvedTool(tool_id, output, str(path), source, ToolStatus.VERSION_MISMATCH, f"expected {expected}")
        return ResolvedTool(tool_id, expected, str(path), source, ToolStatus.READY)

    def resolve(self, tool_id: str) -> ResolvedTool:
        if tool_id not in self.versions:
            raise KeyError(f"Unknown tool: {tool_id}")
        explicit = self._configured_path(tool_id)
        if explicit is not None:
            return self._check(tool_id, explicit, ToolSource.EXPLICIT)
        managed = self.managed_path(tool_id)
        if managed.exists():
            return self._check(tool_id, managed, ToolSource.MANAGED)
        if tool_id == "semgrep" and not getattr(sys, "frozen", False):
            executable = "semgrep.exe" if os.name == "nt" else "semgrep"
            # Backward-compatible use of an already installed Python script.
            # A standalone Runtime has no Semgrep Python dependency.
            runtime_exe = Path(sysconfig.get_path("scripts")) / executable
            try:
                if runtime_exe.is_file() and importlib.metadata.version("semgrep") == self.versions["semgrep"]:
                    return self._check(tool_id, runtime_exe, ToolSource.SYSTEM)
            except importlib.metadata.PackageNotFoundError:
                pass
        system = shutil.which(tool_id)
        if system:
            return self._check(tool_id, Path(system), ToolSource.SYSTEM)
        if tool_id not in self.python_engines and self.manifest(tool_id) is None:
            return ResolvedTool(tool_id, "", "", None, ToolStatus.UNSUPPORTED_PLATFORM)
        return ResolvedTool(tool_id, "", "", None, ToolStatus.MISSING)

    def ensure(self, tool_id: str, *, offline: bool | None = None) -> ResolvedTool:
        checkpoint()
        emit('ENGINE_PREPARING', scanner=tool_id, scanner_version=self.versions.get(tool_id, ''))
        # Multiple capability providers can share one engine. Serialize its
        # resolution/install transaction without serializing actual scans.
        with self._lock_guard:
            lock = self._engine_locks.setdefault(tool_id, threading.RLock())
        with lock:
            checkpoint()
            result = self._ensure(tool_id, offline=offline)
        emit('ENGINE_READY' if result.status == ToolStatus.READY else 'ENGINE_PREPARATION_FAILED',
            scanner=tool_id, scanner_version=result.version or self.versions.get(tool_id, ''),
            error_code=result.diagnostic.error_code if result.diagnostic else '',
            source=result.diagnostic.source if result.diagnostic else '')
        return result

    def _ensure(self, tool_id: str, *, offline: bool | None = None) -> ResolvedTool:
        try:
            current = self.resolve(tool_id)
        except ScanCancelled:
            raise
        except Exception as exc:
            logger.warning("tool_resolution_failed tool=%s reason=%s", tool_id, type(exc).__name__)
            diagnostic = exc.diagnostic if isinstance(exc, DiagnosticError) else classify_network_error(exc, fallback='ENGINE_UNAVAILABLE')
            return ResolvedTool(tool_id, "", "", None, ToolStatus.BROKEN, diagnostic.error_summary, diagnostic)
        if current.status == ToolStatus.READY:
            return current
        if current.source == ToolSource.EXPLICIT:
            return current
        if not LicensePolicy.can_auto_download(self.license_metadata(tool_id)):
            return ResolvedTool(tool_id, "", "", None, ToolStatus.BROKEN, "automatic installation prohibited by license policy")
        if offline is None:
            offline = os.getenv("SECURITY_RUNTIME_OFFLINE") == "1"
        requirement = self.python_requirements.get(tool_id)
        if offline and not (requirement and requirement[1]):
            if current.source is not None and current.status != ToolStatus.MISSING:
                return current
            diagnostic = classify_network_error(offline=True)
            return ResolvedTool(tool_id, "", "", None, ToolStatus.OFFLINE, diagnostic.error_summary, diagnostic)
        try:
            if requirement:
                self.install_python_package(tool_id, self.versions[tool_id], requirement[0], no_index=requirement[1], executable_name=requirement[2])
            else:
                manifest = self.manifest(tool_id)
                if manifest is None:
                    return ResolvedTool(tool_id, "", "", None, ToolStatus.UNSUPPORTED_PLATFORM)
                self._install_binary(manifest)
            return self.resolve(tool_id)
        except ScanCancelled:
            raise
        except Exception as exc:
            logger.warning("tool_install_failed tool=%s reason=%s", tool_id, type(exc).__name__)
            diagnostic = exc.diagnostic if isinstance(exc, DiagnosticError) else classify_network_error(exc, fallback='ENGINE_PREPARATION_FAILED')
            return ResolvedTool(tool_id, "", "", None, ToolStatus.BROKEN, diagnostic.error_summary, diagnostic)

    def _install_binary(self, manifest: ToolManifest) -> None:
        parent = self.root / "tools" / manifest.tool_id
        parent.mkdir(parents=True, exist_ok=True)
        final = parent / manifest.version
        with tempfile.TemporaryDirectory(dir=parent, prefix="install-") as tmp:
            staging = Path(tmp)
            archive = staging / "release.archive"
            self.provider.download(manifest, archive)
            executable = staging / manifest.executable_name
            if manifest.archive_type == "binary":
                if archive.stat().st_size > 200_000_000 or sha256_file(archive) != manifest.sha256:
                    raise ValueError("Release binary checksum mismatch or oversized")
                shutil.copyfile(archive, executable)
            elif manifest.archive_type == "zip":
                with zipfile.ZipFile(archive) as package:
                    members = [item for item in package.infolist() if not item.is_dir() and Path(item.filename).name == manifest.executable_name]
                    if len(members) != 1 or members[0].file_size > 200_000_000:
                        raise ValueError("Release archive executable is missing or oversized")
                    with package.open(members[0]) as source, executable.open("wb") as target:
                        shutil.copyfileobj(source, target)
            else:
                with tarfile.open(archive, "r:gz") as package:
                    members = [item for item in package.getmembers() if item.isfile() and Path(item.name).name == manifest.executable_name]
                    if len(members) != 1 or members[0].size > 200_000_000:
                        raise ValueError("Release archive executable is missing or oversized")
                    with package.extractfile(members[0]) as source, executable.open("wb") as target:
                        shutil.copyfileobj(source, target)
            executable.chmod(executable.stat().st_mode | 0o111)
            archive.unlink()
            if manifest.version not in self._version(manifest.tool_id, executable):
                raise ValueError("Release executable failed version validation")
            source_dir = Path(__file__).parent / "licenses" / manifest.tool_id
            for name in ("LICENSE", "NOTICE"):
                source = source_dir / name
                if source.is_file():
                    shutil.copy2(source, staging / name)
            if manifest.license_metadata.notice_required and not (staging / "LICENSE").is_file():
                raise ValueError("Required engine license text is missing")
            if manifest.license_metadata.notice_required and not (staging / "NOTICE").is_file():
                raise ValueError("Required engine NOTICE is missing")
            installed_at = datetime.now(timezone.utc).isoformat()
            (staging / "metadata.json").write_text(json.dumps({"name": manifest.display_name, "version": manifest.version,
                "download_source": manifest.download_url, "sha256": manifest.sha256,
                "license": manifest.license_metadata.license_spdx, "installed_at": installed_at}), encoding="utf-8")
            (staging / "install.json").write_text(json.dumps({"tool_id": manifest.tool_id, "version": manifest.version,
                                                               "archive_sha256": manifest.sha256, "binary_sha256": sha256_file(executable)}), encoding="utf-8")
            if final.exists():
                shutil.rmtree(final)
            os.replace(staging, final)

    def prepare_python_runtime(self) -> Path:
        """Bootstrap a relocatable, checksum-pinned CPython without system Python."""
        if not LicensePolicy.can_auto_download(MANAGED_PYTHON_LICENSE):
            raise ValueError("Managed Python download prohibited by license policy")
        key = "-".join(platform_key())
        entries = json.loads((Path(__file__).parent / "python_downloads.json").read_text(encoding="utf-8"))
        entry = entries.get(key)
        if entry is None:
            raise ValueError(f"No reviewed Python bootstrap for {key}")
        relative_exe = Path("python.exe") if os.name == "nt" else Path("bin/python3.12")
        parent = self.root / "python" / (entry["version"] + "-" + entry["build"])
        parent.mkdir(parents=True, exist_ok=True)
        final = parent / key
        executable = final / relative_exe
        try:
            record = json.loads((final / "metadata.json").read_text(encoding="utf-8"))
            if (record["sha256"] == entry["sha256"] and record["binary_sha256"] == sha256_file(executable)
                    and matches_version(entry["version"], self._probe_version("cpython", executable))):
                return executable
        except (OSError, ValueError, KeyError):
            pass
        if os.getenv("SECURITY_RUNTIME_OFFLINE") == "1":
            raise ValueError("Managed Python unavailable offline")
        manifest = ToolManifest("cpython", "Managed CPython", entry["version"], *platform_key(),
                                entry["url"], entry["sha256"], "tar.gz", relative_exe.as_posix(),
                                "https://github.com/astral-sh/python-build-standalone", MANAGED_PYTHON_LICENSE.license_spdx,
                                MANAGED_PYTHON_LICENSE)
        with tempfile.TemporaryDirectory(dir=parent, prefix="install-") as temporary:
            staging = Path(temporary)
            archive = staging / "python.tar.gz"
            self.provider.download(manifest, archive)
            with tarfile.open(archive, "r:gz") as package:
                members = package.getmembers()
                if (sum(member.size for member in members) > 600_000_000
                        or any(not member.name.startswith("python/") and member.name != "python" for member in members)):
                    raise ValueError("Unexpected Python bootstrap archive")
                package.extractall(staging, filter="data")
            installed = staging / "python"
            candidate = installed / relative_exe
            # Bootstrap CPython is not a scanner engine. Validate its pinned
            # version directly, without the scanner registry/version cache.
            if not matches_version(entry["version"], self._probe_version("cpython", candidate)):
                raise ValueError("Managed Python failed version validation")
            if not any(path.is_file() for path in installed.rglob("*LICENSE*")):
                raise ValueError("Managed Python license inventory is missing")
            (installed / "metadata.json").write_text(json.dumps({
                "engine_id": "cpython-bootstrap", "version": entry["version"], "build": entry["build"],
                "download_source": entry["url"], "sha256": entry["sha256"],
                "binary_sha256": sha256_file(candidate), "license": MANAGED_PYTHON_LICENSE.license_spdx,
                "installed_at": datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
            if final.exists():
                shutil.rmtree(final)
            os.replace(installed, final)
        return executable

    def install_python_package(self, tool_id: str, version: str, requirement: str, *, executable_name: str | None = None, no_index: bool = False) -> Path:
        checkpoint()
        emit('ENGINE_PACKAGE_PREPARING', scanner=tool_id, scanner_version=version)
        license_metadata = self.license_metadata(tool_id)
        if not LicensePolicy.can_auto_download(license_metadata):
            raise ValueError("Python engine installation prohibited by license policy")
        self.versions[tool_id] = version
        self.python_engines.add(tool_id)
        parent = self.root / ("engines" if tool_id == "semgrep" else "tools") / tool_id
        parent.mkdir(parents=True, exist_ok=True)
        final = parent / version
        if final.exists():
            shutil.rmtree(final)
        final.mkdir()
        try:
            staging = final
            environment = staging / ("runtime" if tool_id == "semgrep" else "venv")
            if getattr(sys, "frozen", False):
                bootstrap = self.prepare_python_runtime()
                with external_tool_loader():
                    proc = run_process([str(bootstrap), "-m", "venv", str(environment)],
                                       env=tool_environment(bootstrap), timeout=120)
                if proc.returncode:
                    raise DiagnosticError(classify_network_error(stderr=proc.stderr, return_code=proc.return_code, fallback='PYTHON_BOOTSTRAP_FAILED'))
            else:
                venv.EnvBuilder(with_pip=True).create(environment)
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            report = staging / "pip-report.json"
            command = [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--report", str(report)]
            if no_index:
                command += ["--no-index", "--no-build-isolation"]
            command.append(requirement)
            with external_tool_loader():
                proc = run_process(command, timeout=600, env=tool_environment(python))
            if proc.returncode:
                raise DiagnosticError(classify_network_error(stderr=proc.stderr, return_code=proc.return_code, fallback='PYTHON_PACKAGE_PREPARATION_FAILED'))
            executable = environment / ("Scripts" if os.name == "nt" else "bin") / (executable_name or tool_id + (".exe" if os.name == "nt" else ""))
            if not executable.is_file():
                raise ValueError("Python package engine did not provide the expected command")
            if not matches_version(version, self._version(tool_id, executable)):
                raise ValueError("Python package engine failed version validation")
            license_candidates = list(environment.rglob("*.dist-info/LICENSE")) + list(environment.rglob("*.dist-info/LICENSE.txt"))
            own_license = next((candidate for candidate in license_candidates
                                if candidate.parent.name.replace("-", "_").lower().startswith(tool_id.replace("-", "_").lower() + "_")), None)
            bundled_license = Path(__file__).parent / "licenses" / tool_id / "LICENSE"
            if own_license is not None:
                shutil.copy2(own_license, staging / "LICENSE")
            elif bundled_license.is_file():
                shutil.copy2(bundled_license, staging / "LICENSE")
            elif license_metadata.notice_required:
                raise ValueError("Python package license text is missing")
            notice = Path(__file__).parent / "licenses" / tool_id / "NOTICE"
            if notice.is_file():
                shutil.copy2(notice, staging / "NOTICE")
            else:
                (staging / "NOTICE").write_text(f"{tool_id} {version}\n{license_metadata.copyright}\n{license_metadata.license_spdx}\n", encoding="utf-8")
            pip_data = json.loads(report.read_text(encoding="utf-8"))
            selected = next((item for item in pip_data.get("install", [])
                             if item.get("metadata", {}).get("name", "").lower().replace("_", "-") == tool_id), None)
            if selected is None:
                raise ValueError("Python package provenance is missing")
            if selected.get("metadata", {}).get("version") != version:
                raise ValueError("Python package version mismatch")
            source = selected.get("download_info", {})
            digest = source.get("archive_info", {}).get("hashes", {}).get("sha256", "")
            if not digest and Path(requirement).is_file():
                digest = sha256_file(Path(requirement))
            if not digest:
                raise ValueError("Python package checksum is missing")
            report.unlink()
            (staging / "metadata.json").write_text(json.dumps({"engine_id": tool_id, "name": tool_id, "version": version,
                "source": source.get("url", requirement), "download_source": source.get("url", requirement),
                "sha256": digest, "license": license_metadata.license_spdx,
                "executable_sha256": sha256_file(executable),
                "installed_at": datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
            marker = staging / "install.json.tmp"
            marker.write_text(json.dumps({"tool_id": tool_id, "version": version, "requirement": requirement}), encoding="utf-8")
            os.replace(marker, staging / "install.json")
            return self.managed_path(tool_id)
        except Exception:
            shutil.rmtree(final, ignore_errors=True)
            raise

    def prepare_trivy_database(self, binary: str, *, offline: bool | None = None, force=False, validate_database=None) -> ToolStatus:
        checkpoint()
        with self._database_lock:
            fresh = self.database_freshness()['status']
            if fresh == 'FRESH' and not force and (validate_database is None or validate_database(self.trivy_cache_dir() / 'db')):
                self.data_diagnostics.pop('vulnerability_db', None)
                return ToolStatus.READY
            emit('DATA_PREPARING', scanner='trivy', component='vulnerability_db', message=f'Database freshness: {fresh}')
            if validate_database is None:
                result = self._prepare_trivy_database(binary, offline=offline, force=force)
            else:
                result = self._prepare_trivy_database(binary, offline=offline, force=force,
                                                      validate_database=validate_database)
        diagnostic = self.data_diagnostics.get('vulnerability_db')
        emit('DATA_READY' if result == ToolStatus.READY and diagnostic is None else 'DATA_PREPARATION_FAILED',
             scanner='trivy', component='vulnerability_db', error_code=diagnostic.error_code if diagnostic else '',
             source=diagnostic.source if diagnostic else '')
        return result

    def _prepare_trivy_database(self, binary: str, *, offline: bool | None = None, force=False, validate_database=None) -> ToolStatus:
        self.data_diagnostics.pop('vulnerability_db', None)
        available = self.database_status() == ToolStatus.READY
        if (self.database_freshness()['status'] == 'FRESH' and not force
                and (validate_database is None or validate_database(self.trivy_cache_dir() / 'db'))):
            return ToolStatus.READY
        if offline is None:
            offline = os.getenv("SECURITY_RUNTIME_OFFLINE") == "1"
        if offline:
            self.data_diagnostics['vulnerability_db'] = (ErrorDiagnostic('VULNERABILITY_DB_STALE',
                'Offline scan uses a cached database whose freshness is not current.',
                'Reconnect and refresh vulnerability data before treating the result as current.')
                if available else classify_network_error(offline=True))
            return ToolStatus.READY if available else ToolStatus.OFFLINE
        cache = self.trivy_cache_dir()
        cache.mkdir(parents=True, exist_ok=True)
        # Public vulnerability DB downloads must not depend on the user's
        # Docker credential helper or Docker being installed at all.
        docker_config = cache / "docker-config"
        docker_config.mkdir(exist_ok=True)
        env = tool_environment(Path(binary))
        env["DOCKER_CONFIG"] = str(docker_config)
        from .hook_state import HookStateStore
        locks = HookStateStore(cache / '.update-state')
        with locks.lock(cache, wait_seconds=0) as acquired:
            if not acquired:
                self.data_diagnostics['vulnerability_db'] = ErrorDiagnostic('DOWNLOAD_BUSY',
                    'Another process is updating the public database.', 'Retry preparation after it completes.')
                budget = current_budget()
                if budget:
                    budget.report(dict(event='DOWNLOAD_FAILED', component='vulnerability_db', error_code='DOWNLOAD_BUSY'))
                return ToolStatus.READY if available else ToolStatus.BROKEN
            return self._download_trivy_database(binary, cache, env, available, validate_database)

    def _download_trivy_database(self, binary, cache, env, available, validate_database):
        budget = current_budget()
        max_attempts = 1 + budget.retries if budget else 2
        for attempt in range(max_attempts):
            observed = [time.monotonic(), -1]
            download_source = ['']
            def transfer(line):
                source = re.search(r'Downloading artifact.*repo="([A-Za-z0-9.-]+)(?:/|:)', line)
                if source:
                    download_source[0] = source[1]
                counts = parse_download_progress(line)
                if counts and counts[0] > observed[1]:
                    observed[:] = [time.monotonic(), counts[0]]
                    if budget:
                        budget.report(dict(event='DOWNLOAD_PROGRESS', component='vulnerability_db',
                            received_bytes=counts[0], total_bytes=counts[1], attempt=attempt + 1, max_attempts=max_attempts))
            try:
                seconds = bounded_timeout(budget.seconds if budget else 900)
                if budget:
                    if attempt:
                        budget.report(dict(event='DOWNLOAD_RETRY', component='vulnerability_db', attempt=attempt + 1, max_attempts=max_attempts))
                    budget.report(dict(event='DOWNLOAD_STARTED', component='vulnerability_db', attempt=attempt + 1,
                        max_attempts=max_attempts, timeout_seconds=max(1, int(seconds))))
                # Download to a separate cache. A failed update cannot destroy
                # the previous usable database. No target project is executed.
                with tempfile.TemporaryDirectory(prefix='db-update-', dir=cache) as temporary:
                    staging = Path(temporary)
                    with external_tool_loader():
                        command = [str(Path(binary).resolve()), 'image', '--download-db-only', '--cache-dir', str(staging)]
                        if budget:
                            command += ['--timeout', f'{seconds:.3f}s']
                        else:
                            command.append('--quiet')
                        proc = run_process(command, env=env, timeout=seconds,
                            on_stderr_line=transfer if budget else None,
                            idle_timeout=budget.idle_seconds if budget else None,
                            activity_clock=lambda: observed[0])
                    if (proc.returncode == 0 and self.database_freshness(staging / 'db')['status'] == 'FRESH'
                            and (validate_database is None or validate_database(staging / 'db'))):
                        from .hook_state import no_links
                        bounded_timeout(5)
                        final = cache / 'db'
                        no_links(final)
                        backup = staging / 'previous-db'
                        if final.exists():
                            os.replace(final, backup)
                        try:
                            os.replace(staging / 'db', final)
                        except OSError:
                            if backup.exists():
                                os.replace(backup, final)
                            raise
                        self.data_diagnostics.pop('vulnerability_db', None)
                        if budget:
                            budget.report(dict(event='DOWNLOAD_COMPLETE', component='vulnerability_db', attempt=attempt + 1, max_attempts=max_attempts))
                        return ToolStatus.READY
                diagnostic = classify_network_error(stderr=proc.stderr, return_code=proc.returncode, fallback='VULNERABILITY_DB_PREPARATION_FAILED')
            except (OSError, TimeoutError, ValueError) as exc:
                diagnostic = classify_network_error(exc, fallback='VULNERABILITY_DB_PREPARATION_FAILED')
                if isinstance(exc, ProcessIdleTimeout):
                    diagnostic = ErrorDiagnostic('DOWNLOAD_STALLED', 'Download made no byte progress.', 'Retry preparation when the connection is stable.')
            self.data_diagnostics['vulnerability_db'] = diagnostic
            if budget:
                error_code = 'PREPARATION_BUDGET_EXHAUSTED' if budget.remaining() <= 0 else diagnostic.error_code
                budget.report(dict(event='DOWNLOAD_FAILED', component='vulnerability_db', error_code=error_code,
                    source=download_source[0] or diagnostic.source, attempt=attempt + 1, max_attempts=max_attempts))
            logger.warning("trivy_database_prepare_failed attempt=%s category=%s source=%s", attempt + 1, diagnostic.error_code, diagnostic.source)
            if diagnostic.error_code in {'HTTP_429', 'HTTP_401', 'HTTP_403', 'HTTP_404', 'OFFLINE_MODE', 'CHECKSUM_MISMATCH'} or budget and budget.remaining() <= 0:
                break
            if attempt + 1 < max_attempts:
                delay = bounded_timeout(2)
                time.sleep(delay)
        if available and self.database_status() == ToolStatus.READY:
            original = self.data_diagnostics.get('vulnerability_db')
            self.data_diagnostics['vulnerability_db'] = ErrorDiagnostic('VULNERABILITY_DB_STALE',
                'Database refresh failed; scanning uses the previous cached vulnerability data.',
                'Retry the data update online; current vulnerability coverage is incomplete.',
                source=original.source if original else '')
            return ToolStatus.READY
        return ToolStatus.BROKEN

    def statuses(self) -> dict[str, ResolvedTool]:
        return {tool_id: self.resolve(tool_id) for tool_id in self.versions}

    def prepare_all(self, *, include_database: bool = True) -> dict[str, ResolvedTool]:
        results = {tool_id: self.ensure(tool_id) for tool_id in VERSIONS if tool_id not in ON_DEMAND_ENGINES}
        if include_database and results["trivy"].status == ToolStatus.READY:
            self.prepare_trivy_database(results["trivy"].path)
        return results
