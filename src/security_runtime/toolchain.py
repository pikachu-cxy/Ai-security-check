"""Pinned, per-user scanner tool lifecycle. No system installation is changed."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
import importlib.metadata
import json
import logging
import os
import platform
import shutil
import subprocess
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
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from .engines import BUILTIN_ENGINES
from .licensing import LicenseMetadata, LicensePolicy


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

    def to_dict(self) -> dict:
        return asdict(self)


def _manifest(tool: str, version: str, platform_name: str, arch: str, asset: str, digest: str, homepage: str, license_name: str) -> ToolManifest:
    owner = "gitleaks/gitleaks" if tool == "gitleaks" else "aquasecurity/trivy"
    return ToolManifest(tool, tool.title(), version, platform_name, arch,
                        f"https://github.com/{owner}/releases/download/v{version}/{asset}", digest,
                        "zip" if asset.endswith(".zip") else "tar.gz",
                        tool + (".exe" if platform_name == "windows" else ""), homepage, license_name,
                        BUILTIN_ENGINES[tool].license_metadata)


_ASSETS = {
    ("gitleaks", "windows", "x64"): ("gitleaks_8.30.0_windows_x64.zip", "54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573"),
    ("gitleaks", "linux", "x64"): ("gitleaks_8.30.0_linux_x64.tar.gz", "79a3ab579b53f71efd634f3aaf7e04a0fa0cf206b7ed434638d1547a2470a66e"),
    ("gitleaks", "macos", "x64"): ("gitleaks_8.30.0_darwin_x64.tar.gz", "ca221d012d247080c2f6f61f4b7a83bffa2453806b0c195c795bbe9a8c775ed5"),
    ("gitleaks", "macos", "arm64"): ("gitleaks_8.30.0_darwin_arm64.tar.gz", "b251ab2bcd4cd8ba9e56ff37698c033ebf38582b477d21ebd86586d927cf87e7"),
    ("trivy", "windows", "x64"): ("trivy_0.74.0_windows-64bit.zip", "94c40e0696e4b907a74b7b2e1438d5d72ebaca83115817407f568a002d520842"),
    ("trivy", "linux", "x64"): ("trivy_0.74.0_Linux-64bit.tar.gz", "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"),
    ("trivy", "macos", "x64"): ("trivy_0.74.0_macOS-64bit.tar.gz", "472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485"),
    ("trivy", "macos", "arm64"): ("trivy_0.74.0_macOS-ARM64.tar.gz", "1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11"),
}
VERSIONS = {"semgrep": "1.178.0", "gitleaks": "8.30.0", "trivy": "0.74.0"}
HOMEPAGES = {"gitleaks": "https://github.com/gitleaks/gitleaks", "trivy": "https://trivy.dev"}
LICENSES = {"gitleaks": "MIT", "trivy": "Apache-2.0"}
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


class ToolSourceProvider(Protocol):
    def download(self, manifest: ToolManifest, destination: Path) -> None: ...


class OfficialReleaseProvider:
    def download(self, manifest: ToolManifest, destination: Path) -> None:
        if not manifest.download_url.startswith("https://github.com/"):
            raise ValueError("Only pinned official HTTPS release assets are accepted")
        request = urllib.request.Request(manifest.download_url, headers={"User-Agent": "ai-security-runtime"})
        digest = hashlib.sha256()
        size = 0
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
            if not response.url.startswith("https://"):
                raise ValueError("Insecure release redirect")
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                size += len(chunk)
                if size > 200_000_000:
                    raise ValueError("Release asset exceeds 200 MB")
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != manifest.sha256:
            destination.unlink(missing_ok=True)
            raise ValueError("Release SHA256 mismatch")


class ToolManager:
    def __init__(self, root: Path | None = None, provider: ToolSourceProvider | None = None):
        self.root = root if root is not None else default_data_root()
        self.provider = provider or OfficialReleaseProvider()
        self.versions = dict(VERSIONS)
        self.python_engines = {"semgrep"}
        self.python_requirements = {"semgrep": (f"semgrep=={VERSIONS['semgrep']}", False, None)}
        self.extra_manifests: dict[tuple[str, str, str], ToolManifest] = {}
        self.extra_licenses: dict[str, LicenseMetadata] = {}
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
        base = self.root / "tools" / tool_id / self.versions[tool_id]
        return base / "venv" / ("Scripts" if os.name == "nt" else "bin") / executable if tool_id in self.python_engines else base / executable

    def trivy_cache_dir(self) -> Path:
        return Path(os.getenv("SECURITY_RUNTIME_TRIVY_CACHE_DIR") or os.getenv("TRIVY_CACHE_DIR") or self.root / "cache" / "trivy")

    def database_status(self) -> ToolStatus:
        directory = self.trivy_cache_dir() / "db"
        return ToolStatus.READY if (directory / "trivy.db").is_file() and (directory / "metadata.json").is_file() else ToolStatus.MISSING

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
            pass
        return None

    def _version(self, tool_id: str, path: Path) -> str:
        try:
            proc = subprocess.run([str(path.resolve()), "--version"], stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=8, check=False)
            if proc.returncode:
                return ""
            return (proc.stdout + proc.stderr).strip()[:160]
        except (OSError, subprocess.TimeoutExpired):
            return ""

    def _check(self, tool_id: str, path: Path, source: ToolSource) -> ResolvedTool:
        path = path.expanduser().resolve()
        if not path.is_file():
            return ResolvedTool(tool_id, "", str(path), source, ToolStatus.MISSING)
        if source == ToolSource.MANAGED and tool_id in self.python_engines and path.is_relative_to(self.root / "tools"):
            install_dir = path.parents[2]
            if not all((install_dir / name).is_file() for name in ("install.json", "metadata.json", "LICENSE", "NOTICE")):
                return ResolvedTool(tool_id, "", str(path), source, ToolStatus.BROKEN, "Python package installation is incomplete")
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
        if expected not in output:
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
        if tool_id == "semgrep":
            executable = "semgrep.exe" if os.name == "nt" else "semgrep"
            # The declared Python dependency belongs to this interpreter and
            # takes priority over an unrelated Semgrep found on system PATH.
            # Python package metadata pins this executable's package version.
            runtime_exe = Path(sysconfig.get_path("scripts")) / executable
            try:
                if runtime_exe.is_file() and importlib.metadata.version("semgrep") == self.versions["semgrep"]:
                    return ResolvedTool(tool_id, self.versions[tool_id], str(runtime_exe.resolve()), ToolSource.MANAGED, ToolStatus.READY)
            except importlib.metadata.PackageNotFoundError:
                pass
        system = shutil.which(tool_id)
        if system:
            return self._check(tool_id, Path(system), ToolSource.SYSTEM)
        if tool_id not in self.python_engines and self.manifest(tool_id) is None:
            return ResolvedTool(tool_id, "", "", None, ToolStatus.UNSUPPORTED_PLATFORM)
        return ResolvedTool(tool_id, "", "", None, ToolStatus.MISSING)

    def ensure(self, tool_id: str, *, offline: bool | None = None) -> ResolvedTool:
        try:
            current = self.resolve(tool_id)
        except Exception as exc:
            logger.warning("tool_resolution_failed tool=%s reason=%s", tool_id, type(exc).__name__)
            return ResolvedTool(tool_id, "", "", None, ToolStatus.BROKEN, type(exc).__name__)
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
            return ResolvedTool(tool_id, "", "", None, ToolStatus.OFFLINE, "tool unavailable offline")
        try:
            if requirement:
                self.install_python_package(tool_id, self.versions[tool_id], requirement[0], no_index=requirement[1], executable_name=requirement[2])
            else:
                manifest = self.manifest(tool_id)
                if manifest is None:
                    return ResolvedTool(tool_id, "", "", None, ToolStatus.UNSUPPORTED_PLATFORM)
                self._install_binary(manifest)
            return self.resolve(tool_id)
        except Exception as exc:
            logger.warning("tool_install_failed tool=%s reason=%s", tool_id, type(exc).__name__)
            return ResolvedTool(tool_id, "", "", None, ToolStatus.BROKEN, str(exc)[:200])

    def _install_binary(self, manifest: ToolManifest) -> None:
        parent = self.root / "tools" / manifest.tool_id
        parent.mkdir(parents=True, exist_ok=True)
        final = parent / manifest.version
        with tempfile.TemporaryDirectory(dir=parent, prefix="install-") as tmp:
            staging = Path(tmp)
            archive = staging / "release.archive"
            self.provider.download(manifest, archive)
            executable = staging / manifest.executable_name
            if manifest.archive_type == "zip":
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

    def install_python_package(self, tool_id: str, version: str, requirement: str, *, executable_name: str | None = None, no_index: bool = False) -> Path:
        license_metadata = self.license_metadata(tool_id)
        if not LicensePolicy.can_auto_download(license_metadata):
            raise ValueError("Python engine installation prohibited by license policy")
        self.versions[tool_id] = version
        self.python_engines.add(tool_id)
        parent = self.root / "tools" / tool_id
        parent.mkdir(parents=True, exist_ok=True)
        final = parent / version
        if final.exists():
            shutil.rmtree(final)
        final.mkdir()
        try:
            environment = final / "venv"
            venv.EnvBuilder(with_pip=True).create(environment)
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            command = [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-input"]
            if no_index:
                command += ["--no-index", "--no-build-isolation"]
            command.append(requirement)
            proc = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600, check=False)
            if proc.returncode:
                raise ValueError("Python package engine installation failed: " + proc.stderr[-200:])
            executable = environment / ("Scripts" if os.name == "nt" else "bin") / (executable_name or tool_id + (".exe" if os.name == "nt" else ""))
            if not executable.is_file():
                raise ValueError("Python package engine did not provide the expected command")
            if version not in self._version(tool_id, executable):
                raise ValueError("Python package engine failed version validation")
            license_candidates = list(environment.rglob("*.dist-info/LICENSE")) + list(environment.rglob("*.dist-info/LICENSE.txt"))
            own_license = next((candidate for candidate in license_candidates
                                if candidate.parent.name.replace("-", "_").lower().startswith(tool_id.replace("-", "_").lower() + "_")), None)
            bundled_license = Path(__file__).parent / "licenses" / tool_id / "LICENSE"
            if own_license is not None:
                shutil.copy2(own_license, final / "LICENSE")
            elif bundled_license.is_file():
                shutil.copy2(bundled_license, final / "LICENSE")
            elif license_metadata.notice_required:
                raise ValueError("Python package license text is missing")
            notice = Path(__file__).parent / "licenses" / tool_id / "NOTICE"
            if notice.is_file():
                shutil.copy2(notice, final / "NOTICE")
            else:
                (final / "NOTICE").write_text(f"{tool_id} {version}\n{license_metadata.copyright}\n{license_metadata.license_spdx}\n", encoding="utf-8")
            (final / "metadata.json").write_text(json.dumps({"name": tool_id, "version": version,
                "download_source": requirement, "sha256": sha256_file(Path(requirement)) if Path(requirement).is_file() else "",
                "license": license_metadata.license_spdx, "installed_at": datetime.now(timezone.utc).isoformat()}), encoding="utf-8")
            marker = final / "install.json.tmp"
            marker.write_text(json.dumps({"tool_id": tool_id, "version": version, "requirement": requirement}), encoding="utf-8")
            os.replace(marker, final / "install.json")
            return executable
        except Exception:
            shutil.rmtree(final, ignore_errors=True)
            raise

    def prepare_trivy_database(self, binary: str, *, offline: bool | None = None) -> ToolStatus:
        if self.database_status() == ToolStatus.READY:
            return ToolStatus.READY
        if offline is None:
            offline = os.getenv("SECURITY_RUNTIME_OFFLINE") == "1"
        if offline:
            return ToolStatus.OFFLINE
        cache = self.trivy_cache_dir()
        cache.mkdir(parents=True, exist_ok=True)
        # Public vulnerability DB downloads must not depend on the user's
        # Docker credential helper or Docker being installed at all.
        docker_config = cache / "docker-config"
        docker_config.mkdir(exist_ok=True)
        env = dict(os.environ)
        env["DOCKER_CONFIG"] = str(docker_config)
        for attempt in range(2):
            try:
                proc = subprocess.run([str(Path(binary).resolve()), "image", "--download-db-only", "--cache-dir", str(cache), "--quiet"],
                                      stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env,
                                      timeout=900, check=False)
                if proc.returncode == 0 and self.database_status() == ToolStatus.READY:
                    return ToolStatus.READY
                logger.warning("trivy_database_prepare_failed attempt=%s detail=%s", attempt + 1, proc.stderr[-300:])
            except (OSError, subprocess.TimeoutExpired) as exc:
                logger.warning("trivy_database_prepare_failed attempt=%s reason=%s", attempt + 1, type(exc).__name__)
            if attempt == 0:
                time.sleep(2)
        return ToolStatus.BROKEN

    def statuses(self) -> dict[str, ResolvedTool]:
        return {tool_id: self.resolve(tool_id) for tool_id in self.versions}

    def prepare_all(self, *, include_database: bool = True) -> dict[str, ResolvedTool]:
        results = {tool_id: self.ensure(tool_id) for tool_id in VERSIONS}
        if include_database and results["trivy"].status == ToolStatus.READY:
            self.prepare_trivy_database(results["trivy"].path)
        return results
