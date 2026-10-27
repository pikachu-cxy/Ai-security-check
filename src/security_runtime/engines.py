"""Engine contract, separate from scanners and product capabilities."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .licensing import GITLEAKS_LICENSE, TRIVY_LICENSE, SEMGREP_LICENSE, OPENGREP_LICENSE, OSV_SCANNER_LICENSE, LicenseMetadata


class EngineType(StrEnum):
    BINARY = "BINARY"
    PYTHON_PACKAGE = "PYTHON_PACKAGE"
    DOCKER = "DOCKER"
    LOCAL_SERVICE = "LOCAL_SERVICE"
    REMOTE_SERVICE = "REMOTE_SERVICE"


class ExecutionTrust(StrEnum):
    SAFE_LOCAL = "SAFE_LOCAL"
    UNTRUSTED_TARGET = "UNTRUSTED_TARGET"
    SANDBOX_REQUIRED = "SANDBOX_REQUIRED"
    NETWORK_REQUIRED = "NETWORK_REQUIRED"


@dataclass(frozen=True)
class EngineDescriptor:
    engine_id: str
    display_name: str
    engine_type: EngineType
    version: str
    source: str
    homepage: str
    license: str
    attribution_required: bool
    attribution_text: str
    platforms: tuple[str, ...]
    install_strategy: str
    execution_trust: ExecutionTrust
    license_metadata: LicenseMetadata


class ManagedEngine(Protocol):
    """Lifecycle contract. Service and sandbox engines may supply other executors."""

    descriptor: EngineDescriptor

    def prepare(self) -> object: ...
    def execute(self, request: object) -> object: ...


BUILTIN_ENGINES = {
    "opengrep": EngineDescriptor("opengrep", "OpenGrep", EngineType.BINARY, "1.32.0", "Official GitHub Release",
                                "https://github.com/opengrep/opengrep", "LGPL-2.1-only", True,
                                "OpenGrep and contributors", ("windows", "linux", "macos"), "PINNED_RELEASE",
                                ExecutionTrust.SAFE_LOCAL, OPENGREP_LICENSE),
    "semgrep": EngineDescriptor("semgrep", "Semgrep", EngineType.PYTHON_PACKAGE, "1.178.0", "PyPI",
                                "https://semgrep.dev", "LGPL-2.1-only", False, "", ("windows", "linux", "macos"), "MANAGED_PYTHON_PACKAGE", ExecutionTrust.SAFE_LOCAL, SEMGREP_LICENSE),
    "gitleaks": EngineDescriptor("gitleaks", "Gitleaks", EngineType.BINARY, "8.30.0", "Official GitHub Release",
                                 "https://github.com/gitleaks/gitleaks", "MIT", False, "", ("windows", "linux", "macos"), "PINNED_RELEASE", ExecutionTrust.SAFE_LOCAL, GITLEAKS_LICENSE),
    "trivy": EngineDescriptor("trivy", "Trivy", EngineType.BINARY, "0.74.0", "Official GitHub Release",
                              "https://trivy.dev", "Apache-2.0", False, "", ("windows", "linux", "macos"), "PINNED_RELEASE", ExecutionTrust.SAFE_LOCAL, TRIVY_LICENSE),
    "osv-scanner": EngineDescriptor("osv-scanner", "OSV-Scanner", EngineType.BINARY, "2.6.0", "Official GitHub Release",
                              "https://github.com/google/osv-scanner", "Apache-2.0", False, "", ("windows", "linux", "macos"), "PINNED_RELEASE", ExecutionTrust.SAFE_LOCAL, OSV_SCANNER_LICENSE),
}
ON_DEMAND_ENGINES = frozenset({"osv-scanner", "semgrep"})  # Historical explicit use only; never a fallback.
