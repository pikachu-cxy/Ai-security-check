"""Engine contract, separate from scanners and product capabilities."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .licensing import GITLEAKS_LICENSE, TRIVY_LICENSE, SEMGREP_LICENSE, LicenseMetadata


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
    "semgrep": EngineDescriptor("semgrep", "Semgrep", EngineType.PYTHON_PACKAGE, "1.178.0", "PyPI",
                                "https://semgrep.dev", "LGPL-2.1-only", False, "", ("windows", "linux", "macos"), "RUNTIME_DEPENDENCY", ExecutionTrust.SAFE_LOCAL, SEMGREP_LICENSE),
    "gitleaks": EngineDescriptor("gitleaks", "Gitleaks", EngineType.BINARY, "8.30.0", "Official GitHub Release",
                                 "https://github.com/gitleaks/gitleaks", "MIT", False, "", ("windows", "linux", "macos"), "PINNED_RELEASE", ExecutionTrust.SAFE_LOCAL, GITLEAKS_LICENSE),
    "trivy": EngineDescriptor("trivy", "Trivy", EngineType.BINARY, "0.74.0", "Official GitHub Release",
                              "https://trivy.dev", "Apache-2.0", False, "", ("windows", "linux", "macos"), "PINNED_RELEASE", ExecutionTrust.SAFE_LOCAL, TRIVY_LICENSE),
}
