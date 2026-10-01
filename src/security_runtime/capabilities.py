"""Product capabilities are independent of scanner and engine names."""
from __future__ import annotations

from enum import StrEnum

from .models import ScanMode, TargetProfile


class Capability(StrEnum):
    CODE_SAST = "CODE_SAST"
    SECRET_SCAN = "SECRET_SCAN"
    DEPENDENCY_VULN = "DEPENDENCY_VULN"
    IAC_MISCONFIG = "IAC_MISCONFIG"
    CONTAINER_VULN = "CONTAINER_VULN"
    LICENSE_SCAN = "LICENSE_SCAN"
    SBOM = "SBOM"
    PACKAGE_RISK = "PACKAGE_RISK"
    AI_SKILL_SECURITY = "AI_SKILL_SECURITY"
    MCP_SECURITY_STATIC = "MCP_SECURITY_STATIC"
    MCP_SECURITY_DYNAMIC = "MCP_SECURITY_DYNAMIC"
    AGENT_DYNAMIC_SECURITY = "AGENT_DYNAMIC_SECURITY"
    AI_INFRA_VULN = "AI_INFRA_VULN"
    LLM_JAILBREAK = "LLM_JAILBREAK"
    MODEL_API_INTEGRITY = "MODEL_API_INTEGRITY"
    AGENT_RUNTIME_SECURITY = "AGENT_RUNTIME_SECURITY"
    AI_APP_SECURITY = "AI_APP_SECURITY"


DYNAMIC_CAPABILITIES = {Capability.MCP_SECURITY_DYNAMIC, Capability.AGENT_DYNAMIC_SECURITY, Capability.LLM_JAILBREAK}


def requested_capabilities(profile: TargetProfile, mode: ScanMode, files: tuple[str, ...],
                           available: set[Capability] | None = None) -> set[Capability]:
    result = set()
    if profile.languages:
        result.add(Capability.CODE_SAST)
    if files or mode == ScanMode.RELEASE:
        result.add(Capability.SECRET_SCAN)
    manifest_names = {"requirements.txt", "pyproject.toml", "package.json", "package-lock.json", "Dockerfile", "pom.xml", "go.mod"}
    if (mode == ScanMode.RELEASE and profile.ecosystems) or (mode == ScanMode.FEATURE and any(name.rsplit("/", 1)[-1] in manifest_names - {"Dockerfile"} for name in files)):
        result.add(Capability.DEPENDENCY_VULN)
    if mode != ScanMode.QUICK and any(name.rsplit("/", 1)[-1] == "Dockerfile" or name.endswith((".tf", ".yaml", ".yml")) for name in files):
        result.add(Capability.IAC_MISCONFIG)
    # Plugins can add capabilities without core changes; supports() still scopes targets.
    builtin = {Capability.CODE_SAST, Capability.SECRET_SCAN, Capability.DEPENDENCY_VULN,
               Capability.IAC_MISCONFIG, Capability.CONTAINER_VULN, Capability.LICENSE_SCAN, Capability.SBOM}
    result.update((available or set()) - builtin)
    if mode == ScanMode.QUICK:
        result -= DYNAMIC_CAPABILITIES
    return result


class CapabilityRegistry:
    def __init__(self, scanner_registry):
        self.scanner_registry = scanner_registry

    def get_scanners(self, capability: Capability):
        return [scanner for scanner in self.scanner_registry.adapters if capability in scanner.capabilities]

    def get_available_scanners(self, capability: Capability):
        from .toolchain import ToolStatus

        manager = self.scanner_registry.tool_manager
        return [scanner for scanner in self.get_scanners(capability)
                if all(manager.resolve(engine).status == ToolStatus.READY for engine in scanner.required_engines())]

    def get_capabilities(self, scanner) -> frozenset[Capability]:
        return frozenset(scanner.capabilities)
