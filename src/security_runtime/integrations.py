"""Project-scoped AI coding integrations, separate from scan execution."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from .integration_config import IntegrationConfigError, IntegrationConfigStore
from .integration_state import IntegrationStateStore, WorkspaceBinding
from .mcp_config import server_entry
from .mcp_verify import verify_mcp_entry


class IntegrationCapability(StrEnum):
    MCP = "MCP"
    HOOK = "HOOK"
    DEEPLINK = "DEEPLINK"
    EXTENSION = "EXTENSION"
    PROJECT_SCOPE = "PROJECT_SCOPE"
    GLOBAL_SCOPE = "GLOBAL_SCOPE"


class IntegrationStatusCode(StrEnum):
    NOT_INSTALLED = "NOT_INSTALLED"
    DETECTED = "DETECTED"
    CONNECTED = "CONNECTED"
    BROKEN = "BROKEN"
    NEEDS_RESTART = "NEEDS_RESTART"
    UNSUPPORTED = "UNSUPPORTED"


class InstallStrategy(StrEnum):
    PROJECT_CONFIG = "PROJECT_CONFIG"
    DEEPLINK = "DEEPLINK"
    EXTENSION = "EXTENSION"
    MARKETPLACE = "MARKETPLACE"


@dataclass(frozen=True)
class IntegrationStatus:
    integration_id: str
    display_name: str
    status: IntegrationStatusCode
    message: str
    details: dict[str, str] = field(default_factory=dict)
    repair_hint: str = ""


class IntegrationAdapter(Protocol):
    integration_id: str
    display_name: str

    def detect(self) -> bool: ...
    def status(self, workspace: Path) -> IntegrationStatus: ...
    def install(self, workspace: Path) -> IntegrationStatus: ...
    def verify(self, workspace: Path) -> IntegrationStatus: ...
    def repair(self, workspace: Path) -> IntegrationStatus: ...
    def uninstall(self, workspace: Path) -> IntegrationStatus: ...
    def capabilities(self) -> frozenset[IntegrationCapability]: ...


class ProjectMCPIntegration:
    integration_id = ""
    display_name = ""
    config_relative = ""
    install_strategy = InstallStrategy.PROJECT_CONFIG
    include_type = True

    def __init__(self, state: IntegrationStateStore | None = None):
        self.state = state or IntegrationStateStore()

    def capabilities(self) -> frozenset[IntegrationCapability]:
        return frozenset({IntegrationCapability.MCP, IntegrationCapability.PROJECT_SCOPE})

    def executable_candidates(self) -> tuple[Path, ...]:
        return ()

    def detect(self) -> bool:
        return any(candidate.is_file() for candidate in self.executable_candidates())

    def _config(self, workspace: Path) -> IntegrationConfigStore:
        return IntegrationConfigStore(workspace, self.config_relative)

    def _expected(self, workspace: Path) -> dict:
        return server_entry(workspace, self.integration_id, include_type=self.include_type)

    def _details(self, workspace: Path, *, health: str = "") -> dict[str, str]:
        workspace = workspace.resolve()
        record = self.state.get(self.integration_id, workspace)
        return {"scope": "PROJECT", "config_path": str(self._config(workspace).path),
                "workspace": str(workspace), "last_verified": (record or {}).get("last_verified_at") or "",
                "mcp_health": health, "command_path": (record or {}).get("command_path") or "",
                "configuration_status": "WRITTEN" if self._config(workspace).path.exists() else "MISSING",
                "runtime_self_test": (record or {}).get("runtime_self_test", "UNKNOWN"),
                "last_client_invocation": (record or {}).get("last_client_invocation_at", "")}

    def status(self, workspace: Path) -> IntegrationStatus:
        config = self._config(workspace)
        try:
            entry = config.entry()
        except IntegrationConfigError as exc:
            return IntegrationStatus(self.integration_id, self.display_name, IntegrationStatusCode.BROKEN,
                                     str(exc), self._details(workspace), f"security-check setup {self.integration_id} --verbose")
        if entry is None:
            status = IntegrationStatusCode.DETECTED if self.detect() else IntegrationStatusCode.NOT_INSTALLED
            return IntegrationStatus(self.integration_id, self.display_name, status,
                                     "Application detected" if self.detect() else "Application not detected", self._details(workspace))
        expected = self._expected(workspace)
        if (entry.get("command") != expected["command"] or entry.get("args") != expected["args"]
                or entry.get("env", {}).get("SECURITY_RUNTIME_WORKSPACE") != expected["env"]["SECURITY_RUNTIME_WORKSPACE"]
                or entry.get("env", {}).get("SECURITY_RUNTIME_INTEGRATION") != self.integration_id
                or (self.include_type and entry.get("type") != "stdio")):
            return IntegrationStatus(self.integration_id, self.display_name, IntegrationStatusCode.BROKEN,
                                     "Runtime path or workspace binding has changed", self._details(workspace),
                                     "security-check integrations repair")
        record = self.state.get(self.integration_id, workspace)
        if record and record.get("last_client_invocation_at"):
            return IntegrationStatus(self.integration_id, self.display_name, IntegrationStatusCode.CONNECTED,
                                     "Client invoked the Runtime in this workspace", self._details(workspace, health="VERIFIED"))
        if not record:
            return IntegrationStatus(self.integration_id, self.display_name, IntegrationStatusCode.BROKEN,
                                     "Project entry exists but Runtime verification is missing",
                                     self._details(workspace, health="UNKNOWN"),
                                     "security-check integrations repair")
        return IntegrationStatus(self.integration_id, self.display_name, IntegrationStatusCode.NEEDS_RESTART,
                                 "Configuration written; Runtime self-test passed; client connection not confirmed yet",
                                 self._details(workspace, health="RUNTIME_VERIFIED"))

    def install(self, workspace: Path) -> IntegrationStatus:
        config = self._config(workspace)
        entry = self._expected(workspace)
        health = {"ok": False, "message": ""}

        def verify() -> bool:
            health["ok"], health["message"] = verify_mcp_entry(entry, workspace)
            return health["ok"]

        config.install(entry, verify)
        if not health["ok"]:
            health["ok"], health["message"] = verify_mcp_entry(entry, workspace)
        if not health["ok"]:
            raise IntegrationConfigError(health["message"])
        prior = self.state.get(self.integration_id, workspace)
        created_at = prior["installed_at"] if prior else None
        binding = WorkspaceBinding.create(workspace, self.integration_id, created_at=created_at,
                                          last_verified_at=datetime.now(timezone.utc).isoformat())
        self.state.save(binding, IntegrationStatusCode.NEEDS_RESTART, str(config.path), entry["command"])
        return self.status(workspace)

    def verify(self, workspace: Path) -> IntegrationStatus:
        config = self._config(workspace)
        entry = config.entry()
        if entry is None:
            return self.status(workspace)
        ok, message = verify_mcp_entry(entry, workspace)
        if not ok:
            return IntegrationStatus(self.integration_id, self.display_name, IntegrationStatusCode.BROKEN,
                                     message, self._details(workspace, health="FAILED"),
                                     "security-check integrations repair")
        return self.status(workspace)

    def repair(self, workspace: Path) -> IntegrationStatus:
        if self._config(workspace).entry() is None:
            return self.status(workspace)
        return self.install(workspace)

    def uninstall(self, workspace: Path) -> IntegrationStatus:
        self._config(workspace).uninstall()
        self.state.remove(self.integration_id, workspace)
        return self.status(workspace)


class CursorIntegration(ProjectMCPIntegration):
    integration_id = "cursor"
    display_name = "Cursor"
    config_relative = ".cursor/mcp.json"

    def executable_candidates(self) -> tuple[Path, ...]:
        paths = []
        configured = os.getenv("SECURITY_RUNTIME_CURSOR_EXECUTABLE")
        if configured:
            paths.append(Path(configured))
        command = shutil.which("cursor")
        if command:
            paths.append(Path(command))
        paths.extend((Path(os.getenv("ProgramFiles", "C:/Program Files")) / "cursor" / "Cursor.exe",
                      Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Programs/cursor/Cursor.exe"))
        return tuple(paths)


class WorkBuddyIntegration(ProjectMCPIntegration):
    integration_id = "workbuddy"
    display_name = "WorkBuddy"
    config_relative = ".workbuddy/mcp.json"
    include_type = False  # The official WorkBuddy project example uses command/args/env.

    def executable_candidates(self) -> tuple[Path, ...]:
        paths = []
        configured = os.getenv("SECURITY_RUNTIME_WORKBUDDY_EXECUTABLE")
        if configured:
            paths.append(Path(configured))
        paths.append(Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Programs/WorkBuddyAI/WorkBuddyAI.exe")
        return tuple(paths)


class GenericMCPIntegration:
    integration_id = "generic-mcp"
    display_name = "Generic MCP"

    def capabilities(self) -> frozenset[IntegrationCapability]:
        return frozenset({IntegrationCapability.MCP, IntegrationCapability.PROJECT_SCOPE})


class IntegrationRegistry:
    def __init__(self, state: IntegrationStateStore | None = None):
        self.state = state or IntegrationStateStore()
        self.adapters: dict[str, IntegrationAdapter | GenericMCPIntegration] = {
            "cursor": CursorIntegration(self.state), "workbuddy": WorkBuddyIntegration(self.state),
            "generic-mcp": GenericMCPIntegration()}

    def get(self, integration_id: str) -> IntegrationAdapter:
        adapter = self.adapters.get(integration_id)
        if adapter is None or integration_id == "generic-mcp":
            raise KeyError(integration_id)
        return adapter

    def native(self) -> tuple[IntegrationAdapter, ...]:
        return self.get("cursor"), self.get("workbuddy")
