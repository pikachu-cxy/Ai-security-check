"""Local integration bindings and minimal dogfood telemetry."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .storage import SQLiteStore
from .workspace import WorkspaceResolver


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class WorkspaceBinding:
    workspace_id: str
    root: str
    git_root: str
    integration_id: str
    scope: str
    created_at: str
    last_verified_at: str | None = None

    @classmethod
    def create(cls, root: Path, integration_id: str, *, created_at: str | None = None,
               last_verified_at: str | None = None) -> "WorkspaceBinding":
        resolved = WorkspaceResolver().resolve(root).path
        identity = hashlib.sha256(str(resolved).casefold().encode("utf-8")).hexdigest()[:24]
        return cls(identity, str(resolved), str(resolved), integration_id, "PROJECT",
                   created_at or _now(), last_verified_at)

    @classmethod
    def from_environment(cls) -> "WorkspaceBinding | None":
        value = os.getenv("SECURITY_RUNTIME_WORKSPACE")
        if not value:
            return None
        return cls.create(Path(value), os.getenv("SECURITY_RUNTIME_INTEGRATION", "generic-mcp"))


@dataclass(frozen=True)
class DogfoodEvent:
    integration: str
    workspace: str
    scan_mode: str = ""
    duration_ms: int = 0
    finding_count: int = 0
    coverage: str = ""
    fix_generated: bool = False
    verify_result: str = ""


class IntegrationStateStore:
    def __init__(self, path: Path | None = None):
        self.path = path or SQLiteStore.default_path().parent / "integrations.db"

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as database, database:
            database.execute("CREATE TABLE IF NOT EXISTS integrations (integration_id TEXT NOT NULL, workspace TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY (integration_id, workspace))")
            database.execute("CREATE TABLE IF NOT EXISTS dogfood_events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, event TEXT NOT NULL)")

    def _connect(self):
        return sqlite3.connect(self.path)

    def save(self, binding: WorkspaceBinding, status: str, config_path: str, command_path: str) -> None:
        self._initialize()
        prior = self.get(binding.integration_id, Path(binding.root)) or {}
        state = {"binding": asdict(binding), "status": status, "scope": binding.scope,
                 "installed_at": binding.created_at, "last_verified_at": binding.last_verified_at,
                 "config_path": config_path, "command_path": command_path,
                 "last_client_invocation_at": prior.get("last_client_invocation_at", ""),
                 "runtime_self_test": "PASSED" if binding.last_verified_at else "UNKNOWN"}
        with closing(self._connect()) as database, database:
            database.execute("INSERT OR REPLACE INTO integrations VALUES (?, ?, ?)",
                             (binding.integration_id, binding.root, json.dumps(state)))

    def client_invoked(self, integration_id: str, workspace: Path) -> None:
        prior = self.get(integration_id, workspace)
        if not prior:
            return
        prior["last_client_invocation_at"] = _now()
        prior["status"] = "CONNECTED"
        with closing(self._connect()) as database, database:
            database.execute("UPDATE integrations SET state = ? WHERE integration_id = ? AND workspace = ?",
                             (json.dumps(prior), integration_id, str(workspace.resolve())))

    def get(self, integration_id: str, workspace: Path) -> dict | None:
        if not self.path.is_file():
            return None
        try:
            with closing(self._connect()) as database:
                row = database.execute("SELECT state FROM integrations WHERE integration_id = ? AND workspace = ?",
                                       (integration_id, str(workspace.resolve()))).fetchone()
        except sqlite3.OperationalError:
            return None
        return json.loads(row[0]) if row else None

    def remove(self, integration_id: str, workspace: Path) -> None:
        if not self.path.is_file():
            return
        with closing(self._connect()) as database, database:
            database.execute("DELETE FROM integrations WHERE integration_id = ? AND workspace = ?",
                             (integration_id, str(workspace.resolve())))

    def event(self, event: DogfoodEvent) -> None:
        # The schema deliberately has no prompt, source, secret or evidence fields.
        self._initialize()
        with closing(self._connect()) as database, database:
            database.execute("INSERT INTO dogfood_events (created_at, event) VALUES (?, ?)",
                             (_now(), json.dumps(asdict(event))))

    def stats(self, days: int = 7) -> dict:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = []
        if self.path.is_file():
            try:
                with closing(self._connect()) as database:
                    rows = database.execute("SELECT event FROM dogfood_events WHERE created_at >= ?", (since,)).fetchall()
            except sqlite3.OperationalError:
                pass
        events = [json.loads(row[0]) for row in rows]
        scans = [event for event in events if event.get("scan_mode")]
        verified = [event for event in events if event.get("verify_result") == "RESOLVED"]
        integrations: dict[str, int] = {}
        for event in scans:
            integration = event["integration"]
            integrations[integration] = integrations.get(integration, 0) + 1
        return {"days": days, "scans": len(scans), "issues_found": sum(event["finding_count"] for event in scans),
                "issues_resolved": len(verified),
                "average_scan_ms": round(sum(event["duration_ms"] for event in scans) / len(scans)) if scans else 0,
                "integrations": integrations}
