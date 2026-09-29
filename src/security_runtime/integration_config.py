"""Shared, transactional project MCP configuration editing."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Callable


SERVER_NAME = "ai-security-runtime"


class IntegrationConfigError(ValueError):
    pass


class IntegrationConfigStore:
    def __init__(self, workspace: Path, relative_path: str):
        self.workspace = workspace.resolve()
        self.path = self.workspace / relative_path
        self.backup = self.path.with_name(self.path.name + ".security-check.bak")

    def _check_path(self) -> None:
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise IntegrationConfigError("Configuration symlinks are not supported")
        if not self.path.parent.resolve().is_relative_to(self.workspace):
            raise IntegrationConfigError("Configuration path is outside the workspace")

    def load(self) -> dict:
        self._check_path()
        if not self.path.exists():
            return {"mcpServers": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrationConfigError("Existing configuration is invalid JSON. No changes were made.") from exc
        if not isinstance(value, dict) or not isinstance(value.get("mcpServers", {}), dict):
            raise IntegrationConfigError("Existing configuration has an invalid mcpServers object. No changes were made.")
        return value

    def entry(self) -> dict | None:
        value = self.load().get("mcpServers", {}).get(SERVER_NAME)
        return value if isinstance(value, dict) else None

    def _atomic_bytes(self, content: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".security-check-", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def _transaction(self, next_value: dict, verify: Callable[[], bool]) -> bool:
        self._check_path()
        original = self.path.read_bytes() if self.path.exists() else None
        serialized = (json.dumps(next_value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        if original is not None and json.loads(original.decode("utf-8-sig")) == next_value:
            return False
        if self.backup.exists():
            raise IntegrationConfigError("An earlier configuration backup needs recovery before setup")
        if original is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.path, self.backup)
        restored = False
        committed = False
        try:
            self._atomic_bytes(serialized)
            if not verify():
                raise IntegrationConfigError("Runtime MCP verification failed")
            committed = True
        except Exception:
            if original is None:
                self.path.unlink(missing_ok=True)
            else:
                self._atomic_bytes(original)
            restored = True
            raise
        finally:
            if restored or committed:
                self.backup.unlink(missing_ok=True)
        return True

    def install(self, entry: dict, verify: Callable[[], bool]) -> bool:
        value = self.load()
        value.setdefault("mcpServers", {})[SERVER_NAME] = entry
        return self._transaction(value, verify)

    def uninstall(self) -> bool:
        value = self.load()
        if SERVER_NAME not in value.get("mcpServers", {}):
            return False
        value["mcpServers"].pop(SERVER_NAME)
        return self._transaction(value, lambda: True)

    def rollback(self) -> bool:
        self._check_path()
        if not self.backup.is_file():
            return False
        self._atomic_bytes(self.backup.read_bytes())
        self.backup.unlink()
        return True
