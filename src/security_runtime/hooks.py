from __future__ import annotations

import os
import subprocess
from enum import StrEnum
from pathlib import Path

from .workspace import WorkspaceResolver


class HookEvent(StrEnum):
    FILE_CHANGED = "FILE_CHANGED"
    AGENT_STOP = "AGENT_STOP"
    BEFORE_COMMAND = "BEFORE_COMMAND"
    BEFORE_MCP = "BEFORE_MCP"
    PRE_COMMIT = "PRE_COMMIT"


def install_pre_commit(root: Path) -> Path:
    root = WorkspaceResolver().resolve(root).path
    proc = subprocess.run(["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root), "rev-parse", "--git-path", "hooks"], capture_output=True, text=True, timeout=5, check=True)
    hooks = Path(proc.stdout.strip())
    if not hooks.is_absolute():
        hooks = root / hooks
    destination = hooks / "pre-commit"
    if destination.exists():
        raise ValueError(f"Hook already exists: {destination}")
    script = "#!/bin/sh\nsecurity-check scan --mode quick --staged\n"
    destination.write_text(script, encoding="utf-8", newline="\n")
    destination.chmod(destination.stat().st_mode | 0o111)
    return destination
