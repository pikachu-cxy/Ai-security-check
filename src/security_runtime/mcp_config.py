"""Portable local MCP launch configuration."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path

from .workspace import WorkspaceResolver


@dataclass(frozen=True)
class RuntimeCommand:
    command: str
    args: tuple[str, ...]


def resolve_runtime_command() -> RuntimeCommand:
    if getattr(sys, "frozen", False):
        installed = shutil.which("security-check")
        if installed:
            try:
                if Path(installed).samefile(sys.executable):
                    # Preserve the package manager's stable alias so upgrades
                    # can retarget it without invalidating saved MCP configs.
                    return RuntimeCommand(str(Path(installed).absolute()), ("mcp",))
            except OSError:
                pass
        return RuntimeCommand(str(Path(sys.executable).resolve()), ("mcp",))
    name = "security-check.exe" if os.name == "nt" else "security-check"
    adjacent = Path(sys.executable).resolve().with_name(name)
    if adjacent.is_file():
        return RuntimeCommand(str(adjacent), ("mcp",))
    scripts_entry = Path(sysconfig.get_path("scripts")) / name
    if scripts_entry.is_file():
        return RuntimeCommand(str(scripts_entry.resolve()), ("mcp",))
    installed = shutil.which("security-check")
    if installed and Path(installed).is_file():
        return RuntimeCommand(str(Path(installed).resolve()), ("mcp",))
    return RuntimeCommand(str(Path(sys.executable).resolve()), ("-m", "security_runtime.cli", "mcp"))


def server_entry(workspace: Path, integration_id: str, *, include_type: bool = True) -> dict:
    root = WorkspaceResolver().resolve(workspace).path
    runtime = resolve_runtime_command()
    value = {"command": runtime.command, "args": list(runtime.args),
             "env": {"SECURITY_RUNTIME_WORKSPACE": str(root), "SECURITY_RUNTIME_INTEGRATION": integration_id}}
    if include_type:
        value = {"type": "stdio", **value}
    return value


def json_config(workspace: Path) -> str:
    return json.dumps({"mcpServers": {"ai-security-runtime": server_entry(workspace, "generic-mcp")}}, indent=2, ensure_ascii=False)


def toml_config(workspace: Path) -> str:
    entry = server_entry(workspace, "generic-mcp")
    quote = json.dumps
    return ("[mcp_servers.ai_security_runtime]\n"
            f"command = {quote(entry['command'])}\n"
            f"args = [{', '.join(quote(item) for item in entry['args'])}]\n"
            "[mcp_servers.ai_security_runtime.env]\n"
            + "\n".join(f"{key} = {quote(value)}" for key, value in entry["env"].items()) + "\n")


def copy_to_clipboard(value: str) -> bool:
    if os.name != "nt":
        return False
    try:
        result = subprocess.run(["clip"], input=value, text=True, capture_output=True,
                                timeout=5, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
