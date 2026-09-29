"""Replaceable SAST execution engine contract. Rule packs remain independent."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .rulepacks import ResolvedRulePack


@dataclass(frozen=True)
class SASTRequest:
    workspace: Path
    rule_pack: ResolvedRulePack
    scan_scope: tuple[str, ...]


class SASTEngineProvider(Protocol):
    engine_id: str

    def command(self, executable: str, request: SASTRequest) -> list[str]: ...


class SemgrepEngineProvider:
    engine_id = "semgrep"

    def command(self, executable: str, request: SASTRequest) -> list[str]:
        if not request.rule_pack.path.is_dir():
            raise ValueError("Local rule pack is missing")
        return [str(Path(executable).resolve()), "scan", "--config", str(request.rule_pack.path),
                "--json", "--quiet", "--metrics", "off", "--disable-version-check", *request.scan_scope]
