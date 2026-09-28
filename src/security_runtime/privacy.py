from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .models import Finding, ScanResult
from .redactor import SecretRedactor


class ContextProvider(Protocol):
    def build_context(self, root: Path, finding: Finding) -> str: ...


class LocalContextProvider:
    def build_context(self, root: Path, finding: Finding) -> str:
        root = root.resolve()
        path = (root / finding.file_path).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            return ""
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start, end = max(0, finding.line_start - 6), min(len(lines), finding.line_end + 5)
        return SecretRedactor().redact("\n".join(lines[start:end]))[:4000]


class CloudSyncAdapter(Protocol):
    def sync_metadata(self, result: ScanResult) -> None: ...


@dataclass
class DisabledCloudSync:
    enabled: bool = False

    def sync_metadata(self, result: ScanResult) -> None:
        return None


class AIProvider(Protocol):
    def generate_fix(self, finding: Finding, redacted_context: str) -> dict: ...
