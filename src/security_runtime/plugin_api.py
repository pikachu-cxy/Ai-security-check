"""Public scanner extension contract loaded from Python entry points."""
from __future__ import annotations

from dataclasses import dataclass

from .capabilities import Capability


SCANNER_ENTRY_POINT = "ai_security_runtime.scanners"


@dataclass(frozen=True)
class ScannerPluginMetadata:
    scanner_id: str
    display_name: str
    plugin_version: str
    scanner_version: str
    capabilities: frozenset[Capability]
    supported_languages: frozenset[str]
    supported_ecosystems: frozenset[str]
    required_engines: tuple[str, ...]
