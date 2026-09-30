# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 AI Security Runtime contributors
"""Public scanner extension contract loaded from Python entry points."""
from __future__ import annotations

from dataclasses import dataclass
import os
import sys
from pathlib import Path

from .capabilities import Capability


SCANNER_ENTRY_POINT = "ai_security_runtime.scanners"


def discover_plugin_directory(default: Path) -> None:
    """Allow the same entry-point API in source and standalone installations."""
    directory = Path(os.getenv("SECURITY_RUNTIME_PLUGIN_DIR", str(default))).expanduser().resolve()
    if directory.is_dir() and str(directory) not in sys.path:
        sys.path.insert(0, str(directory))


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
