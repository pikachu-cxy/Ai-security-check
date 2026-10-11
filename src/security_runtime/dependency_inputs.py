"""Dependency input identity shared by discovery and incremental planning.

This classifies filenames only. Callers must still validate workspace paths and
record each provider's actual inventory coverage; recognition is not proof that
a complete dependency graph was scanned.
"""
from __future__ import annotations

from pathlib import PurePath


DEPENDENCIES = {
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "poetry.lock": "pip",
    "Pipfile.lock": "pip",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "gradle.lockfile": "gradle",
    "buildscript-gradle.lockfile": "gradle",
    "go.mod": "go",
    "go.sum": "go",
}
DEPENDENCY_NAMES = frozenset(DEPENDENCIES)


def is_dependency_input(path: str | PurePath) -> bool:
    """Recognize a manifest/lockfile in a validated relative path on either OS."""
    return str(path).replace("\\", "/").rsplit("/", 1)[-1] in DEPENDENCY_NAMES
