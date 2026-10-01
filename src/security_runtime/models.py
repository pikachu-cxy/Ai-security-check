from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class ScanMode(StrEnum):
    QUICK = "quick"
    FEATURE = "feature"
    RELEASE = "release"


class TargetType(StrEnum):
    CODE = "CODE"
    AI_APP = "AI_APP"
    AI_SKILL = "AI_SKILL"
    WEB = "WEB"
    MOBILE_APP = "MOBILE_APP"


class RunStatus(StrEnum):
    SUCCESS = "SUCCESS"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


@dataclass
class Target:
    id: str
    path: str
    target_type: str = TargetType.CODE
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    git_info: dict[str, str] = field(default_factory=dict)


@dataclass
class TargetProfile:
    path: str
    target_type: str = TargetType.CODE
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    git_info: dict[str, str] = field(default_factory=dict)


@dataclass
class AIAppProfile:
    providers: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)
    rag: bool = False
    memory: bool = False
    mcp_servers: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    external_inputs: list[str] = field(default_factory=list)
    sensitive_actions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScanPlan:
    scanners: tuple[str, ...]
    files: tuple[str, ...]
    capabilities: tuple[str, ...] = ()


@dataclass
class Finding:
    id: str
    category: str
    title: str
    plain_title: str
    description: str
    impact: str
    severity: str
    confidence: str
    file_path: str
    line_start: int
    line_end: int
    evidence: str
    fix_advice: str
    scanner_sources: list[str]
    fingerprint: str
    status: str = "OPEN"
    technical_details: dict[str, str] = field(default_factory=dict)


@dataclass
class ScannerRun:
    scanner: str
    version: str
    status: str
    duration_ms: int
    finding_count: int = 0
    error: str = ""


@dataclass
class ScanResult:
    scan_id: str
    mode: str
    target_profile: TargetProfile
    status: str
    findings: list[Finding]
    scanner_runs: list[ScannerRun]
    summary: str
    release_status: str
    duration_ms: int
    coverage: str = "FULL"
    execution_state: str = "EXECUTED"
    coverage_scope: str = "PLANNED_FILES"
    capability_results: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ScanContext:
    root: str
    mode: ScanMode
    files: tuple[str, ...]
    staged: bool = False
    rules_path: str | None = None
    context_files: tuple[str, ...] = ()
