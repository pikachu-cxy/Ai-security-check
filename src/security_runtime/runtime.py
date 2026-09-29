from __future__ import annotations

import time
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .findings import FindingNormalizer, deduplicate
from .git import GitService
from .models import RunStatus, ScanContext, ScanMode, ScanResult, ScannerRun
from .planner import ScannerPlanner
from .risk import MESSAGES, RiskEngine
from .scanners import ScannerRegistry
from .storage import ScanStore, SQLiteStore
from .target import TargetDetector
from .workspace import WorkspaceResolver, WorkspaceError

logger = logging.getLogger(__name__)


class SecurityRuntime:
    def __init__(self, registry: ScannerRegistry | None = None, store: ScanStore | None = None):
        self.registry = registry or ScannerRegistry()
        self.store = store or SQLiteStore()

    def scan(self, repository_path: str | Path | None = None, mode: str = "quick", staged: bool = False, rules_path: str | None = None) -> ScanResult:
        start = time.monotonic()
        root = WorkspaceResolver().resolve(repository_path).path
        scan_mode = ScanMode(mode)
        git = GitService(root)
        files = git.changed_files(scan_mode, staged=staged)
        # Scanner targets are constrained to real files inside this repository.
        files = [f for f in files if (root / f).resolve().is_relative_to(root)]
        changed_lines = git.changed_lines(files, scan_mode, staged=staged) if scan_mode != ScanMode.RELEASE else {}
        if scan_mode == ScanMode.QUICK:
            top_level = [p.name for p in root.iterdir() if p.is_file() and p.name in {"requirements.txt", "pyproject.toml", "package.json", "pom.xml", "build.gradle", "go.mod", "Dockerfile"}]
            profile = TargetDetector().detect(root, sorted(set(files + top_level)))
        else:
            profile = TargetDetector().detect(root)
        profile.git_info = {"branch": git.branch()}
        context = ScanContext(str(root), scan_mode, tuple(files), staged, rules_path)
        normalizer = FindingNormalizer(root)
        findings = []
        runs: list[ScannerRun] = []
        _, selected = ScannerPlanner(self.registry).plan(profile, context)
        with ThreadPoolExecutor(max_workers=max(1, len(selected))) as pool:
            futures = {scanner.name: pool.submit(scanner.scan, context, normalizer) for scanner in selected}
            for scanner in self.registry.adapters:
                if scanner.name not in futures:
                    runs.append(ScannerRun(scanner.name, "", RunStatus.SKIPPED, 0, error="outside scan scope"))
                    continue
                try:
                    found, run = futures[scanner.name].result()
                except Exception as exc:
                    found, run = [], ScannerRun(scanner.name, "", RunStatus.FAILED, 0, error=type(exc).__name__)
                if scan_mode != ScanMode.RELEASE and getattr(scanner, "filter_changed_lines", False):
                    found = [f for f in found if f.line_start in changed_lines.get(f.file_path, set())]
                    run.finding_count = len(found)
                findings.extend(found)
                runs.append(run)
        findings = deduplicate(findings)
        planned_runs = [run for run in runs if run.status != RunStatus.SKIPPED]
        no_changes = scan_mode != ScanMode.RELEASE and not files
        successful = sum(run.status == RunStatus.SUCCESS for run in planned_runs)
        complete = no_changes or (bool(planned_runs) and successful == len(planned_runs))
        coverage = "FULL" if complete else "PARTIAL" if successful else "MINIMAL"
        release_status = RiskEngine().assess(findings, complete)
        summary = "没有需要检查的代码变更" if no_changes else MESSAGES[release_status]
        if not complete:
            summary += "；Security check completed with limited coverage."
        result = ScanResult(str(uuid.uuid4()), scan_mode, profile, "COMPLETED" if complete else "PARTIAL", findings, runs, summary, release_status, round((time.monotonic()-start)*1000), coverage)
        self.store.save(result)
        logger.info("scan_completed", extra={"scan_id": result.scan_id, "mode": result.mode, "duration_ms": result.duration_ms})
        return result

    def get_findings(self, scan_id: str) -> list[dict]:
        scan = self.store.get_scan(scan_id)
        return scan["findings"] if scan else []

    def generate_fix(self, finding_id: str) -> dict:
        record = self.store.get_finding(finding_id)
        if not record:
            raise KeyError("Finding not found")
        finding, _ = record
        return {"finding_id": finding_id, "root_cause": finding["plain_title"], "fix_strategy": finding["fix_advice"], "coding_agent_prompt": f"Fix {finding['plain_title']} at {finding['file_path']}:{finding['line_start']}. {finding['fix_advice']} Preserve behavior and add a regression test. Do not include secrets in output."}

    def verify(self, finding_id: str, workspace_path: str | Path | None = None) -> dict:
        record = self.store.get_finding(finding_id)
        if not record:
            raise KeyError("Finding not found")
        finding, scan = record
        root = WorkspaceResolver().resolve(scan["target_profile"]["path"]).path
        if workspace_path is not None and WorkspaceResolver().resolve(workspace_path).path != root:
            raise WorkspaceError("Finding does not belong to the requested workspace")
        relative = Path(finding["file_path"])
        file = (root / relative).resolve()
        if not file.is_relative_to(root.resolve()):
            return {"finding_id": finding_id, "status": "UNKNOWN", "reason": "invalid path"}
        if not file.exists():
            return {"finding_id": finding_id, "status": "RESOLVED", "reason": "file removed"}
        # Reuse the same adapters, scoped to the affected file. Only a successful
        # run from the originating scanner can establish resolution.
        profile = TargetDetector().detect(root)
        context = ScanContext(str(root), ScanMode.QUICK, (relative.as_posix(),))
        n = FindingNormalizer(root)
        successful = False
        observed = []
        for adapter in self.registry.plan(profile, context):
            if adapter.name not in finding["scanner_sources"]:
                continue
            found, run = adapter.scan(context, n)
            if run.status == RunStatus.SUCCESS:
                successful = True
                observed.extend(found)
        if not successful:
            return {"finding_id": finding_id, "status": "UNKNOWN", "reason": "originating scanner unavailable or failed"}
        still = any(f.fingerprint == finding["fingerprint"] for f in observed)
        return {"finding_id": finding_id, "status": "STILL_PRESENT" if still else "RESOLVED"}
