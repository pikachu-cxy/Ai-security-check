from __future__ import annotations

import time
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .findings import FindingNormalizer, deduplicate
from .capabilities import Capability, requested_capabilities
from .git import GitService
from .models import RunStatus, ScanContext, ScanMode, ScanResult, ScannerRun
from .planner import ScannerPlanner
from .risk import MESSAGES, RiskEngine
from .scanners import ScannerRegistry
from .storage import ScanStore, SQLiteStore
from .target import TargetDetector, DEPENDENCIES
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
        # TargetDetector validates every explicit path before any file is read.
        if scan_mode != ScanMode.RELEASE:
            manifests = set()
            directories = {root} if files else set()
            if scan_mode == ScanMode.FEATURE:
                for name in files:
                    directories.update(parent for parent in (root / name).parents if parent.is_relative_to(root))
            for directory in directories:
                for name in set(DEPENDENCIES) | {"Dockerfile"}:
                    path = directory / name
                    if path.is_file():
                        manifests.add(path.relative_to(root).as_posix())
            profile = TargetDetector().detect(root, sorted(set(files) | manifests))
        else:
            profile = TargetDetector().detect(root, files)
        files = [name for name in files if name in profile.files]
        changed_lines = git.changed_lines(files, scan_mode, staged=staged) if scan_mode != ScanMode.RELEASE else {}
        profile.git_info = {"branch": git.branch()}
        context = ScanContext(str(root), scan_mode, tuple(files), staged, rules_path,
                              tuple(name for name in profile.files if name not in files))
        normalizer = FindingNormalizer(root)
        findings = []
        runs: list[ScannerRun] = []
        no_changes = scan_mode != ScanMode.RELEASE and not files
        _, selected = ScannerPlanner(self.registry).plan(profile, context)
        if no_changes or not files:
            selected = []
        with ThreadPoolExecutor(max_workers=max(1, len(selected))) as pool:
            futures = {scanner.name: pool.submit(scanner.scan, context, normalizer) for scanner in selected}
            for scanner in self.registry.adapters:
                if scanner.name not in futures:
                    runs.append(ScannerRun(scanner.name, "", RunStatus.NOT_APPLICABLE, 0))
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
        planned_runs = [run for run in runs if run.status not in {RunStatus.SKIPPED, RunStatus.NOT_APPLICABLE}]
        successful = sum(run.status == RunStatus.SUCCESS for run in planned_runs)
        complete = bool(planned_runs) and successful == len(planned_runs)
        coverage = "FULL" if complete else "PARTIAL" if successful else "MINIMAL"
        release_status = RiskEngine().assess(findings, complete)
        wanted = requested_capabilities(profile, scan_mode, context.files)
        capability_results = {}
        for capability in (Capability.CODE_SAST, Capability.SECRET_SCAN, Capability.DEPENDENCY_VULN, Capability.IAC_MISCONFIG):
            supporting = [run for run in planned_runs if any(adapter.name == run.scanner and capability in adapter.capabilities for adapter in selected)]
            capability_results[capability] = ("NOT_APPLICABLE" if not files or capability not in wanted else
                "EXECUTED" if supporting and all(run.status == RunStatus.SUCCESS for run in supporting) else
                "UNAVAILABLE" if not supporting or all(run.status == RunStatus.UNAVAILABLE for run in supporting) else "FAILED")
        if complete and any(value in {"FAILED", "UNAVAILABLE"} for value in capability_results.values()):
            complete = False
            coverage = "PARTIAL" if successful else "MINIMAL"
            release_status = RiskEngine().assess(findings, False)
        if complete and capability_results[Capability.CODE_SAST] != "EXECUTED":
            coverage = "SCOPED"
        status = "COMPLETED" if complete else "PARTIAL"
        execution_state = "EXECUTED" if successful else "UNAVAILABLE" if planned_runs and all(run.status == RunStatus.UNAVAILABLE for run in planned_runs) else "FAILED"
        summary = MESSAGES[release_status]
        if no_changes or not files:
            status = execution_state = "NO_CHANGES" if no_changes else "NOT_APPLICABLE"
            coverage = "NONE"
            release_status = "NOT_ASSESSED"
            summary = "没有需要检查的代码变更。\n本次没有执行代码安全扫描。" if no_changes else "本次没有适用的安全检查，未执行扫描。"
        elif not complete:
            summary += "；Security check completed with limited coverage."
        result = ScanResult(str(uuid.uuid4()), scan_mode, profile, status, findings, runs, summary, release_status, round((time.monotonic()-start)*1000), coverage,
                            execution_state=execution_state, capability_results=capability_results)
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
        try:
            profile = TargetDetector().detect(root, [relative.as_posix()])
        except (ValueError, OSError):
            return {"finding_id": finding_id, "status": "UNKNOWN", "reason": "affected file cannot be safely profiled"}
        context = ScanContext(str(root), ScanMode.QUICK, (relative.as_posix(),))
        n = FindingNormalizer(root)
        successful = False
        observed = []
        origin_runs = []
        for adapter in self.registry.adapters:
            if adapter.name not in finding["scanner_sources"]:
                continue
            try:
                found, run = adapter.scan(context, n)
            except Exception:
                found, run = [], ScannerRun(adapter.name, "", RunStatus.FAILED, 0)
            origin_runs.append(run)
            if run.status == RunStatus.SUCCESS:
                successful = True
                observed.extend(found)
        if any(f.fingerprint == finding["fingerprint"] for f in observed):
            return {"finding_id": finding_id, "status": "STILL_PRESENT"}
        if not successful or len(origin_runs) != len(set(finding["scanner_sources"])) or any(run.status != RunStatus.SUCCESS for run in origin_runs):
            return {"finding_id": finding_id, "status": "UNKNOWN", "reason": "originating scanner unavailable or failed"}
        still = any(f.fingerprint == finding["fingerprint"] for f in observed)
        return {"finding_id": finding_id, "status": "STILL_PRESENT" if still else "RESOLVED"}
