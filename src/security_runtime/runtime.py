from __future__ import annotations

import time
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextvars import copy_context
from dataclasses import replace
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
from .progress import NullProgressReporter, progress_context, current_reporter, emit, checkpoint, ScanCancelled
from .scanners import BaseScanner
from .dependency_fallback import should_fallback, dependency_status, capability_detail

logger = logging.getLogger(__name__)


def aggregate_provider_statuses(runs: list[ScannerRun]) -> str:
    if not runs:
        return "UNAVAILABLE"
    successes = sum(run.status == RunStatus.SUCCESS for run in runs)
    if successes == len(runs):
        return "EXECUTED"
    if successes:
        return "PARTIAL"
    return "UNAVAILABLE" if all(run.status == RunStatus.UNAVAILABLE for run in runs) else "FAILED"


class SecurityRuntime:
    def __init__(self, registry: ScannerRegistry | None = None, store: ScanStore | None = None):
        self.registry = registry or ScannerRegistry()
        self.store = store or SQLiteStore()

    def scan(self, repository_path: str | Path | None = None, mode: str = "quick", staged: bool = False, rules_path: str | None = None, *, progress=None) -> ScanResult:
        reporter = progress or NullProgressReporter()
        with progress_context(reporter):
            try:
                return self._scan(repository_path, mode, staged, rules_path)
            except (KeyboardInterrupt, ScanCancelled):
                reporter.cancel()
                emit('SCAN_CANCELLED')
                raise

    def _scan(self, repository_path, mode, staged, rules_path):
        start = time.monotonic()
        checkpoint()
        emit('SCAN_STARTED', message=f'模式：{mode}')
        scan_mode = ScanMode(mode)
        emit('WORKSPACE_DISCOVERY_STARTED')
        workspace = WorkspaceResolver().resolve(repository_path, allow_non_git_explicit=True, allow_non_git_source=True)
        root = workspace.path
        emit('WORKSPACE_DISCOVERY_COMPLETED', message=f'项目：{root.name}')
        if not workspace.is_git and (scan_mode != ScanMode.RELEASE or staged):
            raise WorkspaceError("Quick, feature and staged scans require Git. Use security-check scan --mode release --path <project> for a source directory.")
        git = GitService(root) if workspace.is_git else None
        checkpoint()
        emit('TARGET_DISCOVERY_STARTED')
        files = git.changed_files(scan_mode, staged=staged) if workspace.is_git else TargetDetector().detect(root).files
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
        profile.git_info = {"branch": git.branch()} if workspace.is_git else {}
        emit('TARGET_DISCOVERY_COMPLETED', message=f'{len(files)} 个扫描文件')
        context = ScanContext(str(root), scan_mode, tuple(files), staged, rules_path,
                              tuple(name for name in profile.files if name not in files))
        normalizer = FindingNormalizer(root)
        findings = []
        runs: list[ScannerRun] = []
        no_changes = scan_mode != ScanMode.RELEASE and not files
        checkpoint()
        emit('PLANNING_STARTED')
        rule_plans={}
        if files and not no_changes:
            for adapter in self.registry.adapters:
                if callable(getattr(adapter,'plan_rules',None)) and adapter.supports(profile,context):
                    rule_plans[adapter.name]=adapter.plan_rules(profile,context)
                    plan=rule_plans[adapter.name]
                    emit('RULE_PLAN_READY',scanner=adapter.name,message=f'{len(plan.rules)} 条适用规则 · {len(plan.files)} 个 SAST 文件')
                    if not plan.rules:
                        emit('SAST_NOT_COVERED',message='代码安全未执行：当前规则包没有适用于 ' + ' / '.join(plan.detected_languages) + ' 的规则')
        _, selected = ScannerPlanner(self.registry).plan(profile, context)
        selected=[adapter for adapter in selected if adapter.name not in rule_plans or rule_plans[adapter.name].rules]
        if no_changes or not files:
            selected = []
        emit('PLAN_READY', message=f'将执行 {len(selected)} 个安全引擎')

        def execute(scanner):
            checkpoint()
            if not isinstance(scanner, BaseScanner):
                emit('SCANNER_STARTED', scanner=scanner.name, capability=tuple(scanner.capabilities))
            try:
                scanner_context=replace(context,rule_plan=rule_plans[scanner.name]) if scanner.name in rule_plans else context
                found, run = scanner.scan(scanner_context, normalizer)
            except ScanCancelled:
                raise
            except Exception:
                found, run = [], ScannerRun(scanner.name, '', RunStatus.FAILED, 0,
                    error_code='SCANNER_FAILED', error_summary='Scanner did not complete successfully.',
                    remediation='Inspect local engine configuration and retry the check.')
            if scan_mode != ScanMode.RELEASE and getattr(scanner, 'filter_changed_lines', False):
                found = [f for f in found if any(f.line_start<=line<=f.line_end for line in changed_lines.get(f.file_path,set()))]
                run.finding_count = len(found)
            run.capabilities = tuple(sorted(scanner.capabilities))
            run.provider = getattr(scanner, 'engine_id', '') or scanner.scanner_id
            run.provider_role = getattr(scanner, 'provider_role', 'PRIMARY')
            if scanner.name in rule_plans and not run.rule_coverage:
                run.rule_coverage=rule_plans[scanner.name].coverage(run.status)
            event_type = {'SUCCESS': 'SCANNER_COMPLETED', 'FAILED': 'SCANNER_FAILED',
                          'UNAVAILABLE': 'SCANNER_UNAVAILABLE', 'TIMEOUT': 'SCANNER_TIMEOUT'}.get(run.status)
            if event_type:
                emit(event_type, scanner=run.scanner, scanner_version=run.version,
                    capability=run.capabilities, duration_ms=run.duration_ms, finding_count=run.finding_count,
                    error_code=run.error_code, source=run.source)
            provider_runs = [run]
            if Capability.DEPENDENCY_VULN in scanner.capabilities and run.provider_role == 'PRIMARY' and should_fallback(run):
                fallback = next((adapter for adapter in getattr(self.registry, 'fallback_adapters', [])
                    if Capability.DEPENDENCY_VULN in adapter.capabilities and adapter.supports(profile, context)), None)
                if fallback:
                    emit('FALLBACK_SELECTED', scanner=fallback.name, capability=(Capability.DEPENDENCY_VULN,),
                        error_code=run.error_code, message='依赖检查切换至 OSV-Scanner')
                    more, fallback_runs = execute(fallback)
                    found.extend(more)
                    provider_runs.extend(fallback_runs)
            return found, provider_runs

        pool = ThreadPoolExecutor(max_workers=max(1, len(selected)))
        try:
            futures = {scanner.name: pool.submit(copy_context().run, execute, scanner) for scanner in selected}
            for scanner in self.registry.adapters:
                if scanner.name not in futures:
                    plan=rule_plans.get(scanner.name)
                    runs.append(ScannerRun(scanner.name,'',RunStatus.NOT_COVERED if plan and not plan.rules else RunStatus.NOT_APPLICABLE,0,
                        capabilities=tuple(scanner.capabilities),rule_coverage=plan.coverage('NOT_COVERED') if plan else {}))
                    continue
                try:
                    while True:
                        try:
                            found, provider_runs = futures[scanner.name].result(timeout=.1)
                            break
                        except FutureTimeout:
                            checkpoint()
                except ScanCancelled:
                    raise
                except Exception as exc:
                    found, provider_runs = [], [ScannerRun(scanner.name, "", RunStatus.FAILED, 0,
                        error_code="SCANNER_FAILED", error_summary="Scanner did not complete successfully.",
                        remediation="Inspect local engine configuration and retry the check.")]
                findings.extend(found)
                runs.extend(provider_runs)
        except (KeyboardInterrupt, ScanCancelled):
            current_reporter().cancel()
            raise
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        findings = deduplicate(findings)
        rule_coverage=next((run.rule_coverage for run in runs if run.rule_coverage),{})
        planned_runs = [run for run in runs if run.status not in {RunStatus.SKIPPED, RunStatus.NOT_APPLICABLE, RunStatus.NOT_COVERED}]
        successful = sum(run.status == RunStatus.SUCCESS for run in planned_runs)
        complete = bool(planned_runs) and successful == len(planned_runs)
        coverage = "FULL" if complete else "PARTIAL" if successful else "MINIMAL"
        release_status = RiskEngine().assess(findings, complete)
        wanted = requested_capabilities(profile, scan_mode, context.files)
        capability_results = {}
        for capability in (Capability.CODE_SAST, Capability.SECRET_SCAN, Capability.DEPENDENCY_VULN, Capability.IAC_MISCONFIG):
            supporting = [run for run in planned_runs if capability in run.capabilities]
            aggregate = dependency_status(supporting) if capability == Capability.DEPENDENCY_VULN else aggregate_provider_statuses(supporting)
            capability_results[capability] = "NOT_APPLICABLE" if not files or capability not in wanted else aggregate
        if rule_coverage and files:
            capability_results[Capability.CODE_SAST]=rule_coverage['status']
        capability_details = {cap: capability_detail([run for run in planned_runs if cap in run.capabilities], state)
                              for cap, state in capability_results.items()}
        if rule_coverage:
            capability_details[Capability.CODE_SAST]['coverage'] = 'FULL' if capability_results[Capability.CODE_SAST]=='EXECUTED' else 'PARTIAL' if capability_results[Capability.CODE_SAST]=='PARTIAL' else 'NONE'
        complete = bool(planned_runs) and all(value in {'EXECUTED','NOT_APPLICABLE'} for value in capability_results.values())
        # Third-party capabilities retain their independent provider contract.
        complete = complete and all(run.status == RunStatus.SUCCESS for run in planned_runs
            if not set(run.capabilities).intersection(capability_results))
        coverage = "FULL" if complete else "PARTIAL" if successful else "MINIMAL"
        release_status = RiskEngine().assess(findings, complete)
        if complete and capability_results[Capability.CODE_SAST] != "EXECUTED":
            coverage = "SCOPED"
        status = "COMPLETED" if complete else "PARTIAL"
        execution_state = "EXECUTED" if successful else "UNAVAILABLE" if planned_runs and all(run.status == RunStatus.UNAVAILABLE for run in planned_runs) else "FAILED"
        if not planned_runs and rule_coverage.get('status')=='NOT_COVERED':
            execution_state='NOT_COVERED'
        summary = MESSAGES[release_status]
        if no_changes or not files:
            status = execution_state = "NO_CHANGES" if no_changes else "NOT_APPLICABLE"
            coverage = "NONE"
            release_status = "NOT_ASSESSED"
            summary = "没有需要检查的代码变更。\n本次没有执行代码安全扫描。" if no_changes else "本次没有适用的安全检查，未执行扫描。"
        elif not complete:
            summary += "；Security check completed with limited coverage."
        result = ScanResult(str(uuid.uuid4()), scan_mode, profile, status, findings, runs, summary, release_status, round((time.monotonic()-start)*1000), coverage,
                            execution_state=execution_state, capability_results=capability_results, capability_details=capability_details, rule_coverage=rule_coverage)
        self.store.save(result)
        emit('SCAN_COMPLETED', duration_ms=result.duration_ms, finding_count=len(result.findings))
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
        root = WorkspaceResolver().resolve(scan["target_profile"]["path"], allow_non_git_explicit=True).path
        if workspace_path is not None and WorkspaceResolver().resolve(workspace_path, allow_non_git_explicit=True).path != root:
            raise WorkspaceError("Finding does not belong to the requested workspace")
        from .verification import VerificationService
        return VerificationService(self.registry).verify_many(root, [finding], scan)[0]
