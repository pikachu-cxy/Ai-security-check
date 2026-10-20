from __future__ import annotations

import time
import uuid
import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import nullcontext
from contextvars import copy_context
from dataclasses import asdict, replace
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
from .scanners import BaseScanner, PatternSASTScanner
from .scan_request import ScanRequest, ScanBinding, ScanInputError, SourceKind
from .scan_input import capture_scan_input, index_inventory
from .dependency_fallback import should_fallback, dependency_status, capability_detail
from .scanner_observation import milliseconds
from .dependency_inputs import is_dependency_input

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


def combined_rule_coverage(runs: list[ScannerRun]) -> dict:
    """Keep each provider's rule identity; a successful extra check cannot mask failure."""
    providers = {run.scanner: run.rule_coverage for run in runs if run.rule_coverage}
    if not providers:
        return {}
    result = dict(next(iter(providers.values())))
    if len(providers) == 1:
        return result
    result['providers'] = providers
    states = [item['status'] for item in providers.values()]
    result['status'] = ('EXECUTED' if all(state in {'EXECUTED', 'NOT_APPLICABLE'} for state in states)
                        else 'PARTIAL' if any(state in {'EXECUTED', 'PARTIAL'} for state in states)
                        else result['status'])
    result['total_provider_selected'] = sum(item.get('total_selected', 0) for item in providers.values())
    result['total_provider_executed'] = sum(item.get('total_executed', 0) for item in providers.values())
    return result


class SecurityRuntime:
    def __init__(self, registry: ScannerRegistry | None = None, store: ScanStore | None = None):
        self.registry = registry or ScannerRegistry()
        self.store = store or SQLiteStore()

    def scan(self, repository_path: str | Path | None = None, mode: str = "quick", staged: bool = False, rules_path: str | None = None, *, progress=None, request: ScanRequest | None = None, observer=None, execution=None) -> ScanResult:
        from .background_preparation import current_preparation, ACTIVE
        from .verification_policy import local_recheck, local_recheck_requested
        preparation = current_preparation()
        preparing = preparation['status'] in ACTIVE and not preparation.get('ready')
        reporter = execution or progress or NullProgressReporter()
        with progress_context(reporter), (local_recheck() if preparing and not local_recheck_requested() else nullcontext()):
            try:
                if request is not None:
                    if not isinstance(request, ScanRequest):
                        raise ScanInputError('SCAN_INPUT_REQUEST_INVALID')
                    if repository_path is not None and Path(repository_path).resolve() != request.workspace_root.resolve():
                        raise ScanInputError('SCAN_INPUT_WORKSPACE_MISMATCH')
                    repository_path, mode = request.workspace_root, request.mode
                    staged = request.source_kind == SourceKind.INDEX
                    rules_path = request.rules_path
                result = self._scan(repository_path, mode, staged, rules_path, request, observer, execution)
                if preparing:
                    from .background_preparation import preparation_message
                    result.background_preparation = preparation | {'message': preparation_message(preparation),
                        'execution_policy': 'AVAILABLE_LOCAL_COMPONENTS_ONLY', 'missing_checks': 'PENDING'}
                    if request is None and mode == 'quick' and not staged and not rules_path:
                        from .closeout import CloseoutService
                        try:
                            job = CloseoutService(self).prepare(result.target_profile.path, source_scan_id=result.scan_id,
                                source='MANUAL_QUICK_PREPARATION_PENDING')
                            result.background_preparation['closeout_ref'] = job['closeout_ref']
                            result.background_preparation['background_registered'] = job.get('background_registered', False)
                        except (ValueError, OSError, sqlite3.DatabaseError):
                            # Registration limits/errors must never discard the
                            # already persisted available-component results.
                            result.background_preparation.update(background_registered=False,
                                pending_source_scan_id=result.scan_id, pending_reason='CLOSEOUT_REGISTRATION_INCOMPLETE')
                return result
            except (KeyboardInterrupt, ScanCancelled):
                reporter.cancel()
                emit('SCAN_CANCELLED')
                raise

    def _scan(self, repository_path, mode, staged, rules_path, request=None, observer=None, attempt=None):
        start = time.monotonic()
        observed_start = time.perf_counter()
        stage_start = time.perf_counter()
        observed = {'timing_ms': {'state_persistence': None, 'total': None,
            'reuse_proof_prepare': None, 'reuse_proof_seal': None}, 'providers': {}}
        checkpoint()
        emit('SCAN_STARTED', message=f'模式：{mode}')
        emit('WORKSPACE_DISCOVERY_STARTED')
        scan_mode = ScanMode(mode)
        workspace = WorkspaceResolver().resolve(repository_path, allow_non_git_explicit=True, allow_non_git_source=True)
        if staged and not workspace.is_git:
            raise WorkspaceError('Staged scans require Git; use release mode without --staged for a source directory.')
        if staged and scan_mode != ScanMode.QUICK:
            raise WorkspaceError('INDEX_SCAN_REQUIRES_GIT_QUICK_MODE')
        if not workspace.is_git and scan_mode != ScanMode.RELEASE and request is None:
            raise WorkspaceError('Quick and feature scans require Git; use release mode for a source directory, or an explicit validated input request.')
        git = GitService(workspace.path) if workspace.is_git else None
        emit('WORKSPACE_DISCOVERY_COMPLETED', message=f'项目：{workspace.path.name}')
        observed['timing_ms']['workspace_discovery'] = milliseconds(stage_start)
        stage_start = time.perf_counter()
        emit('TARGET_DISCOVERY_STARTED')
        index_names, selection_revision = index_inventory(git) if staged else ((), None)
        initial_files = (list(request.requested_files) if request is not None else
            git.changed_files(scan_mode, staged=staged) if git else None)
        detector = TargetDetector()
        discovery_skipped = []
        if initial_files is None:
            initial = detector.detect(workspace.path, select_scan_targets=True)
            initial_files = initial.files
            discovery_skipped = initial.skipped_files
        changed_files = tuple(initial_files)
        changed_dependencies = tuple(name for name in changed_files
            if is_dependency_input(name) and not set(Path(name).parts) & detector.ignored)
        if request is not None and request.dependency_changes is not None:
            if not set(request.dependency_changes).issubset(changed_dependencies):
                raise ScanInputError('SCAN_INPUT_DEPENDENCY_SCOPE_INVALID')
            changed_dependencies = request.dependency_changes
        manifests = set(request.context_files if request is not None else ())
        if scan_mode != ScanMode.RELEASE:
            directories = {Path('.')} if initial_files else set()
            if scan_mode == ScanMode.FEATURE:
                for name in initial_files:
                    directories.update(Path(name).parents)
            elif scan_mode == ScanMode.QUICK:
                for name in initial_files:
                    if is_dependency_input(name):
                        directories.update(Path(name).parents)
            for directory in directories:
                for name in set(DEPENDENCIES) | {'Dockerfile'}:
                    candidate = (directory / name).as_posix()
                    if (candidate in index_names if staged else (workspace.path / candidate).is_file()):
                        manifests.add(candidate)
        if initial_files:
            for name in ('.gitleaks.toml', '.gitleaksignore', '.semgrepignore'):
                if (name in index_names if staged else (workspace.path / name).is_file()):
                    manifests.add(name)
            import os
            for name in ('GITLEAKS_CONFIG', 'TRIVY_CONFIG'):
                value = os.getenv(name)
                if not value:
                    continue
                configured = Path(value).expanduser()
                configured = ((workspace.path / configured).resolve() if not configured.is_absolute()
                              else configured.resolve())
                if configured.is_relative_to(workspace.path):
                    candidate = configured.relative_to(workspace.path).as_posix()
                    if (candidate in index_names if staged else configured.is_file()):
                        manifests.add(candidate)
        candidates = sorted(set(initial_files) | manifests)
        if staged:
            present = sorted(set(candidates).intersection(index_names))
            skipped = []
        else:
            initial = detector.detect(workspace.path, candidates, select_scan_targets=True)
            present = initial.files
            skipped = [*discovery_skipped, *initial.skipped_files]
        targets = tuple(name for name in initial_files if name in present)
        context_files = tuple(name for name in present if name not in targets)
        absent = tuple(name for name in changed_files if name not in present and
            (name not in index_names if staged else not (workspace.path / name).exists()))
        expected_absent = request.absent_files if request is not None else ()
        if not set(expected_absent).issubset(absent):
            raise ScanInputError('SCAN_INPUT_ABSENCE_CHANGED')
        rule_pack = None
        rule_manager = None
        rule_root = Path(rules_path) if rules_path else None
        bindings = list(request.bindings if request is not None else ())
        for adapter in self.registry.adapters:
            reader = getattr(adapter, 'input_bindings', None)
            if callable(reader):
                for actual in reader():
                    if any(value.kind == actual.kind and value.name == actual.name and value != actual for value in bindings):
                        raise ScanInputError('SCAN_INPUT_BINDING_CHANGED')
                    if actual not in bindings:
                        bindings.append(actual)
        for adapter in self.registry.adapters:
            if not isinstance(adapter, PatternSASTScanner):
                continue
            try:
                candidate_pack = adapter.rule_packs.resolve(user_path=Path(rules_path) if rules_path else None)
                if rule_pack is not None and candidate_pack != rule_pack:
                    raise ScanInputError('SCAN_INPUT_RULE_PACK_MISMATCH')
                rule_pack, rule_manager = candidate_pack, adapter.rule_packs
                rule_root = rule_pack.path
            except ScanInputError:
                raise
            except (OSError, ValueError, KeyError):
                # Missing rules stay a provider gap; other capabilities still run.
                rule_root = None
                continue
        if rule_pack is not None:
            actual = ScanBinding('RULES', rule_pack.descriptor.rule_pack_id, rule_pack.checksum)
            if any(value.kind == actual.kind and value.name == actual.name and value != actual for value in bindings):
                raise ScanInputError('SCAN_INPUT_BINDING_CHANGED')
            if actual not in bindings:
                bindings.append(actual)
        fixed_request = ScanRequest(workspace.path, scan_mode,
            SourceKind.INDEX if staged else SourceKind.WORKTREE, targets, context_files,
            absent, changed_dependencies if scan_mode != ScanMode.RELEASE else None,
            rule_root, tuple(bindings), selection_revision,
            code_preference=request.code_preference if request else 'FULL',
            recheck_native=request.recheck_native if request else False)
        inventory_reader = None
        if scan_mode == ScanMode.RELEASE and not staged:
            def inventory_reader():
                names = git.changed_files('release') if git else None
                return TargetDetector().detect(workspace.path, names, select_scan_targets=True).files
        key = self.store.evidence_key() if hasattr(self.store, 'evidence_key') else None
        initial_changed_lines = (git.changed_lines(list(targets), scan_mode, staged=staged)
            if git and scan_mode != ScanMode.RELEASE and request is None else {})
        # Resolve source-dependent routing before copying deferred rule packs.
        source_request = replace(fixed_request, rules_path=None)
        with capture_scan_input(source_request, git=git, identity_key=key,
                                inventory_reader=inventory_reader,
                                private_parent=attempt.private_parent if attempt is not None else None,
                                on_created=attempt.input_created if attempt is not None else None,
                                on_removed=attempt.input_removed if attempt is not None else None) as view:
            root = view.execution_root
            profile = TargetDetector().detect(root, list(fixed_request.source_paths), select_scan_targets=True)
            profile.skipped_files = sorted([*profile.skipped_files, *skipped], key=lambda row: row['path'])
            files = [name for name in targets if name in profile.files]
            changed_lines = (git.changed_lines(files, scan_mode, staged=staged)
                if git and scan_mode != ScanMode.RELEASE and request is None else {})
            if changed_lines != initial_changed_lines:
                # Moving diff metadata cannot suppress a finding. Inspect the
                # complete captured target files instead of filtering by it.
                changed_lines = None
            profile.git_info = {'branch': git.branch()} if git else {}
            profile.path = str(workspace.path)
            bound_pack = None
            context = ScanContext(str(root), scan_mode, tuple(files), staged,
                str(view.rules_path) if view.rules_path is not None else None,
                tuple(name for name in profile.files if name not in files),
                dependency_changes=changed_dependencies if scan_mode != ScanMode.RELEASE else None,
                logical_root=str(workspace.path), input_view=view, bound_rule_pack=bound_pack)
            emit('TARGET_DISCOVERY_COMPLETED', message=f'{len(files)} 个扫描文件')
            observed['timing_ms']['target_preparation'] = milliseconds(stage_start)
            from .scan_freshness import capture
            source_context = capture(root, self.store, mode=mode, staged=staged,
                rules_path=rules_path, hook_scope=request.files if request is not None else None,
                logical_root=workspace.path, selection=profile)
            execution = self
            if fixed_request.code_preference == 'CANONICAL_DYNAMIC_WHEN_ELIGIBLE':
                from .dynamic_function import NativeFunctionScanner, quick_function_candidate_scope
                from .scanners import SemgrepAdapter
                native = any(type(adapter) is NativeFunctionScanner for adapter in self.registry.adapters)
                other_code = any(Capability.CODE_SAST in adapter.capabilities and
                    type(adapter) not in {NativeFunctionScanner, SemgrepAdapter} for adapter in self.registry.adapters)
                choice = quick_function_candidate_scope(root, files, has_native_family=fixed_request.recheck_native)
                if native and not other_code and choice['eligible']:
                    registry = ScannerRegistry([adapter for adapter in self.registry.adapters if type(adapter) is not SemgrepAdapter],
                        tool_manager=self.registry.tool_manager, fallback_adapters=self.registry.fallback_adapters)
                    registry.code_scope_notice = ('本次快速检查只覆盖这些文件中的动态 Function / eval 调用；'
                        '其他代码安全规则尚未执行，需要完整扫描确认。')
                    observed['code_selection'] = dict(applied=True, notice=registry.code_scope_notice,
                        basis='CAPTURED_INPUT', input_id=view.input_id)
                    execution = SecurityRuntime(registry, self.store)
            selected_rule_provider = any(isinstance(adapter, PatternSASTScanner) and adapter.supports(profile, context)
                for adapter in execution.registry.adapters)
            capture_rules = rule_root is not None and (selected_rule_provider or bool(rules_path))
            with (view.with_rules(rule_root) if capture_rules else nullcontext(view)) as final_view:
                bound_pack = (rule_manager.bind_input(rule_pack, final_view.rules_path)
                    if rule_pack is not None and selected_rule_provider else None)
                final_context = replace(context, input_view=final_view, bound_rule_pack=bound_pack,
                    rules_path=str(final_view.rules_path) if final_view.rules_path else None)
                if observed.get('code_selection'):
                    observed['code_selection']['input_id'] = final_view.input_id
                if attempt is not None:
                    attempt.input_ready(final_view)
                return execution._execute_scan(workspace, final_context, profile, changed_lines, observer,
                    source_context, final_view, start, observed_start, observed, attempt)

    def _execute_scan(self, workspace, context, profile, changed_lines, hook_observer,
                      source_context, view, start, observed_start, observed, attempt=None):
        root = view.execution_root
        scan_mode, staged = context.mode, context.staged
        files, changed_dependencies = list(context.files), tuple(context.dependency_changes or ())
        normalizer = FindingNormalizer(root, identity_root=workspace.path)
        stage_start = time.perf_counter()
        findings = []
        runs: list[ScannerRun] = []
        has_targets = bool(files or changed_dependencies)
        no_changes = scan_mode != ScanMode.RELEASE and not has_targets
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
        if no_changes or not has_targets:
            selected = []
        emit('PLAN_READY', message=f'将执行 {len(selected)} 个安全引擎')
        observed['timing_ms']['rule_planning'] = milliseconds(stage_start)
        reuse_identity = None
        if (scan_mode == ScanMode.RELEASE and not staged and not source_context['hook_scope']
                and not source_context['custom_rules']):
            from .scan_reuse import capture_reuse_identity
            proof_started = time.perf_counter()
            try:
                reuse_identity = capture_reuse_identity(self.registry, workspace.path,
                    files=context.files, context_files=context.context_files, selected=selected)
            except (ValueError, OSError, KeyError, TypeError, AttributeError, RuntimeError):
                pass  # A missing reuse proof never prevents a fresh scan.
            finally:
                observed['timing_ms']['reuse_proof_prepare'] = milliseconds(proof_started)
        stage_start = time.perf_counter()

        def unexpected_run(scanner, exc, started, stage):
            # Record useful fixed diagnostics, never arbitrary exception text,
            # commands, environment values or project/scanner output.
            kind = type(exc).__name__ if type(exc).__module__ == 'builtins' else 'OtherException'
            return ScannerRun(scanner.name, '', RunStatus.FAILED, int(milliseconds(started)),
                error_code='SCANNER_FAILED', error_summary='安全检查遇到内部错误，未能完成。',
                remediation='请查看技术诊断中的失败阶段和异常类型，修复后重新检查。',
                diagnostic_detail=f'{stage}: {kind}', coverage_contract='NONE',
                scanner_diagnostics={'failure': {'stage': stage, 'exception_type': kind}})

        def execute(scanner):
            if scan_mode == ScanMode.QUICK and Capability.DEPENDENCY_VULN in scanner.capabilities:
                from .verification_policy import local_recheck, local_recheck_requested
                if not local_recheck_requested():
                    # Keep the entire dependency chain offline, including a
                    # selected fallback, without replacing the Hook's ledger.
                    with local_recheck():
                        return execute(scanner)
            execution_started = time.perf_counter()
            checkpoint()
            if not isinstance(scanner, BaseScanner):
                emit('SCANNER_STARTED', scanner=scanner.name, capability=tuple(scanner.capabilities))
            try:
                scanner_context=replace(context,rule_plan=rule_plans[scanner.name]) if scanner.name in rule_plans else context
                found, run = scanner.scan(scanner_context, normalizer)
            except ScanCancelled:
                raise
            except Exception as exc:
                found, run = [], unexpected_run(scanner, exc, execution_started, 'PROVIDER_EXECUTION')
            if run.scanner_diagnostics.get('execution_binding', {}).get('data_status') == 'UNVERIFIABLE':
                run.coverage_contract = 'PARTIAL'
                run.coverage_notes = list(dict.fromkeys([*run.coverage_notes,
                    'DATA_IDENTITY_UNVERIFIABLE: actual vulnerability data version was not fixed and verified.']))
            if (scan_mode != ScanMode.RELEASE and not source_context['hook_scope']
                    and changed_lines is not None and getattr(scanner, 'filter_changed_lines', False)):
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
                    found, provider_runs = [], [unexpected_run(scanner, exc, stage_start, 'PROVIDER_ORCHESTRATION')]
                    provider_runs[0].capabilities = tuple(scanner.capabilities)
                    provider_runs[0].provider = getattr(scanner, 'engine_id', '') or scanner.scanner_id
                    provider_runs[0].provider_role = getattr(scanner, 'provider_role', 'PRIMARY')
                findings.extend(found)
                runs.extend(provider_runs)
        except (KeyboardInterrupt, ScanCancelled):
            current_reporter().cancel()
            raise
        finally:
            pool.shutdown(wait=True, cancel_futures=True)
        observed['timing_ms']['scanner_orchestration'] = milliseconds(stage_start)
        stage_start = time.perf_counter()
        wanted = requested_capabilities(profile, scan_mode, context.capability_files())
        if Capability.DEPENDENCY_VULN in wanted and not any(
                Capability.DEPENDENCY_VULN in run.capabilities and run.status != RunStatus.NOT_APPLICABLE for run in runs):
            runs.append(ScannerRun('dependency-inputs', '', RunStatus.UNAVAILABLE, 0,
                capabilities=(Capability.DEPENDENCY_VULN,), coverage_contract='NONE',
                error_code='DEPENDENCY_SCOPE_UNAVAILABLE',
                error_summary='依赖清单发生了变化，但当前范围没有可供检查的依赖清单或锁文件。',
                remediation='请提供有效的依赖清单或锁文件后重新检查；删除文件不能证明已安装依赖或原风险已消除。',
                scanner_diagnostics={'failure': {'stage': 'DEPENDENCY_SCOPE_SELECTION', 'reason': 'NO_SUPPORTED_CURRENT_INPUT'}}))
        if hook_observer is not None:
            # Preserve rule/coordinate multiplicity before historical occurrence
            # fingerprints merge colliding rules on the same line. Raw remains
            # unchanged; the hook observer projects safe family metadata only.
            hook_observer(findings, runs, rule_plans)
        findings = deduplicate(findings)
        rule_coverage = combined_rule_coverage(runs)
        planned_runs = [run for run in runs if run.status not in {RunStatus.SKIPPED, RunStatus.NOT_APPLICABLE, RunStatus.NOT_COVERED}]
        successful = sum(run.status == RunStatus.SUCCESS for run in planned_runs)
        complete = bool(planned_runs) and successful == len(planned_runs)
        coverage = "FULL" if complete else "PARTIAL" if successful else "MINIMAL"
        release_status = RiskEngine().assess(findings, complete)
        capability_results = {}
        for capability in (Capability.CODE_SAST, Capability.SECRET_SCAN, Capability.DEPENDENCY_VULN, Capability.IAC_MISCONFIG):
            supporting = [run for run in planned_runs if capability in run.capabilities]
            aggregate = dependency_status(supporting) if capability == Capability.DEPENDENCY_VULN else aggregate_provider_statuses(supporting)
            capability_results[capability] = "NOT_APPLICABLE" if not has_targets or capability not in wanted else aggregate
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
        if no_changes or not has_targets:
            status = execution_state = "NO_CHANGES" if no_changes else "NOT_APPLICABLE"
            coverage = "NONE"
            release_status = "NOT_ASSESSED"
            summary = "没有需要检查的代码变更。\n本次没有执行代码安全扫描。" if no_changes else "本次没有适用的安全检查，未执行扫描。"
        elif not complete:
            summary += "；本次只完成部分安全检查，仍有范围未确认。"
        if Capability.DEPENDENCY_VULN in wanted:
            state = capability_results[Capability.DEPENDENCY_VULN]
            if state in {'UNAVAILABLE', 'FAILED'}:
                summary += "\n依赖检查未完成，暂时无法确认本次依赖变更是否存在漏洞。"
            elif state == 'PARTIAL':
                summary += "\n已检查可识别的依赖版本；完整依赖关系或漏洞数据的新鲜程度尚未确认。"
        scope_notice = getattr(self.registry, 'code_scope_notice', '')
        if scope_notice:
            summary += '\n' + scope_notice
            if complete:
                coverage = 'SCOPED'
            rule_coverage = dict(rule_coverage, coverage_scope='CANONICAL_DYNAMIC_CODE_ONLY',
                                 deferred_providers=['semgrep'], scope_notice=scope_notice)
        result = ScanResult(str(uuid.uuid4()), scan_mode, profile, status, findings, runs, summary, release_status, round((time.monotonic()-start)*1000), coverage,
                            execution_state=execution_state, capability_results=capability_results, capability_details=capability_details, rule_coverage=rule_coverage)
        observed['timing_ms']['result_normalization_policy'] = milliseconds(stage_start)
        observed['providers'] = {run.scanner:run.scanner_diagnostics for run in runs if run.scanner_diagnostics}
        observed['scope'] = {'requested_files':len(files),'profile_files':len(profile.files),
                            'context_files':len(context.context_files),'repository_discovery':scan_mode==ScanMode.RELEASE}
        observed['scope']['changed_dependency_inputs'] = len(changed_dependencies)
        # Persistence time is known only after the transaction; no second write
        # and no mutation of signed scan identities just to record a measurement.
        result.scanner_diagnostics = observed
        source_context.update(input_files=list(context.files), context_files=list(context.context_files),
                              dependency_changes=list(context.dependency_changes or ()))
        source_context['execution_bindings'] = {run.scanner: run.scanner_diagnostics['execution_binding']
            for run in runs if 'execution_binding' in run.scanner_diagnostics}
        from .scan_freshness import complete as complete_context
        view.assert_intact()
        if attempt is not None:
            source_context['execution_attempt'] = attempt.receipt
            attempt.checkpoint(force=True)
        result.scan_context = complete_context(source_context, root, self.store, input_view=view)
        from .finding_scope_snapshot import capture_scopes
        result.source_scopes = capture_scopes(root, [asdict(finding) for finding in findings])
        if result.scan_context['fixed_input']['applicability'] != 'CURRENT':
            result.status, result.coverage, result.release_status = 'PARTIAL', 'UNKNOWN', 'REVIEW'
            result.summary += '\n扫描对应已捕获的文件版本；原来源已变化或无法核验，最新变化仍需检查。'
        if staged:
            observed['source_kind'] = 'GIT_INDEX_PROJECTION'
        from .scanner_cache import lifetime
        observed.update(lifetime())
        if reuse_identity is not None:
            from .scan_reuse import finalize_reuse_proof
            proof_started = time.perf_counter()
            finalize_reuse_proof(self, result, reuse_identity)
            observed['timing_ms']['reuse_proof_seal'] = milliseconds(proof_started)
        stage_start = time.perf_counter()
        self.store.save(result)
        if attempt is not None:
            attempt.after_scan(view, result)
        observed['timing_ms']['state_persistence'] = milliseconds(stage_start)
        observed['timing_ms']['total'] = milliseconds(observed_start)
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
