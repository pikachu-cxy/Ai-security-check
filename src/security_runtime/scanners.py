from __future__ import annotations

import json
import importlib.metadata
import logging
import tempfile
import time
import shutil
import subprocess
import os
import hashlib
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Protocol

from .findings import FindingNormalizer
from .equivalence import equivalence_key
from .verification_policy import offline_scanning, local_recheck, local_recheck_requested, scanner_process_observed
from .models import Finding, RunStatus, ScanContext, ScannerRun, TargetProfile
from .capabilities import Capability
from .toolchain import ToolManager, ToolStatus, tool_environment, external_tool_loader
from .plugin_api import SCANNER_ENTRY_POINT, ScannerPluginMetadata
from .rulepacks import RulePackManager
from .rule_coverage import plan_rules
from .rule_program import annotate as annotate_capability, aggregate as aggregate_capabilities
from dataclasses import replace
import yaml
from .sast import SASTRequest, SemgrepEngineProvider
from .target import TargetDetector
from .dependency_inputs import is_dependency_input
from .local_evidence import snapshot_fingerprint, scanner_evidence_metadata
from .engine_environment import engine_environment
from .processes import ProcessResult, run_process, OutputLimitError
from .diagnostics import DiagnosticError, ErrorDiagnostic, classify_network_error, sanitize
from .progress import emit, checkpoint, ScanCancelled
from .scanner_observation import observation, metadata, span, count, add_time, invocation, scope as observe_scope, cache as cache_observed


MAX_OUTPUT = 4_000_000
logger = logging.getLogger(__name__)
_trivy_inventory = ContextVar('trivy_inventory', default=None)
_sast_batch_limit = ContextVar('sast_batch_limit', default=40)
_executing_engine = ContextVar('executing_scanner_engine', default=None)
_executing_environment = ContextVar('executing_scanner_environment', default=None)


def execution_environment(binary):
    """A copy of the environment fixed at this provider's execution boundary."""
    captured = _executing_environment.get()
    return dict(captured) if captured is not None else tool_environment(Path(binary))


@contextmanager
def baseline_sast_batches(enabled):
    """Reduce baseline engine startups without changing normal edit batches."""
    token = _sast_batch_limit.set(128 if enabled else 40)
    try:
        yield
    finally:
        _sast_batch_limit.reset(token)


def sast_batches(files):
    # Reserve space for the executable, options/config and Windows' quoting.
    # Count UTF-16 units; non-ASCII paths are not an unlimited argv budget.
    batch, units = [], 0
    for name in files:
        cost = len(subprocess.list2cmdline([name]).encode('utf-16-le')) // 2 + 1
        if cost > 16_000:
            raise ValueError('SAST target argument budget exceeded')
        if batch and (len(batch) >= _sast_batch_limit.get() or units + cost > 16_000):
            yield tuple(batch)
            batch, units = [], 0
        batch.append(name)
        units += cost
    if batch:
        yield tuple(batch)


@contextmanager
def _artifacts(context, *, prefix='security-runtime-artifacts-'):
    if context.input_view is not None:
        with context.input_view.artifacts() as directory:
            yield directory
        return
    # Standalone adapter embeddings retain their existing temporary-output API.
    with tempfile.TemporaryDirectory(prefix=prefix) as directory:
        yield Path(directory)


@contextmanager
def _snapshot(context: ScanContext):
    """Directory-based engines receive only validated, scoped project files."""
    root = Path(context.root)
    from .hook_state import no_links
    no_links(root)
    root = root.resolve(strict=True)
    files = TargetDetector().detect(root, list(dict.fromkeys((*context.files, *context.context_files)))).files
    if context.input_view is not None:
        with context.input_view.derive(tuple(files)) as scoped:
            yield scoped
        return
    # Standalone adapter embeddings use the same bounded capture path. Runtime
    # always supplies its already captured view above, with no live fallback.
    from .scan_input import capture_scan_input
    from .scan_request import ScanRequest, SourceKind
    request = ScanRequest(root, context.mode, SourceKind.WORKTREE, tuple(files))
    with capture_scan_input(request) as view, view.derive(tuple(files)) as scoped:
        yield scoped


class ScannerAdapter(Protocol):
    name: str
    scanner_id: str
    display_name: str
    capabilities: frozenset[Capability]
    supported_languages: frozenset[str]
    supported_ecosystems: frozenset[str]
    filter_changed_lines: bool
    def required_engines(self) -> tuple[str, ...]: ...
    def supports(self, profile: TargetProfile, context: ScanContext) -> bool: ...
    def scan(self, context: ScanContext, normalizer: FindingNormalizer) -> tuple[list[Finding], ScannerRun]: ...
    def normalize(self, raw: object, normalizer: FindingNormalizer) -> list[Finding]: ...


def _execute(args: list[str], cwd: str, timeout: int) -> ProcessResult:
    with external_tool_loader():
        environment = execution_environment(args[0])
        if local_recheck_requested():
            environment['SECURITY_RUNTIME_OFFLINE'] = '1'
        try:
            with span('process_invocation'):
                count('process_invocations')
                result = run_process(args, cwd=cwd, env=environment, timeout=timeout, max_output=MAX_OUTPUT,
                    capture_start_failure=True)
            add_time('process_creation', getattr(result, 'timing_ms', {}).get('process_creation'))
        except (TimeoutError, OutputLimitError):
            scanner_process_observed()
            raise
        scanner_process_observed()
        return result


def _process_failure(result: ProcessResult):
    raise DiagnosticError(classify_network_error(stderr=result.stderr, return_code=result.return_code))


class BaseScanner:
    name = ""
    scanner_id = ""
    display_name = ""
    capabilities: frozenset[Capability] = frozenset()
    supported_languages: frozenset[str] = frozenset()
    supported_ecosystems: frozenset[str] = frozenset()
    filter_changed_lines = False
    timeout = 30
    engine_id = ""

    def __init__(self, tool_manager: ToolManager | None = None):
        self.tool_manager = tool_manager or ToolManager()

    def required_engines(self) -> tuple[str, ...]:
        return (self.engine_id or self.scanner_id,)

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return True

    def version(self) -> str:
        return self.tool_manager.resolve(self.engine_id or self.scanner_id).version

    def scan(self, context: ScanContext, normalizer: FindingNormalizer) -> tuple[list[Finding], ScannerRun]:
        with observation(context.logical_root or context.root) as observed:
            findings, run = self._scan_observed(context, normalizer)
            run.scanner_diagnostics = {**metadata(observed), **run.scanner_diagnostics}
        return findings, run

    def _scan_observed(self, context, normalizer):
        start = time.monotonic()
        stage = 'ENGINE_PREPARATION'
        def failed(status, diagnostic, version=''):
            return [], ScannerRun(self.name, version, status, round((time.monotonic()-start)*1000),
                                  error=diagnostic.error_summary, coverage_contract='NONE', **diagnostic.to_dict())
        def unexpected(status, exc, version=''):
            kind = type(exc).__name__ if type(exc) in {TypeError, AttributeError, RuntimeError, AssertionError, ImportError, NameError, OverflowError} else 'UNKNOWN_EXCEPTION'
            findings, run = failed(status, ErrorDiagnostic(
                'SCANNER_FAILED', 'Scanner did not complete successfully.',
                'Inspect local engine configuration and retry the check.',
                diagnostic_detail=f'Stage: {stage}; exception type: {kind}.'), version)
            run.scanner_diagnostics = {'failure': {'stage': stage, 'exception_type': kind}}
            return findings, run
        try:
            checkpoint()
            with span('capability_preparation'):
                resolved = self.tool_manager.ensure(self.engine_id or self.scanner_id, **({'offline': True} if local_recheck_requested() else {}))
        except ScanCancelled:
            raise
        except Exception as exc:
            logger.warning("scanner_engine_unavailable scanner=%s reason=%s", self.scanner_id, type(exc).__name__)
            diagnostic = classify_network_error(exc)
            if diagnostic.error_code == 'SCANNER_FAILED':
                return unexpected(RunStatus.UNAVAILABLE, exc)
            return failed(RunStatus.UNAVAILABLE, diagnostic)
        if resolved.status != ToolStatus.READY:
            diagnostic = resolved.diagnostic if getattr(resolved, 'diagnostic', None) else classify_network_error(resolved.detail, offline=resolved.status == ToolStatus.OFFLINE, fallback='ENGINE_UNAVAILABLE')
            return failed(RunStatus.UNAVAILABLE, diagnostic, resolved.version)
        try:
            stage = 'DATA_PREPARATION'
            if self._prepare(resolved.path) != ToolStatus.READY:
                diagnostic = getattr(self.tool_manager, 'data_diagnostics', {}).get('vulnerability_db') or ErrorDiagnostic('VULNERABILITY_DB_UNAVAILABLE', 'Local vulnerability database is unavailable.', 'Run security-check tools install trivy to prepare engine data.')
                return failed(RunStatus.UNAVAILABLE, diagnostic, resolved.version)
            checkpoint()
            stage = 'SCANNER_EXECUTION'
            environment = self._environment(resolved.path, context)
            with engine_environment(self.engine_id or self.scanner_id, environment,
                    workspace=context.logical_root or context.root) as environment:
                execution_identity = None
                if context.input_view is not None:
                    with span('execution_input_identity'):
                        execution_identity = self._input_execution_identity(resolved.path, context, environment)
                    if execution_identity['tool'] is None:
                        return failed(RunStatus.UNAVAILABLE, ErrorDiagnostic(
                            'SCAN_EXECUTION_IDENTITY_UNAVAILABLE', 'Actual scanner executable identity is unavailable.',
                            'Run security-check prepare-scanners --status to identify the affected component. For Semgrep, select its actual virtual-environment entry point with a verifiable Python package and interpreter, then retry.'), resolved.version)
                emit('SCANNER_STARTED', scanner=self.name, scanner_version=resolved.version, capability=tuple(self.capabilities))
                token = _executing_engine.set((self.name, resolved.version, resolved.path))
                environment_token = _executing_environment.set(environment)
                try:
                    findings = self._scan(resolved.path, context, normalizer)
                finally:
                    _executing_engine.reset(token)
                    _executing_environment.reset(environment_token)
                run = ScannerRun(self.name, resolved.version, RunStatus.SUCCESS, round((time.monotonic()-start)*1000), len(findings))
                if execution_identity is not None:
                    with span('execution_input_identity'):
                        after_identity = self._input_execution_identity(resolved.path, context, environment)
                    verified = execution_identity == after_identity
                    run.scanner_diagnostics['execution_binding'] = dict(execution_identity,
                        contract='scanner-execution-binding-v1', verified=verified,
                        data_status='UNVERIFIABLE' if execution_identity['data_required'] and execution_identity['data'] is None else 'VERIFIED')
                    if not verified:
                        run.status, run.coverage_contract = RunStatus.FAILED, 'NONE'
                        run.error_code = 'SCAN_EXECUTION_IDENTITY_CHANGED'
                        run.error_summary = 'Scanner tool or data changed during execution; absence is not proven.'
                return findings, run
        except ScanCancelled:
            raise
        except DiagnosticError as exc:
            return failed(RunStatus.FAILED, exc.diagnostic, resolved.version)
        except TimeoutError:
            return failed(RunStatus.TIMEOUT, ErrorDiagnostic('PROCESS_TIMEOUT', 'Scanner exceeded its execution deadline.', 'Retry with a smaller scan scope or inspect engine performance.'), resolved.version)
        except OutputLimitError:
            return failed(RunStatus.FAILED, ErrorDiagnostic('OUTPUT_LIMIT_EXCEEDED', 'Scanner output exceeded configured limits.', 'Retry with a smaller scan scope.'), resolved.version)
        except ValueError as exc:
            return failed(RunStatus.FAILED, ErrorDiagnostic('SCANNER_OUTPUT_OR_CONFIG_ERROR', sanitize(str(exc), 200), 'Check local rules/configuration and retry.'), resolved.version)
        except (OSError, KeyError) as exc:
            from .processes import ProcessStartError
            findings, run = failed(RunStatus.FAILED, classify_network_error(exc, fallback='LOCAL_IO_ERROR'), resolved.version)
            if isinstance(exc, ProcessStartError):
                run.scanner_diagnostics = {'failure': dict(exc.failure)}
            return findings, run
        except Exception as exc:
            # Keep fixed internal diagnostics without reflecting arbitrary
            # exception text, paths, commands, environment or source material.
            return unexpected(RunStatus.FAILED, exc, resolved.version)

    def _scan(self, binary: str, context: ScanContext, normalizer: FindingNormalizer) -> list[Finding]:
        raise NotImplementedError

    def _environment(self, binary, context):
        environment = tool_environment(Path(binary))
        if local_recheck_requested():
            environment['SECURITY_RUNTIME_OFFLINE'] = '1'
        if context.input_view is not None:
            variables = {'gitleaks': ('GITLEAKS_CONFIG',), 'trivy': ('TRIVY_CONFIG',)}
            for name in variables.get(self.engine_id or self.scanner_id, ()):
                if not environment.get(name):
                    continue
                source = Path(environment[name]).expanduser()
                source = (Path(context.logical_root) / source).resolve() if not source.is_absolute() else source.resolve()
                try:
                    relative = source.relative_to(Path(context.logical_root)).as_posix()
                except ValueError:
                    relative = None
                available = {entry.path for entry in context.input_view.manifest if entry.role in {'TARGET', 'CONTEXT'}}
                if relative not in available:
                    raise DiagnosticError(ErrorDiagnostic('SCAN_INPUT_CONFIGURATION_UNBOUND',
                        'Explicit scanner configuration is outside the captured input.',
                        'Provide configuration inside the bounded input scope before retrying.'))
                environment[name] = str(Path(context.root) / relative)
        return environment

    def _input_execution_identity(self, binary, context, environment):
        tool = self.engine_id or self.scanner_id
        identity_reader = getattr(self.tool_manager, 'execution_identity', None)
        actual = identity_reader(tool, Path(binary), environment=environment) if callable(identity_reader) else None
        actual = actual if (isinstance(actual, str) and len(actual) == 64
            and all(char in '0123456789abcdef' for char in actual)) else None
        data_required = tool in {'trivy', 'osv-scanner'} or Capability.DEPENDENCY_VULN in self.capabilities
        data = None
        data_reader = getattr(self.tool_manager, 'execution_data_identity', None)
        if data_required and callable(data_reader):
            names = (*context.files, *context.context_files)
            ecosystems = {'Maven' if Path(name).name.endswith('.xml') or 'gradle' in Path(name).name
                else 'Go' if Path(name).name == 'go.mod' else 'PyPI' if Path(name).name in
                {'requirements.txt', 'pyproject.toml'} else 'npm' for name in names if is_dependency_input(name)}
            data = data_reader(tool, kind=getattr(self, 'checks', None), ecosystems=ecosystems)
            data = data if (isinstance(data, str) and len(data) == 64
                and all(char in '0123456789abcdef' for char in data)) else None
        return dict(tool=actual, data=data, data_required=data_required)

    def _prepare(self, binary: str) -> ToolStatus:
        return ToolStatus.READY


class PatternSASTScanner(BaseScanner):
    """Local rule-pack scanner whose execution engine is replaceable."""

    capabilities = frozenset({Capability.CODE_SAST})
    supported_languages = frozenset({"Python", "JavaScript", "TypeScript", "Vue", "Java", "Go", "PHP"})
    filter_changed_lines = True
    timeout = 45

    def __init__(self, tool_manager: ToolManager | None = None, *, rule_packs: RulePackManager | None = None, engine_provider=None):
        super().__init__(tool_manager)
        self.rule_packs = rule_packs or RulePackManager()
        self.engine_provider = engine_provider or SemgrepEngineProvider()
        self._plan_cache = {}  # Immutable selection templates; fresh proof sets per invocation.
        self._config_cache = {}
        self._planning_lock = threading.RLock()

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return bool(profile.languages) and (context.mode == "release" or bool(context.files))

    def _bind_preparations(self):
        from .scanner_cache import preparation_bucket
        provider = type(self.engine_provider)
        bucket = preparation_bucket('sast', (provider.__module__, provider.__qualname__, self.engine_provider.engine_id))
        with bucket.lock:
            self._plan_cache = bucket.values.setdefault('plans', {})
            self._config_cache = bucket.values.setdefault('configs', {})
            self._planning_lock = bucket.lock

    def plan_rules(self, profile, context):
        if context.input_view is not None and context.bound_rule_pack is None:
            raise ValueError('Fixed rule input is unavailable')
        from .scanner_cache import workspace_scope
        self._bind_preparations()
        started = time.perf_counter()
        with self._planning_lock, workspace_scope(context.logical_root or context.root):
            pack=context.bound_rule_pack or self.rule_packs.resolve(user_path=Path(context.rules_path) if context.rules_path else None)
            root=Path(context.root).resolve()
            signature=None
            validated=TargetDetector().detect(root,list(context.files)).files
            if set(validated)==set(context.files) and len(validated)<=1000:
                if sum((root/name).stat().st_size for name in validated)<=20_000_000:
                    signature=tuple((name,hashlib.sha256((root/name).read_bytes()).digest()) for name in validated)
            key=(os.path.normcase(str(Path(context.logical_root or context.root).resolve())),
                 pack.descriptor,pack.checksum,context.files,signature)
            hit=signature is not None and key in self._plan_cache
            if not hit:
                template=plan_rules(pack,context.files)
                if len(self._plan_cache) >= 16:
                    self._plan_cache.pop(next(iter(self._plan_cache)))
                if signature is not None:
                    self._plan_cache[key]=template
            # Engine execution sets never enter a template/cache.
            if hit:
                template=self._plan_cache[key]
            return replace(template, pack=pack, confirmed_rules=set(), scanned_files=set(), errored_files=set(), skipped_files={},
                embedded_coverage={},unscoped_error=False,language_files=dict(template.language_files),planning_diagnostics={
                    'rule_pack_cache':'HIT' if getattr(self.rule_packs,'cache_hit',False) else 'MISS',
                    'rule_plan_cache':'HIT' if hit else 'MISS',
                    'rule_planning_ms':round((time.perf_counter()-started)*1000,3)})

    def scan(self, context, normalizer):
        plan=context.rule_plan or self.plan_rules(None,context)
        context=replace(context,rule_plan=plan)
        if not plan.rules:
            findings=[]
            run=ScannerRun(self.name,'',RunStatus.NOT_COVERED,0,rule_coverage=plan.coverage('NOT_COVERED'))
        else:
            findings,run=super().scan(context,normalizer)
            run.rule_coverage=plan.coverage(run.status)
        run.scanner_diagnostics.update(plan.planning_diagnostics)
        run.scanner_diagnostics['scope']={'target_files':len(plan.files),'rules':len(plan.rules),
            'applicable_capabilities':plan.coverage()['applicable_capabilities'],
            'languages':list(plan.detected_languages),'profile':'EXPLICIT_RULE_FILE_SCOPE',
            'repository_discovery':False,'context_files':0,
            'targets_truncated':len(plan.files)>20,
            'relative_targets':[sanitize(name,300) for name in plan.files[:20]], 'scanner_results_reused':False}
        return findings,run

    def _scan(self, binary: str, context: ScanContext, n: FindingNormalizer) -> list[Finding]:
        self._bind_preparations()
        plan=context.rule_plan
        rule_pack=plan.pack
        constant_seconds=0.0
        constant_suppressed=[]
        vue_budget={'files':0,'bytes':0}
        with span('rule_config_preparation'):
            current=(self.rule_packs.bind_input(rule_pack, rule_pack.path) if context.bound_rule_pack
                else self.rule_packs.resolve(user_path=Path(context.rules_path) if context.rules_path else None))
            if (current.path,current.checksum,current.descriptor)!=(rule_pack.path,rule_pack.checksum,rule_pack.descriptor):
                raise ValueError('Rule pack changed after planning')
        with span('rule_config_preparation'):
            selected_ids={r.rule_id for r in plan.rules}
            key=(os.path.normcase(str(Path(context.logical_root or context.root).resolve())),
                 rule_pack.descriptor,rule_pack.checksum,tuple(sorted(selected_ids)))
            with self._planning_lock:
                hit=key in self._config_cache
                cache_observed('selected_config',hit)
                if not hit:
                    definitions=[]
                    for relative in sorted({r.path for r in plan.rules}):
                        definitions.extend(rule for rule in yaml.safe_load((rule_pack.path/relative).read_text(encoding='utf-8'))['rules'] if rule['id'] in selected_ids)
                    config_text=yaml.safe_dump({'rules':definitions},sort_keys=False)
                    if len(config_text.encode())<=1_000_000:
                        if len(self._config_cache) >= 16:
                            self._config_cache.pop(next(iter(self._config_cache)))
                        self._config_cache[key]=config_text
                else:
                    config_text=self._config_cache[key]
        findings=[]
        # Shadow paths cannot preserve custom rule include/exclude semantics.
        # Fail closed for Vue instead of silently widening or losing that scope.
        vue_path_filters=any('paths' in rule and set(rule.get('languages',[])) & {'javascript','typescript'}
            for rule in yaml.safe_load(config_text)['rules']) if any(
            Path(name).suffix.lower()=='.vue' for name in plan.files) else False
        # Serialize selected execution rules, without copying source files.
        with _artifacts(context, prefix='security-runtime-rules-') as temporary:
            config=Path(temporary)/'selected.yml'
            with span('rule_config_preparation'):
                config.write_text(config_text,encoding='utf-8')
            for batch_index, batch in enumerate(sast_batches(plan.files)):
                # Hash bounded safe files before execution, then verify again
                # after it. Source never enters the finding store through this.
                before = {name: snapshot_fingerprint(context.root, name) for name in batch}
                projection = None
                if any(Path(name).suffix.lower() == '.vue' for name in batch):
                    from .vue_scan import VueProjection
                    projection = VueProjection(context.root, batch, Path(temporary)/f'vue-{batch_index}',
                        plan, vue_budget, path_filters=vue_path_filters)
                payloads = []
                for engine_batch in sast_batches(projection.scope if projection else batch):
                    request=SASTRequest(Path(context.root),rule_pack,engine_batch,config)
                    invocation('SAST_SCAN', len(engine_batch))
                    process=_execute(self.engine_provider.command(binary,request),context.root,self.timeout)
                    if process.return_code not in (0,1):
                        _process_failure(process)
                    payloads.append(json.loads(process.stdout))
                with span('parsing_normalization'):
                    data=projection.finish(payloads) if projection else payloads[0]
                    plan.observe(data,batch)
                    if rule_pack.descriptor.bundled and rule_pack.descriptor.rule_pack_id=='ai-security-core':
                        from .python_constants import filter_results
                        # The budget covers proof work, excluding external-engine startup.
                        proof_started=time.monotonic()
                        data,suppressed=filter_results(data,Path(context.root),before,
                            proof_started+max(0,1.0-constant_seconds))
                        constant_seconds+=time.monotonic()-proof_started
                        constant_suppressed.extend(suppressed)
                    normalized = self.normalize(data,n)
                    after = {f.file_path: snapshot_fingerprint(context.root, f.file_path) for f in normalized}
                    for finding in normalized:
                        initial = before.get(finding.file_path, {})
                        final = after[finding.file_path]
                        valid = initial.get('file_sha256') and initial.get('file_sha256') == final['file_sha256']
                        if projection and finding.file_path in projection.details:
                            valid = valid and initial.get('file_sha256') == projection.fingerprints.get(finding.file_path)
                            finding.technical_details['embedded_source'] = {'format':'VUE_SFC',
                                'scope':'SCRIPT_BLOCKS_ONLY','template_status':'NOT_COVERED'}
                        finding.technical_details['evidence_locator'].update(
                            file_sha256=initial['file_sha256'] if valid else None,
                            snapshot_reason=None if valid else initial.get('reason') or final.get('reason') or 'SCAN_FILE_CHANGED')
                    findings.extend(normalized)
                value=data.get('time',{}).get('rules_parse_time')
                if isinstance(value,(int,float)):
                    add_time('engine_reported_rules_parse',value*1000)
                profiling=data.get('time',{}).get('profiling_times',{})
                for key in ('config_time','core_time','ignores_time','total_time'):
                    if isinstance(profiling.get(key),(int,float)):
                        add_time('engine_reported_'+key,profiling[key]*1000)
        plan.planning_diagnostics['constant_proof']={'seconds':round(constant_seconds,4),
            'suppressed_count':len(constant_suppressed),'suppressed_candidates':constant_suppressed[:20],
            'truncated':len(constant_suppressed)>20,'unknown_policy':'RETAIN_ORIGINAL_ALERT'}
        plan.planning_diagnostics['vue_projection'] = dict(vue_budget,
            max_files=64,max_bytes=4*1024*1024,template_status='NOT_COVERED')
        catalog={rule.rule_id:rule for rule in plan.rules}
        for finding in findings:
            rule_id=finding.technical_details.get('rule_id','')
            record=catalog.get(rule_id)
            finding.technical_details.update(engine=self.engine_provider.engine_id,rule_pack=rule_pack.descriptor.rule_pack_id,
                rule_pack_version=rule_pack.descriptor.version,rule_pack_checksum=rule_pack.checksum)
            if record:
                finding.category=record.category
                finding.confidence=record.confidence
                finding.technical_details.update(rule_category=record.category,cwe=list(record.cwe),
                    rule_confidence=record.confidence,rule_maturity=record.maturity,rule_severity=record.severity,
                    rule_version=record.rule_version,framework=record.framework,validation_status='NOT_VALIDATED')
                if record.mode == 'taint':
                    trace=finding.technical_details.get('scanner_evidence_metadata',{}).get('dataflow_trace')
                    finding.technical_details['dataflow_support'] = {
                        'basis':'SEMGREP_TAINT_RULE', 'scope':'ENGINE_LOCAL_ANALYSIS',
                        'trace_status':'PROVIDED' if trace else 'NOT_PROVIDED',
                        'runtime_execution':False, 'cross_file_expansion':False}
                if rule_pack.program:
                    capability = rule_pack.program.capability(rule_id)
                    if capability:
                        annotate_capability(finding, capability, rule_pack.program.version, record)
            finding.equivalence_key = equivalence_key(finding)
        return aggregate_capabilities(findings)

    def normalize(self, data: object, n: FindingNormalizer) -> list[Finding]:
        assert isinstance(data, dict)
        findings=[]
        for item in data.get('results',[]):
            extra=item.get('extra',{})
            metadata=extra.get('metadata',{})
            finding=n.make(scanner=self.name,category=metadata.get('category','command-injection' if 'command' in item.get('check_id','').lower() else 'code'),
                title=extra.get('message','Code security issue'),description=extra.get('message',''),
                severity={'ERROR':'HIGH','WARNING':'MEDIUM'}.get(extra.get('severity'),'LOW'),
                confidence=metadata.get('confidence','MEDIUM'),file_path=item.get('path',''),line=item.get('start',{}).get('line',1),
                evidence=extra.get('lines',''),rule_id=item.get('check_id',''))
            findings.append(finding)
            finding.line_end=max(finding.line_start,item.get('end',{}).get('line',finding.line_start))
            fingerprint = str(extra.get('fingerprint', ''))
            import re
            finding.technical_details['evidence_locator'] = dict(
                start_column=item.get('start', {}).get('col'), end_column=item.get('end', {}).get('col'),
                scanner_fingerprint=fingerprint if re.fullmatch(r'[0-9a-fA-F]{32,128}(?:_\d+)?', fingerprint) else None,
                file_sha256=None, snapshot_reason='SCAN_TIME_HASH_NOT_CAPTURED')
            scanner_metadata = scanner_evidence_metadata(extra, n.root)
            if scanner_metadata:
                finding.technical_details['scanner_evidence_metadata'] = scanner_metadata
        return findings


class SemgrepAdapter(PatternSASTScanner):
    name = scanner_id = "semgrep"
    display_name = "Semgrep"


class GitleaksAdapter(BaseScanner):
    name = scanner_id = "gitleaks"
    display_name = "Gitleaks"
    capabilities = frozenset({Capability.SECRET_SCAN})
    filter_changed_lines = True
    timeout = 30

    def scan(self, context, normalizer):
        from .secret_coverage import capture
        with capture() as receipt:
            findings, run = super().scan(context, normalizer)
        run.provider = 'gitleaks'
        run.scanner_diagnostics['secret_coverage'] = receipt
        return findings, run

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        return context.mode == "release" or bool(context.files)

    def _scan(self, binary: str, context: ScanContext, n: FindingNormalizer) -> list[Finding]:
        # Quick and feature scan changed files only. Gitleaks directory mode is
        # intentionally not used here because it would read the whole project.
        names = (*context.files, *context.context_files) if context.mode == 'release' else context.files
        files = TargetDetector().detect(Path(context.root), list(dict.fromkeys(names))).files
        observe_scope(files, 'FILE' if len(files) == 1 else 'SCOPED_SNAPSHOT')
        if not files:
            return []
        # Preserve the complete validated dirty scope, but pay one process start.
        # Single-file scans also use immutable scoped bytes. Only an ephemeral
        # mirror is scanned; never directory-scan the workspace.
        with _snapshot(replace(context, files=tuple(files), context_files=())) as scoped:
            return self._scan_targets(binary, [str(scoped)], context, n, snapshot_root=scoped,
                                      target_count=len(files))

    def _scan_targets(self, binary, targets, context, n, snapshot_root=None, target_count=1):
        from .secret_coverage import build_receipt, digest, identity, parse_report, publish, text_file, trace_complete, trace_summary
        found = []
        for target in targets:
            scoped = Path(target)
            inputs = [scoped] if scoped.is_file() else sorted(p for p in scoped.rglob('*') if p.is_file())
            names = {p.relative_to(snapshot_root).as_posix(): p for p in inputs} if snapshot_root else {
                p.relative_to(Path(context.root)).as_posix(): p for p in inputs}
            sizes = {name: path.stat().st_size for name, path in names.items()}
            environment = execution_environment(binary)
            default_config = (not environment.get('GITLEAKS_CONFIG') and not environment.get('GITLEAKS_CONFIG_TOML') and
                not (scoped / '.gitleaks.toml').exists() and not (Path(context.root) / '.gitleaks.toml').exists() and
                not (Path(context.root) / '.gitleaksignore').exists())
            # Trace is bounded and stays in memory. Never enable it for custom
            # config: upstream may print config content at debug level.
            trace = (default_config and len(names) <= 20 and sum(sizes.values()) <= 2_000_000 and
                     all(text_file(path) for path in names.values()))
            # Large baselines still carry detector identity for observed hits,
            # without repeatedly hashing all source bytes or claiming file proof.
            before = {name: digest(path) for name, path in names.items()} if trace else {}
            source_matches = trace and all(digest(Path(context.root) / name) == revision for name, revision in before.items())
            engine_before = digest(binary)
            with _artifacts(context) as tmp:
                report = str(Path(tmp) / "findings.json")
                invocation('SECRET_SCAN', target_count)
                process = _execute([binary, "dir", target, "--report-format", "sarif", "--report-path", report,
                    "--redact=0", "--no-banner", "--no-color", "--log-level", 'trace' if trace else 'info',
                    "--max-decode-depth", "5",
                    "--exit-code", "0"], context.root, self.timeout)
                if process.return_code != 0:
                    # Trace may contain source-bearing fields even with redact.
                    # Never reflect raw Secret scanner stderr in diagnostics.
                    raise DiagnosticError(ErrorDiagnostic('SECRET_SCANNER_FAILED',
                        'Secret scanner did not complete successfully.', 'Inspect local engine configuration and retry.'))
                if Path(report).exists() and Path(report).stat().st_size > MAX_OUTPUT:
                    raise OutputLimitError("scanner report exceeds configured limits")
                if not Path(report).is_file():
                    raise ValueError('Secret scanner did not produce its scoped report')
                with span('parsing_normalization'):
                    data = json.loads(Path(report).read_text(encoding="utf-8"))
                    data, rules, reported_version, engine = parse_report(data)
                executing = _executing_engine.get()
                # Upstream SARIF metadata may have a static report version.
                # Bind the actual ToolManager-probed executable/version instead.
                version = executing[1] if executing and executing[0] == self.name and executing[2] == binary else ''
                stable = source_matches and engine_before == digest(binary) and all(
                    digest(path) == before[name] and digest(Path(context.root) / name) == before[name]
                    for name, path in names.items())
                config_stable = (not environment.get('GITLEAKS_CONFIG') and not environment.get('GITLEAKS_CONFIG_TOML') and
                    not (scoped / '.gitleaks.toml').exists() and not (Path(context.root) / '.gitleaks.toml').exists() and
                    not (Path(context.root) / '.gitleaksignore').exists())
                receipt = build_receipt(binary, version, rules, before,
                    default_config=default_config and config_stable and engine == 'gitleaks' and engine_before == digest(binary),
                    complete=trace and stable and trace_complete(process.stderr, sizes))
                receipt['execution_summary'] = trace_summary(process.stderr, sizes)
                receipt['execution_summary']['stable_source'] = stable
                receipt['execution_summary']['reported_engine_matches'] = engine == 'gitleaks'
                receipt['execution_summary']['report_version_matches_execution'] = reported_version == version
                publish(receipt)
                if snapshot_root is not None:
                    for item in data:
                        path = Path(item.get("File", ""))
                        if path.is_absolute():
                            item["File"] = path.resolve().relative_to(snapshot_root.resolve()).as_posix()
                with span('parsing_normalization'):
                    normalized = self.normalize(data, n)
                    for finding in normalized:
                        finding.technical_details.update(identity(receipt, finding.technical_details['rule_id']))
                    found.extend(normalized)
        return found

    def normalize(self, data: object, n: FindingNormalizer) -> list[Finding]:
        assert isinstance(data, list)
        found=[]
        # Capability metadata must never disable the independent Secret engine.
        # No Gitleaks rules/config/allowlists are replaced by the Rule Program.
        try:
            program = RulePackManager().resolve().program
        except (ValueError, OSError):
            program = None
        for item in data:
            finding=n.make(scanner=self.name, category="secret", title=item.get("Description", "Potential secret"), description="A possible secret was found in source code.", severity="HIGH", confidence="HIGH", file_path=item.get("File", ""), line=item.get("StartLine", 1), evidence=item.get("Match", ""), rule_id=item.get("RuleID", ""))
            finding.line_end=max(finding.line_start,item.get('EndLine',finding.line_start))
            if program:
                capability = program.capability(item.get('RuleID',''), 'gitleaks')
                if capability:
                    annotate_capability(finding, capability, program.version)
                    finding.equivalence_key = equivalence_key(finding)
            found.append(finding)
        return found


class TrivyAdapter(BaseScanner):
    name = scanner_id = "trivy-vuln"
    engine_id = "trivy"
    display_name = "Trivy dependency vulnerabilities"
    capabilities = frozenset({Capability.DEPENDENCY_VULN})
    checks = "vuln"
    supported_ecosystems = frozenset({"pip", "npm", "yarn", "pnpm", "maven", "go"})
    timeout = 90

    def _prepare(self, binary: str) -> ToolStatus:
        return self.tool_manager.prepare_trivy_database(binary, **({'offline': True} if local_recheck_requested() else {}))

    def scan(self, context, normalizer):
        if self.checks != 'vuln':
            return super().scan(context, normalizer)
        state = {'inventory': {}, 'notes': [], 'coverage': 'PARTIAL'}
        token = _trivy_inventory.set(state)
        try:
            # Incremental dependency checks never download engines/databases
            # or resolve packages over the network, including a manual QUICK.
            if context.mode == 'quick' and not local_recheck_requested():
                with local_recheck():
                    found, run = super().scan(context, normalizer)
                was_offline = True
            else:
                was_offline = offline_scanning()
                found, run = super().scan(context, normalizer)
        finally:
            _trivy_inventory.reset(token)
        run.dependency_inventory = state['inventory']
        if run.status == RunStatus.SUCCESS:
            run.coverage_contract = state['coverage']
            run.coverage_notes = state['notes']
        else:
            run.coverage_contract = 'NONE'
        if was_offline and run.status==RunStatus.SUCCESS:
            run.coverage_contract='PARTIAL'
            run.coverage_notes.append('Offline Trivy extraction does not attest a complete resolved dependency graph.')
        if self.checks == 'vuln' and run.status == RunStatus.SUCCESS:
            fresh = self.tool_manager.database_freshness()['status']
            run.dependency_inventory['vulnerability_db_freshness'] = fresh if fresh in {'FRESH', 'STALE', 'UNKNOWN', 'MISSING'} else 'UNKNOWN'
            if fresh != 'FRESH':
                run.coverage_contract = 'PARTIAL'
                data_note = ('VULNERABILITY_DB_STALE: Local vulnerability data is past its recorded update deadline.'
                    if fresh == 'STALE' else
                    'VULNERABILITY_DB_FRESHNESS_UNKNOWN: Local vulnerability database freshness could not be verified.')
                run.coverage_notes = [*(run.coverage_notes or []),
                    data_note + ' Cached results do not attest current vulnerability coverage.']
        return found,run

    def supports(self, profile: TargetProfile, context: ScanContext) -> bool:
        relevant = any(is_dependency_input(f) for f in (*context.files, *context.context_files))
        return context.mode in {"quick", "feature", "release"} and relevant

    def _scan(self, binary: str, context: ScanContext, n: FindingNormalizer) -> list[Finding]:
        if self.checks == 'vuln':
            dependency_scope = tuple(dict.fromkeys(f for f in (*context.files, *context.context_files) if is_dependency_input(f)))
            if not dependency_scope:
                raise DiagnosticError(ErrorDiagnostic('DEPENDENCY_SCOPE_UNSUPPORTED',
                    'No supported dependency inventory is in the planned scope.',
                    'Provide a supported manifest or lockfile.'))
            # Only the declared dependency inputs reach this directory engine.
            # Source, project scanner config, and other files stay outside it.
            context = replace(context, files=dependency_scope, context_files=())
            observe_scope(dependency_scope, 'SCOPED_SNAPSHOT')
        with _snapshot(context) as scoped:
            from .python_manifest import stage_python_manifests, manifest_target
            aliases, python_reports = (stage_python_manifests(scoped, context.files)
                if self.checks == 'vuln' else ({}, {}))
            args=[binary, "fs", "--format", "json", "--scanners", self.checks, "--cache-dir", str(self.tool_manager.trivy_cache_dir()), "--skip-db-update", "--skip-java-db-update", "--skip-check-update"]
            if self.checks == 'vuln':
                args.append('--list-all-pkgs')
            if offline_scanning():
                args.append('--offline-scan')
            if self.checks == 'vuln':
                invocation('DEPENDENCY_SCAN', len(set((*context.files, *context.context_files))))
            process = _execute([*args,str(scoped)], str(scoped), self.timeout)
            if process.return_code != 0:
                _process_failure(process)
            data = json.loads(process.stdout)
            if not isinstance(data, dict) or not isinstance(data.get('Results', []), list):
                raise ValueError('Dependency scanner returned an invalid result structure')
            for result in data.get("Results", []):
                result['Target'] = manifest_target(result.get('Target', ''), scoped, aliases)
                if self.checks == 'vuln' and result['Target'] not in dependency_scope:
                    raise ValueError('Dependency scanner reported an unplanned manifest')
            if self.checks == 'vuln':
                state = _trivy_inventory.get()
                if state is not None:
                    state.update(self._dependency_inventory(data, context, process.duration_ms))
                    state['inventory']['python_declarations'] = python_reports
                    if any(report['unresolved_entries'] for report in python_reports.values()):
                        state['coverage'] = 'PARTIAL'
                        state['notes'].append('Some Python declarations are dynamic, unpinned or unsupported; no installed version was inferred.')
                    if python_reports:
                        state['notes'].append('Python declared exact versions include optional/build declarations and unevaluated environment markers; applicability and installed versions are unconfirmed.')
                    if any(level in process.stderr for level in ('WARN', 'ERROR')):
                        state['coverage'] = 'PARTIAL'
                        state['notes'].append('Dependency extraction/resolution warnings prevent confirmation of complete inventory coverage.')
            return self.normalize(data, n)

    @staticmethod
    def _dependency_inventory(data, context, duration_ms):
        planned = {f for f in (*context.files, *context.context_files) if is_dependency_input(f)}
        lockfiles = {'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'poetry.lock', 'Pipfile.lock', 'gradle.lockfile', 'buildscript-gradle.lockfile'}
        packages = []
        observed = set()
        per_manifest = {}
        notes = []
        for result in data.get('Results', []):
            target = str(result.get('Target', '')).replace('\\', '/')
            if target not in planned:
                continue
            extracted = result.get('Packages')
            if not isinstance(extracted, list) or not extracted:
                continue
            observed.add(target)
            per_manifest[target] = len(extracted)
            for package in extracted:
                if isinstance(package, dict):
                    fields = (result.get('Type', ''), package.get('Name', ''), package.get('Version', ''))
                    packages.append(tuple(value if isinstance(value, str) else '' for value in fields))
                else:
                    packages.append(('', '', ''))
        if observed != planned or not planned:
            notes.append('One or more planned dependency inputs produced no package inventory confirmation; empty findings do not attest dependency safety.')
        if any(not all(package) for package in packages):
            notes.append('One or more extracted packages have an unconfirmed name, version or ecosystem.')
        if any(Path(name).name not in lockfiles for name in planned):
            notes.append('Manifest inventory confirms extracted declared versions only; a complete transitive or installed dependency graph is not attested.')
        coverage = 'PARTIAL' if notes else 'FULL'
        return {'coverage': coverage, 'notes': notes, 'inventory': {
            'package_occurrences': len(packages),
            'unique_packages': len(set(packages)),
            'confirmed_package_occurrences': sum(bool(all(package)) for package in packages),
            'confirmed_manifests': len(observed), 'planned_manifests': len(planned),
            'unconfirmed_manifests': sorted(planned - observed),
            'per_manifest': per_manifest, 'complete_dependency_graph_attested': False,
            'package_coordinates': [dict(manifest=str(result.get('Target', '')).replace('\\', '/'),
                ecosystem=str(result.get('Type', '')), package=p.get('Name', ''), version=p.get('Version', ''))
                for result in data.get('Results', []) if str(result.get('Target', '')).replace('\\', '/') in observed
                for p in result.get('Packages', []) if isinstance(p, dict)][:2000],
            'inventory_truncated': len(packages) > 2000,
            'native_duration_ms': duration_ms,
        }}

    def normalize(self, data: object, n: FindingNormalizer) -> list[Finding]:
        assert isinstance(data, dict)
        found = []
        for result in data.get("Results", []):
            for item in result.get("Vulnerabilities", []) if self.checks == "vuln" else []:
                finding = n.dependency(scanner=self.name, package=item.get('PkgName',''), version=item.get('InstalledVersion',''),
                    ecosystem=result.get('Type',''), manifest=result.get('Target',''), vulnerability_id=item.get('VulnerabilityID',''),
                    aliases=item.get('Aliases',[]), severity=item.get('Severity','UNKNOWN'), title=item.get('Title') or 'Vulnerable dependency',
                    description=item.get('Description') or item.get('Title',''), source='Trivy')
                from .diagnostics import sanitize
                from .findings import FIXED_VERSION
                fixed_text = sanitize(item.get('FixedVersion', ''), 500)
                finding.technical_details.update(fixed_version_text=fixed_text,
                    fixed_versions=sorted({v.strip() for v in fixed_text.split(',')
                        if FIXED_VERSION.fullmatch(v.strip())})[:40])
                found.append(finding)
            for item in result.get("Misconfigurations", []) if self.checks == "misconfig" else []:
                found.append(n.make(scanner=self.name, category="configuration", title=item.get("Title", "Configuration issue"), description=item.get("Description", ""), severity=item.get("Severity", "MEDIUM"), confidence="MEDIUM", file_path=result.get("Target", ""), line=item.get("CauseMetadata", {}).get("StartLine", 1), rule_id=item.get("ID", "")))
        return found


class TrivyMisconfigAdapter(TrivyAdapter):
    name = scanner_id = "trivy-misconfig"
    display_name = "Trivy IaC misconfiguration"
    capabilities = frozenset({Capability.IAC_MISCONFIG})
    supported_ecosystems = frozenset()
    checks = "misconfig"

    def _prepare(self, binary):
        # Built-in checks run without preparing the vulnerability/Java databases.
        return ToolStatus.READY

    def supports(self, profile, context):
        return context.mode in {"feature", "release"} and any(
            Path(f).name == "Dockerfile" or f.endswith((".tf", ".yaml", ".yml")) for f in context.files)

    def _scan(self, binary, context, n):
        files = tuple(f for f in context.files if Path(f).name == "Dockerfile" or f.endswith((".tf", ".yaml", ".yml")))
        return super()._scan(binary, replace(context, files=files, context_files=()), n)


class ScannerRegistry:
    def __init__(self, adapters: list[ScannerAdapter] | None = None, tool_manager: ToolManager | None = None, *, fallback_adapters=None):
        self.tool_manager = tool_manager or ToolManager()
        from .osv import OSVDependencyAdapter
        from .dynamic_function import NativeFunctionScanner
        from .dataflow import BoundedDataflowScanner
        from .go_sql import GoSQLScanner
        self.fallback_adapters = fallback_adapters if fallback_adapters is not None else ([OSVDependencyAdapter(self.tool_manager)] if adapters is None else [])
        self.adapters = adapters if adapters is not None else [SemgrepAdapter(self.tool_manager), NativeFunctionScanner(), BoundedDataflowScanner(), GoSQLScanner(), GitleaksAdapter(self.tool_manager), TrivyAdapter(self.tool_manager), TrivyMisconfigAdapter(self.tool_manager), *self._discover_plugins()]

    def _discover_plugins(self) -> list[ScannerAdapter]:
        plugins = []
        used_ids = {"semgrep", "native-js-function", "native-dataflow", "native-go-sql", "gitleaks", "trivy", "trivy-vuln", "trivy-misconfig"}
        for entry in importlib.metadata.entry_points(group=SCANNER_ENTRY_POINT):
            try:
                loaded = entry.load()
                scanner = loaded() if callable(loaded) else loaded
                metadata = getattr(scanner, "metadata", None)
                if not isinstance(metadata, ScannerPluginMetadata):
                    raise ValueError("scanner plugin metadata is missing")
                if metadata.scanner_id != scanner.scanner_id or scanner.scanner_id in used_ids:
                    raise ValueError("scanner plugin id is duplicate or inconsistent")
                if not all(hasattr(scanner, name) for name in ("display_name", "capabilities", "required_engines", "supports", "scan", "normalize")):
                    raise ValueError("scanner plugin interface is incomplete")
                if tuple(scanner.required_engines()) != metadata.required_engines:
                    raise ValueError("scanner plugin engine metadata does not match")
                plugins.append(scanner)
                used_ids.add(scanner.scanner_id)
            except Exception as exc:
                logger.warning("scanner_plugin_skipped name=%s reason=%s", entry.name, type(exc).__name__)
                continue
        return plugins

    def plan(self, profile: TargetProfile, context: ScanContext) -> list[ScannerAdapter]:
        return [adapter for adapter in self.adapters if adapter.supports(profile, context)]
