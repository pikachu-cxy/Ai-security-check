"""Explicit, fail-closed reuse of a signed completed project scan.

History summaries stay read-only. This path revalidates actual local inputs and
provider identities, and never creates a scan, review, or repair authorization.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import os
from pathlib import Path
import platform
import time

from .build_identity import build_identity
from .models import ScanContext, ScanMode
from .scan_freshness import CONTRACT as SOURCE_CONTRACT, encode, source_revision
from .target import TargetDetector

CONTRACT = 'verified-project-scan-reuse-v1'


class _ProofUnavailable(ValueError):
    pass


@dataclass(frozen=True)
class ReuseDecision:
    scan: dict | None
    receipt: dict
    reason_code: str

    @property
    def reused(self):
        return self.scan is not None


def _digest(value, key):
    return hmac.new(key, encode(value), hashlib.sha256).hexdigest()


def _result_data(scan):
    # Timing/observations can finish after persistence. Bind all security facts,
    # source proof, findings, provider statuses and original result identity.
    return {name: value for name, value in scan.items()
            if name not in {'scanner_diagnostics', 'duration_ms', 'background_preparation'}}


def _known_adapters():
    from .dataflow import BoundedDataflowScanner
    from .dynamic_function import NativeFunctionScanner
    from .go_sql import GoSQLScanner
    from .osv import OSVDependencyAdapter
    from .scanners import (SemgrepAdapter, GitleaksAdapter, TrivyAdapter,
                           TrivyMisconfigAdapter)
    return {SemgrepAdapter, GitleaksAdapter, TrivyAdapter, TrivyMisconfigAdapter,
            NativeFunctionScanner, BoundedDataflowScanner, GoSQLScanner, OSVDependencyAdapter}


def _adapter_identity(adapter):
    if type(adapter) not in _known_adapters():
        raise _ProofUnavailable('PROVIDER_IDENTITY_UNSUPPORTED')
    result = {'class': type(adapter).__module__ + '.' + type(adapter).__qualname__,
              'name': adapter.name, 'engines': list(adapter.required_engines())}
    for name in ('capabilities', 'supported_languages', 'supported_ecosystems',
                 'filter_changed_lines', 'timeout', 'checks', 'experimental', 'categories'):
        value = getattr(adapter, name, None)
        result[name] = sorted(value) if isinstance(value, (set, frozenset)) else value
    if hasattr(adapter, 'engine_provider'):
        from .sast import SemgrepEngineProvider
        if type(adapter.engine_provider) is not SemgrepEngineProvider:
            raise _ProofUnavailable('PROVIDER_IDENTITY_UNSUPPORTED')
    return result


def capture_reuse_identity(registry, root, *, files, context_files=(), selected=None,
                           mode=ScanMode.RELEASE, source_root=None):
    """Read bounded local proof inputs; never install/update data or run scans.

    Tool resolution may validate an engine version. The execution identity hashes
    actual engine/package bytes and the complete stable child environment. Runtime
    owns scan-local scratch directories; their generation logic is build-bound.
    """
    from .planner import ScannerPlanner
    from .scanner_observation import observation
    from .scanners import PatternSASTScanner
    from .toolchain import ToolStatus
    root = Path(root).resolve(strict=True)
    build = build_identity()
    if build.get('status') not in {'DEV', 'IDENTIFIED'} or not build.get('build_id'):
        raise _ProofUnavailable('BUILD_IDENTITY_UNVERIFIABLE')
    detector = TargetDetector()
    source = Path(source_root) if source_root is not None else root
    profile = detector.detect(source, list(files), select_scan_targets=True)
    context = ScanContext(str(source), mode, tuple(files),
                          context_files=tuple(context_files), logical_root=str(root))
    if selected is None:
        _, selected = ScannerPlanner(registry).plan(profile, context)
        selected = [adapter for adapter in selected if not callable(getattr(adapter, 'plan_rules', None))
                    or adapter.plan_rules(profile, context).rules]
    inventory = [_adapter_identity(adapter) for adapter in registry.adapters]
    fallback = [_adapter_identity(adapter) for adapter in registry.fallback_adapters]
    providers = []
    # Only share duplicate reads within this exact verification operation.
    # Before/after scan capture and later requests always hash actual bytes anew.
    resolutions, engines, data = {}, {}, {}
    with observation(str(root)):
        for adapter in selected:
            value = _adapter_identity(adapter)
            if callable(getattr(adapter, 'input_bindings', None)):
                value['bindings'] = [asdict(binding) for binding in adapter.input_bindings()]
            if not value['engines'] and callable(getattr(adapter, 'plan_rules', None)):
                value['native_rules'] = adapter.plan_rules(profile, context).pack.checksum
            if isinstance(adapter, PatternSASTScanner):
                pack = adapter.rule_packs.resolve()
                # This includes license/metadata validation beyond execution's
                # rule checksum, and rejects changed routing/provenance.
                value['rules'] = {'descriptor': asdict(pack.descriptor), 'checksum': pack.checksum,
                    'content': hashlib.sha256(adapter.rule_packs._content_identity(pack.path)[1]).hexdigest()}
            if value['engines']:
                if len(value['engines']) != 1:
                    raise _ProofUnavailable('PROVIDER_IDENTITY_UNSUPPORTED')
                tool = value['engines'][0]
                manager = adapter.tool_manager
                manager_key = (id(manager), os.path.normcase(str(manager.root.resolve())), tool)
                if manager_key not in resolutions:
                    resolutions[manager_key] = manager.resolve(tool)
                resolved = resolutions[manager_key]
                if resolved.status != ToolStatus.READY:
                    raise _ProofUnavailable('ENGINE_IDENTITY_UNVERIFIABLE')
                environment = adapter._environment(resolved.path, context)
                # These configured paths are rewritten into a private frozen
                # input at execution. Do not equate live and frozen spellings.
                if environment.get('GITLEAKS_CONFIG') or environment.get('TRIVY_CONFIG'):
                    raise _ProofUnavailable('CONFIGURATION_REUSE_UNSUPPORTED')
                engine_key = (manager_key, os.path.normcase(str(Path(resolved.path).resolve())),
                              tuple(sorted(environment.items())))
                if engine_key not in engines:
                    engines[engine_key] = manager.execution_identity(tool, Path(resolved.path), environment=environment)
                value['engine'] = engines[engine_key]
                value['version'] = resolved.version
                if not value['engine']:
                    raise _ProofUnavailable('ENGINE_IDENTITY_UNVERIFIABLE')
                if tool in {'trivy', 'osv-scanner'}:
                    checks = getattr(adapter, 'checks', None)
                    if tool == 'osv-scanner' or checks != 'misconfig' and manager.database_freshness()['status'] != 'FRESH':
                        raise _ProofUnavailable('PROVIDER_DATABASE_NOT_FRESH')
                    ecosystems = set(profile.ecosystems)
                    data_key = (engine_key, checks, tuple(sorted(ecosystems)))
                    if data_key not in data:
                        data[data_key] = manager.execution_data_identity(tool, kind=checks, ecosystems=ecosystems)
                    value['data'] = data[data_key]
                    if not value['data']:
                        raise _ProofUnavailable('PROVIDER_DATA_IDENTITY_UNVERIFIABLE')
            providers.append(value)
    return {'workspace': os.path.normcase(str(root)), 'build': build,
            'source_presentation': 'RAW_V3',
            'platform': [platform.system(), platform.machine()],
            'discovery': {'exclusions': sorted(detector.ignored), 'max_files': detector.max_files,
                'max_directories': detector.max_directories, 'max_depth': detector.max_depth,
                'max_file_size': detector.max_file_size},
            'registry': inventory, 'fallback': fallback, 'providers': providers}


def _complete_scan(scan):
    context = scan.get('scan_context', {})
    fixed = context.get('fixed_input', {})
    runs = scan.get('scanner_runs', [])
    if (scan.get('mode') != 'release' or context.get('mode') != 'release'
            or context.get('source_kind') != 'WORKTREE' or context.get('requested_scope') != 'PROJECT'
            or context.get('hook_scope') or context.get('custom_rules')):
        raise _ProofUnavailable('NOT_DEFAULT_WHOLE_PROJECT_SCAN')
    if (scan.get('status') != 'COMPLETED' or scan.get('execution_state') != 'EXECUTED'
            or scan.get('coverage') not in {'FULL', 'SCOPED'} or not runs
            or any(run.get('status') not in {'SUCCESS', 'NOT_APPLICABLE'} for run in runs)
            or not any(run.get('status') == 'SUCCESS' for run in runs)
            or not scan.get('capability_results')
            or any(value not in {'EXECUTED', 'NOT_APPLICABLE'} for value in scan['capability_results'].values())):
        raise _ProofUnavailable('SCAN_NOT_COMPLETE')
    if (not context.get('source_consistent') or not context.get('source_revision')
            or fixed.get('applicability') != 'CURRENT' or fixed.get('source_kind') != 'WORKTREE'):
        raise _ProofUnavailable('SOURCE_PROOF_UNVERIFIABLE')
    for run in runs:
        if run.get('status') == 'NOT_APPLICABLE':
            continue
        if run.get('scanner') in {'native-dataflow', 'native-js-function', 'native-go-sql'}:
            continue
        binding = context.get('execution_bindings', {}).get(run.get('scanner'), {})
        if (binding.get('contract') != 'scanner-execution-binding-v1' or binding.get('verified') is not True
                or binding.get('data_status') != 'VERIFIED' or not binding.get('tool')):
            raise _ProofUnavailable('PROVIDER_EXECUTION_PROOF_UNVERIFIABLE')


def finalize_reuse_proof(runtime, result, before):
    """Seal facts during the same scan, before its sole persistence write."""
    if before is None:
        return
    scan = result.to_dict()
    try:
        _complete_scan(scan)
        context = scan['scan_context']
        after = capture_reuse_identity(runtime.registry, scan['target_profile']['path'],
            files=context['input_files'], context_files=context.get('context_files', ()))
        if before != after:
            raise _ProofUnavailable('PROVIDER_IDENTITY_CHANGED_DURING_SCAN')
        key = runtime.store.evidence_key()
        proof = {'contract': CONTRACT, 'identity': after,
            'result_digest': _digest(_result_data(scan), key), 'created_at': time.time()}
        proof['signature'] = _digest(proof, key)
        result.scanner_diagnostics['result_reuse'] = proof
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RuntimeError):
        # Failure to prove reuse must never discard a real completed scan.
        return


def _publication_current(scan, root, hooks):
    attempt = scan['scan_context'].get('execution_attempt')
    if attempt is None:
        return  # A low-level Runtime embedding has no publication lane.
    from .scan_attempt import ScanAttemptStore
    lane = ScanAttemptStore(hooks, root).read().get('lane')
    if (not isinstance(lane, dict) or lane.get('state') != 'COMPLETED'
            or lane.get('scan_id') != scan['scan_id']
            or lane.get('input_id') != scan['scan_context']['fixed_input'].get('input_id')
            or any(lane.get(name) != attempt.get(name) for name in
                   ('attempt_id', 'generation', 'cancel_generation', 'input_id', 'source_revision'))):
        raise _ProofUnavailable('EXECUTION_PUBLICATION_NOT_CURRENT')


def try_reuse(runtime, workspace, *, scan_id=None, hooks=None):
    """Revalidate the latest exact-workspace result, without changing history."""
    started = time.perf_counter()
    def decision(reason, scan=None, **extra):
        receipt = {'contract': CONTRACT, 'reused': scan is not None, 'reason_code': reason,
            'scanner_run': False, 'source_modified': False, 'repair_authorized': False,
            'verification_ms': round((time.perf_counter() - started) * 1000, 3), **extra}
        return ReuseDecision(scan, receipt, reason)
    try:
        from .storage import ReadOnlySQLiteStore
        from .workspace import WorkspaceResolver
        from .hook_state import HookStateStore
        root = WorkspaceResolver().resolve(workspace, allow_non_git_explicit=True,
            allow_non_git_source=True).path
        hooks = hooks or HookStateStore(Path(runtime.store.path).parent / 'hooks')
        store = ReadOnlySQLiteStore(runtime.store.path)
        scan = store.get_scan(scan_id) if scan_id is not None else store.latest_scan(root)
        if scan is None:
            return decision('NO_PREVIOUS_SCAN')
        if Path(scan['target_profile']['path']).resolve(strict=True) != root:
            return decision('WORKSPACE_MISMATCH')
        proof = dict(scan.get('scanner_diagnostics', {}).get('result_reuse', {}))
        if proof.get('contract') != CONTRACT:
            return decision('REUSE_PROOF_UNAVAILABLE')
        key = store.evidence_key()
        signature = proof.pop('signature', None)
        if not isinstance(signature, str) or not hmac.compare_digest(signature, _digest(proof, key)):
            return decision('REUSE_PROOF_INVALID')
        if not hmac.compare_digest(proof['result_digest'], _digest(_result_data(scan), key)):
            return decision('RESULT_PROOF_INVALID')
        _complete_scan(scan)
        context = dict(scan['scan_context'])
        signature = context.pop('signature', None)
        if (context.get('contract') != SOURCE_CONTRACT or not isinstance(signature, str)
                or not hmac.compare_digest(signature, _digest(context, key))):
            return decision('SOURCE_PROOF_INVALID')
        _publication_current(scan, root, hooks)
        if source_revision(root, key)[0] != context['source_revision']:
            return decision('SOURCE_CHANGED')
        current = capture_reuse_identity(runtime.registry, root, files=context['input_files'],
            context_files=context.get('context_files', ()))
        if encode(current) != encode(proof['identity']):
            return decision('BUILD_RULES_ENGINE_OR_CONFIGURATION_CHANGED')
        # Revalidate source after provider checks as well; an edited file may
        # not retain eligibility simply because validation started earlier.
        if source_revision(root, key)[0] != context['source_revision']:
            return decision('SOURCE_CHANGED_DURING_VERIFICATION')
        _publication_current(scan, root, hooks)
        age = time.time() - context['finished_at']
        if age < 0:
            return decision('SCAN_TIMESTAMP_UNVERIFIABLE')
        return decision('VERIFIED_CURRENT_RESULT', scan, original_scan_id=scan['scan_id'],
            result_age_seconds=round(age, 3), provider_freshness='CURRENT_IDENTITY_REVALIDATED',
            result_finished_at=context['finished_at'], verified_at=time.time(),
            review_records='RETAINED_ORIGINAL_SCAN', current_check_proof=True,
            task_publication='NOT_DERIVED_FROM_REUSED_SCAN')
    except _ProofUnavailable as exc:
        return decision(str(exc))
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RuntimeError):
        return decision('REUSE_VERIFICATION_UNAVAILABLE')
