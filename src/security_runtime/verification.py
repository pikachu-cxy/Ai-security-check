"""Bounded, local scanner evidence for resolution; never a code editor or build."""
from contextlib import nullcontext
from dataclasses import asdict, replace
from pathlib import Path

from .equivalence import equivalence_key
from .findings import FindingNormalizer
from .models import ScanContext, ScanMode, RunStatus
from .target import TargetDetector
from .verification_policy import local_recheck
from .progress import ScanCancelled, checkpoint, progress_context

MAX_MEMBERS = 100
MAX_FILES = 20
MAX_BYTES = 2_000_000


def same_dependency_advisory(original, current):
    """A version change is not remediation if this package/advisory persists."""
    if original.get('category') != 'dependency' or current.get('category') != 'dependency':
        return False
    old, new = original.get('technical_details') or {}, current.get('technical_details') or {}
    if any(not old.get(key) or old.get(key) != new.get(key) for key in ('ecosystem', 'package')):
        return False
    def ids(details):
        aliases = details.get('aliases', [])
        aliases = aliases[:100] if isinstance(aliases, list) else []
        return {value for value in [details.get('canonical_vulnerability_id'),
            details.get('vulnerability_id'), *aliases] if isinstance(value, str) and value}
    return bool(ids(old) & ids(new))


def evidence(row):
    """Detector coordinates only. In particular no Secret value or digest."""
    return {key: row.get(key) for key in ('file_path', 'line_start', 'line_end', 'scanner_sources')} | {
        'rule_id': row.get('technical_details', {}).get('rule_id', ''),
        'equivalence_key': equivalence_key(row), 'trust': 'SCANNER_COORDINATES_ONLY'}


def declared_dependency_proof(row, run, path, process_observed):
    """Exact package/advisory absence, independent of full graph coverage."""
    inventory = run.dependency_inventory
    details = row.get('technical_details') or {}
    if (row.get('category') != 'dependency' or run.status != RunStatus.SUCCESS or not process_observed
            or inventory.get('vulnerability_db_freshness') != 'FRESH'
            or inventory.get('inventory_truncated', True)
            or path not in inventory.get('per_manifest', {})
            or any('warnings' in note.lower() for note in run.coverage_notes)
            or not details.get('ecosystem') or not details.get('package')
            or not (details.get('canonical_vulnerability_id') or details.get('vulnerability_id'))):
        return None
    coordinates = [p for p in inventory.get('package_coordinates', [])
                   if p.get('manifest') == path and p.get('ecosystem') == details['ecosystem']
                   and p.get('package') == details['package']]
    if not coordinates or any(not isinstance(p.get('version'), str) or not p['version'] for p in coordinates):
        return None
    return dict(scope='DECLARED_PACKAGE_ADVISORY', manifest=path, package=details['package'],
                ecosystem=details['ecosystem'], versions=sorted({p['version'] for p in coordinates}),
                advisory=details.get('canonical_vulnerability_id') or details['vulnerability_id'],
                database_freshness='FRESH', complete_dependency_graph_verified=False,
                installed_package_verified=False, package_integrity_verified=False)


class VerificationService:
    def __init__(self, registry):
        self.registry = registry

    def verify_many(self, root, findings, scan, *, input_view=None, progress=None, bound_rule_pack=None):
        """Recheck the originating scope; optionally reuse one active fixed input.

        The optional view never falls back to the live project. It remains owned
        by the calling execution and must outlive this bounded verification.
        """
        with progress_context(progress) if progress is not None else nullcontext():
            checkpoint()
            if input_view is not None:
                if Path(root).resolve() != input_view.request.workspace_root.resolve():
                    raise ValueError('Verification input belongs to another workspace')
                input_view.assert_intact()
            results = self._verify_many(root, findings, scan, input_view=input_view, bound_rule_pack=bound_rule_pack)
            checkpoint()
            if input_view is not None:
                input_view.assert_intact()
            return results

    def _verify_many(self, root, findings, scan, *, input_view=None, bound_rule_pack=None):
        logical_root = Path(root).resolve()
        root = input_view.execution_root if input_view is not None else logical_root
        cache = {}
        files = {f.get('file_path', '') for f in findings}
        budget = len(findings) <= MAX_MEMBERS and len(files) <= MAX_FILES
        if budget:
            total = 0
            for name in sorted(files):
                checkpoint()
                try:
                    profile = TargetDetector(max_files=1).detect(root, [name])
                    total += sum((root / p).stat().st_size for p in profile.files)
                except (ValueError, OSError):
                    pass
            budget = total <= MAX_BYTES
        # Recheck only originating rule families, grouped per file/provider. This
        # invocation-local cache remains single-use, never a prior scan proof.
        rules = {}
        for row in findings:
            for name in row.get('scanner_sources', []):
                rules.setdefault((name,row.get('file_path','')),set()).add(row.get('technical_details',{}).get('rule_id',''))
        result=[]
        for row in findings:
            checkpoint()
            result.append(self._verify(root, row, scan, cache, budget, rules,
                input_view=input_view, logical_root=logical_root, bound_rule_pack=bound_rule_pack))
        return result

    def _verify(self, root, row, scan, cache, budget, rules, *, input_view=None, logical_root=None, bound_rule_pack=None):
        result = {'finding_id': row['id'], 'status': 'INCONCLUSIVE', 'verification_status': 'INCONCLUSIVE',
                  'matched_by': None, 'original_evidence': evidence(row), 'current_evidence': [],
                  'scanner_runs': [], 'scope_files': [],
                  'runtime_observed_execution': {'scanner_recheck_attempted': False, 'scanner_recheck': False,
                      'engine_process_observed': False,
                      'patch_applied': False, 'target_build': False, 'tests_run': False},
                  'host_reported_execution': {'status': 'NOT_REPORTED'},
                  'limits': {'members': MAX_MEMBERS, 'files': MAX_FILES, 'bytes': MAX_BYTES},
                  'proof': 'Scanner resolution is scoped evidence, not proof of runtime safety.'}
        def inconclusive(reason):
            result['reason'] = reason
            return result
        if not budget:
            return inconclusive('VERIFICATION_BUDGET_EXCEEDED')
        path = row.get('file_path', '').replace('\\', '/')
        if path not in scan.get('target_profile', {}).get('files', []):
            return inconclusive('ORIGINAL_AFFECTED_SCOPE_NOT_ATTESTED')
        try:
            if not path:
                return inconclusive('AFFECTED_FILE_MISSING_OR_UNREADABLE')
            profile = TargetDetector(max_files=1).detect(root, [path])
            if profile.files != [path]:
                return inconclusive('AFFECTED_FILE_MISSING_OR_NOT_IN_SCOPE')
        except (ValueError, OSError):
            return inconclusive('AFFECTED_FILE_NOT_SAFELY_PROFILED')
        result['scope_files'] = [path]
        origins = set(row.get('scanner_sources') or [])
        if not origins:
            return inconclusive('ORIGINATING_SCANNER_UNKNOWN')
        adapters = {a.name: a for a in (*self.registry.adapters, *getattr(self.registry, 'fallback_adapters', []))}
        complete = bool(equivalence_key(row))
        reasons = []
        provider_failure = False
        for name in sorted(origins):
            checkpoint()
            adapter = adapters.get(name)
            if adapter is None:
                complete = False
                provider_failure = True
                reasons.append('ORIGINATING_SCANNER_UNAVAILABLE')
                continue
            # Only built-in local providers are allowed by default. Trusted
            # extensions must explicitly attest offline, exact-file semantics.
            from .scanners import SemgrepAdapter, GitleaksAdapter, TrivyAdapter, TrivyMisconfigAdapter
            from .osv import OSVDependencyAdapter
            if type(adapter) not in {SemgrepAdapter, GitleaksAdapter, TrivyAdapter, TrivyMisconfigAdapter, OSVDependencyAdapter} and not (
                    getattr(adapter, 'verification_offline', False) is True and
                    getattr(adapter, 'verification_scope_complete', False) is True):
                complete = False
                provider_failure = True
                reasons.append('PROVIDER_LOCAL_SCOPE_NOT_ATTESTED')
                continue
            if isinstance(adapter, SemgrepAdapter):
                from .sast import SemgrepEngineProvider
                provider = adapter.engine_provider
                if type(provider) is not SemgrepEngineProvider and not (
                        getattr(provider, 'verification_offline', False) is True and
                        getattr(provider, 'verification_scope_complete', False) is True):
                    complete = False
                    provider_failure = True
                    reasons.append('ENGINE_LOCAL_SCOPE_NOT_ATTESTED')
                    continue
            key = (name, path)
            if key not in cache:
                context = ScanContext(str(root), ScanMode.FEATURE, (path,),
                    logical_root=str(logical_root or root), input_view=input_view,
                    rules_path=str(input_view.rules_path) if input_view is not None and input_view.rules_path else None,
                    bound_rule_pack=bound_rule_pack)
                plan = None
                ledger = {'engine_process_observed': False}
                try:
                    with local_recheck() as ledger:
                        if callable(getattr(adapter, 'plan_rules', None)):
                            plan = adapter.plan_rules(profile, context)
                            # Preserve the full catalog/checksum identity and
                            # require the original rule in confirmed engine proof.
                            if type(adapter) is SemgrepAdapter:
                                program = getattr(plan.pack, 'program', None)
                                wanted = {rid for original in rules[(name,path)] for rid in
                                    (program.family_rules(original) if program else (original,))}
                                plan = replace(plan, rules=tuple(r for r in plan.rules if r.rule_id in wanted),
                                    confirmed_rules=set(),scanned_files=set(),errored_files=set(),skipped_files={},unscoped_error=False)
                            context = replace(context, rule_plan=plan)
                        if not adapter.supports(profile, context):
                            cache[key] = ([], None, plan, 'ORIGINAL_SCOPE_UNSUPPORTED', False)
                        else:
                            found, run = adapter.scan(context, FindingNormalizer(root, identity_root=logical_root or root))
                            cache[key] = (found, run, plan, '', ledger['engine_process_observed'])
                except ScanCancelled:
                    raise
                except Exception:
                    cache[key] = ([], None, plan, 'SCANNER_RECHECK_FAILED', ledger['engine_process_observed'])
            found, run, plan, error, process_observed = cache[key]
            result['runtime_observed_execution']['engine_process_observed'] |= process_observed
            if run is None:
                provider_failure = True
                if error == 'SCANNER_RECHECK_FAILED':
                    result['runtime_observed_execution']['scanner_recheck_attempted'] = True
                    result['runtime_observed_execution']['scanner_recheck'] |= process_observed
                complete = False
                reasons.append(error)
                continue
            result['runtime_observed_execution']['scanner_recheck_attempted'] = True
            if run.status in {RunStatus.SUCCESS, RunStatus.FAILED, RunStatus.TIMEOUT}:
                result['runtime_observed_execution']['scanner_recheck'] |= process_observed or type(adapter) not in {
                    SemgrepAdapter, GitleaksAdapter, TrivyAdapter, TrivyMisconfigAdapter, OSVDependencyAdapter}
            result['scanner_runs'].append({'scanner': name, 'status': run.status, 'version': run.version,
                'duration_ms': run.duration_ms, 'error_code': run.error_code, 'coverage_contract': run.coverage_contract,
                'provider': run.provider or getattr(adapter, 'engine_id', '') or adapter.scanner_id,
                'provider_role': run.provider_role, 'engine_process_observed': process_observed,
                'scanner_diagnostics':run.scanner_diagnostics})
            if run.status != RunStatus.SUCCESS:
                complete = False
                provider_failure = True
                reasons.append('ORIGINATING_SCANNER_DID_NOT_SUCCEED')
                continue
            origin_row = dict(row, scanner_sources=[name])
            original_key = equivalence_key(origin_row)
            for item in found:
                current = asdict(item)
                current_key = equivalence_key(current)
                if current.get('file_path') != path:
                    continue
                if (row.get('category') == current.get('category') == 'dependency'
                        and not current_key):
                    complete = False
                    reasons.append('DEPENDENCY_ADVISORY_IDENTITY_MISSING')
                # The historical fingerprint can collide between code rules;
                # known different rule families never match that collision.
                known_different = original_key and current_key and original_key != current_key
                matched = ('fingerprint' if current.get('fingerprint') == row.get('fingerprint') and not known_different
                           else 'equivalence_key' if original_key and original_key == current_key else None)
                if not matched and same_dependency_advisory(origin_row, current):
                    matched = 'dependency_advisory'
                if matched:
                    result.update(status='STILL_PRESENT', verification_status='STILL_PRESENT', matched_by=matched,
                                  reason='ORIGINAL_OR_EQUIVALENT_FINDING_OBSERVED')
                    result['current_evidence'].append(evidence(current))
            covered = run.status == RunStatus.SUCCESS and run.coverage_contract == 'FULL' and (process_observed or
                type(adapter) not in {SemgrepAdapter, GitleaksAdapter, TrivyAdapter, TrivyMisconfigAdapter, OSVDependencyAdapter})
            if type(adapter) is TrivyAdapter and row.get('category') == 'dependency':
                result['current_dependency_state'] = dict(
                    database_freshness=run.dependency_inventory.get('vulnerability_db_freshness', 'UNKNOWN'),
                    coverage_contract=run.coverage_contract, coverage_notes=run.coverage_notes,
                    complete_dependency_graph_verified=False)
                proof = declared_dependency_proof(row, run, path, process_observed)
                if proof:
                    covered = True
                    result['dependency_verification'] = proof
                    result['verification_scope'] = proof['scope']
                else:
                    reasons.append('DEPENDENCY_PACKAGE_INVENTORY_OR_FRESH_DATABASE_NOT_PROVEN')
            if type(adapter) is GitleaksAdapter:
                from .secret_coverage import covers
                covered = covered and covers(run, row.get('technical_details', {}), path, root=root)
            elif plan is not None:
                rule = row.get('technical_details', {}).get('rule_id')
                selected = next((r for r in plan.rules if r.rule_id == rule), None)
                details = row.get('technical_details', {})
                compatible = selected and all(not details.get(k) or details[k] == value for k, value in (
                    ('rule_pack', plan.pack.descriptor.rule_pack_id), ('rule_pack_version', plan.pack.descriptor.version),
                    ('rule_version', selected.rule_version)))
                engine_id = (getattr(getattr(adapter, 'engine_provider', None), 'engine_id', '')
                             or getattr(adapter, 'engine_id', '') or adapter.scanner_id)
                if details.get('engine') and details['engine'] != engine_id:
                    compatible = False
                checksum = details.get('rule_pack_checksum') or scan.get('rule_coverage', {}).get('rule_pack_checksum')
                if checksum and checksum != plan.pack.checksum:
                    compatible = False
                covered = (covered and bool(compatible) and rule in plan.confirmed_rules
                    and path in plan.scanned_files and path not in plan.errored_files
                    and path not in getattr(plan, 'skipped_files', {}) and not plan.unscoped_error)
                if getattr(plan.pack, 'program', None):
                    required = set(plan.pack.program.family_rules(rule))
                    applicable = {r.rule_id for r in plan.pack.catalog if r.rule_id in required and
                        Path(path).suffix.lower() in r.target_extensions}
                    covered = covered and bool(applicable) and applicable.issubset(plan.confirmed_rules)
            else:
                # These JSON adapters currently attest candidates, not which
                # original detector/checks evaluated the file. An exit code
                # alone cannot establish absence after config/rule changes.
                if type(adapter) in {GitleaksAdapter, TrivyMisconfigAdapter}:
                    covered = False
                # Changing a non-catalog detector's version weakens absence
                # evidence. Presence remains useful regardless of version.
                old_runs = [r for r in scan.get('scanner_runs', []) if r.get('scanner') == name]
                if old_runs and any(r.get('version') and r['version'] != run.version for r in old_runs):
                    covered = False
            if not covered:
                complete = False
                reasons.append('ORIGINAL_RULE_FILE_COVERAGE_NOT_PROVEN')
        if result['status'] == 'STILL_PRESENT':
            if provider_failure:
                result['observed_present'] = True
                result.update(status='INCONCLUSIVE', verification_status='INCONCLUSIVE')
                return inconclusive(';'.join(dict.fromkeys(reasons)))
            return result
        if not equivalence_key(row):
            reasons.append('RELIABLE_RULE_IDENTITY_MISSING')
        if complete:
            result.update(status='RESOLVED', verification_status='SCANNER_VERIFIED_RESOLVED',
                          reason=('CURRENT_DECLARED_PACKAGE_ADVISORY_RECHECKED_WITH_FRESH_DATABASE'
                                  if result.get('dependency_verification') else
                                  'ALL_ORIGINATING_PROVIDERS_RECHECKED_ORIGINAL_RULE_FILE_SCOPE_WITHOUT_EQUIVALENT'))
            return result
        return inconclusive(';'.join(dict.fromkeys(reasons)) or 'ORIGINAL_RULE_FILE_COVERAGE_NOT_PROVEN')
