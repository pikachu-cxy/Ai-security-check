"""Bounded, local scanner evidence for resolution; never a code editor or build."""
from dataclasses import asdict, replace
from pathlib import Path

from .equivalence import equivalence_key
from .findings import FindingNormalizer
from .models import ScanContext, ScanMode, RunStatus
from .target import TargetDetector
from .verification_policy import local_recheck

MAX_MEMBERS = 100
MAX_FILES = 20
MAX_BYTES = 2_000_000


def evidence(row):
    """Detector coordinates only. In particular no Secret value or digest."""
    return {key: row.get(key) for key in ('file_path', 'line_start', 'line_end', 'scanner_sources')} | {
        'rule_id': row.get('technical_details', {}).get('rule_id', ''),
        'equivalence_key': equivalence_key(row), 'trust': 'SCANNER_COORDINATES_ONLY'}


class VerificationService:
    def __init__(self, registry):
        self.registry = registry

    def verify_many(self, root, findings, scan):
        root = Path(root).resolve()
        cache = {}
        files = {f.get('file_path', '') for f in findings}
        budget = len(findings) <= MAX_MEMBERS and len(files) <= MAX_FILES
        if budget:
            total = 0
            for name in sorted(files):
                try:
                    profile = TargetDetector(max_files=1).detect(root, [name])
                    total += sum((root / p).stat().st_size for p in profile.files)
                except (ValueError, OSError):
                    pass
            budget = total <= MAX_BYTES
        return [self._verify(root, row, scan, cache, budget) for row in findings]

    def _verify(self, root, row, scan, cache, budget):
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
                context = ScanContext(str(root), ScanMode.FEATURE, (path,))
                plan = None
                ledger = {'engine_process_observed': False}
                try:
                    with local_recheck() as ledger:
                        if callable(getattr(adapter, 'plan_rules', None)):
                            plan = adapter.plan_rules(profile, context)
                            context = replace(context, rule_plan=plan)
                        if not adapter.supports(profile, context):
                            cache[key] = ([], None, plan, 'ORIGINAL_SCOPE_UNSUPPORTED', False)
                        else:
                            found, run = adapter.scan(context, FindingNormalizer(root))
                            cache[key] = (found, run, plan, '', ledger['engine_process_observed'])
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
                'provider_role': run.provider_role, 'engine_process_observed': process_observed})
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
                # The historical fingerprint can collide between code rules;
                # known different rule families never match that collision.
                known_different = original_key and current_key and original_key != current_key
                matched = ('fingerprint' if current.get('fingerprint') == row.get('fingerprint') and not known_different
                           else 'equivalence_key' if original_key and original_key == current_key else None)
                if matched:
                    result.update(status='STILL_PRESENT', verification_status='STILL_PRESENT', matched_by=matched,
                                  reason='ORIGINAL_OR_EQUIVALENT_FINDING_OBSERVED')
                    result['current_evidence'].append(evidence(current))
            covered = run.status == RunStatus.SUCCESS and run.coverage_contract == 'FULL' and (process_observed or
                type(adapter) not in {SemgrepAdapter, GitleaksAdapter, TrivyAdapter, TrivyMisconfigAdapter, OSVDependencyAdapter})
            if plan is not None:
                rule = row.get('technical_details', {}).get('rule_id')
                selected = next((r for r in plan.rules if r.rule_id == rule), None)
                details = row.get('technical_details', {})
                compatible = selected and all(not details.get(k) or details[k] == value for k, value in (
                    ('rule_pack', plan.pack.descriptor.rule_pack_id), ('rule_pack_version', plan.pack.descriptor.version),
                    ('rule_version', selected.rule_version)))
                engine_id = getattr(getattr(adapter, 'engine_provider', None), 'engine_id', '')
                if details.get('engine') and details['engine'] != engine_id:
                    compatible = False
                checksum = details.get('rule_pack_checksum') or scan.get('rule_coverage', {}).get('rule_pack_checksum')
                if checksum and checksum != plan.pack.checksum:
                    compatible = False
                covered = covered and bool(compatible) and rule in plan.confirmed_rules and path in plan.scanned_files and path not in plan.errored_files and not plan.unscoped_error
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
                          reason='ALL_ORIGINATING_PROVIDERS_RECHECKED_ORIGINAL_RULE_FILE_SCOPE_WITHOUT_EQUIVALENT')
            return result
        return inconclusive(';'.join(dict.fromkeys(reasons)) or 'ORIGINAL_RULE_FILE_COVERAGE_NOT_PROVEN')
