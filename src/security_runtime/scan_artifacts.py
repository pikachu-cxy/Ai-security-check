"""Exact-input scanner fact reuse. Never shares task evidence or dispositions."""
from dataclasses import asdict
import copy
import hashlib
import hmac
import json
import uuid

from .tasks.durable import SignedRecords
from .scan_reuse import capture_reuse_identity

CONTRACT = 'fixed-scan-artifact-v1'
SOURCE_PRESENTATION = 'RAW_V3'


class ScanArtifacts(SignedRecords):
    def __init__(self, hooks, root, **kwargs):
        super().__init__(hooks, root, 'scan-artifacts.db', **kwargs)

    def identity(self, runtime, context, view, selected):
        # Unknown providers/configs fail closed. Hash the actual engine/data,
        # not a capability string or a build number alone.
        provider = capture_reuse_identity(runtime.registry, self.root,
            files=context.files, context_files=context.context_files,
            selected=selected, mode=context.mode, source_root=view.execution_root)
        self.provider_digest = hmac.new(self._key(), json.dumps(provider, sort_keys=True,
            default=str).encode(), hashlib.sha256).hexdigest()
        self.provider_digests = {item['name']:hmac.new(self._key(), json.dumps(
            dict(provider=item, build=provider['build'], platform=provider['platform']),
            sort_keys=True, default=str).encode(), hashlib.sha256).hexdigest()
            for item in provider['providers']}
        value = dict(contract=CONTRACT, provider=provider, source=view.source_revision,
            mode=str(context.mode), dependency_changes=context.dependency_changes,
            files=context.files, context_files=context.context_files,
            preference=view.request.code_preference, native=view.request.recheck_native)
        return hmac.new(self._key(), json.dumps(value, sort_keys=True, default=str).encode(),
                        hashlib.sha256).hexdigest()

    def lookup(self, identity):
        row = self.read(identity)
        if (row and row['expires_at'] > self.now()
                and row.get('source_presentation') == SOURCE_PRESENTATION):
            return row
        return None

    def save_result(self, identity, result, view=None):
        if (result.status not in {'SUCCESS', 'COMPLETED', 'PARTIAL'} or result.coverage not in {'FULL', 'SCOPED', 'PARTIAL'}
                or not result.scanner_runs or result.target_profile.skipped_files
                or any(run.status not in {'SUCCESS', 'NOT_APPLICABLE'} for run in result.scanner_runs)
                or any(run.rule_coverage and run.rule_coverage.get('status') not in {'EXECUTED', 'NOT_APPLICABLE'}
                       for run in result.scanner_runs)
                or result.scan_context.get('fixed_input', {}).get('applicability') not in {'CURRENT', 'HISTORICAL'}):
            return
        # A registry with no secret provider can have valid SAST facts and an
        # explicit SECRET_SCAN gap. Reuse preserves that gap, never upgrades it.
        # Failed/unavailable selected providers still prevent reuse above.
        for run in result.scanner_runs:
            if run.status != 'SUCCESS' or run.scanner.startswith('native-'):
                continue
            proof = result.scan_context.get('execution_bindings', {}).get(run.scanner, {})
            if proof.get('verified') is not True or proof.get('data_status') not in {'VERIFIED', 'DISABLED'}:
                return
        hashes = None
        if view is not None:
            from .scan_input import _read_file
            view.assert_intact()
            hashes = {e.path:hashlib.sha256(_read_file(view.execution_root/e.path, 4_000_000)).hexdigest()
                      for e in view.manifest if e.role in {'TARGET', 'CONTEXT'}}
            view.assert_intact()
        with self.transaction() as db:
            for row in self._all(db):
                if row['expires_at'] <= self.now():
                    db.execute('DELETE FROM records WHERE key=?', (row['key'],))
            self._put(db, identity, dict(created_at=self.now(), expires_at=self.now()+86400,
                result=asdict(result), input_hashes=hashes, source_presentation=SOURCE_PRESENTATION,
                configuration={p:(hashes or {}).get(p) for p in ('.semgrepignore', '.gitleaksignore', '.gitleaks.toml')},
                absent=list(view.request.absent_files) if view is not None else []))

    def original_project(self, baseline, auxiliary, findings, current_proof):
        """Reuse an explicit project inventory only against the actual baseline.

        All consumed source/context bytes must match, including unrelated
        context. A subset match, missing hash or new detector is not enough.
        """
        if not baseline.get('inventory_complete'):
            return None
        known = {**baseline['hashes'], **auxiliary}
        from .tasks.security import _environment
        required = {p for p in baseline.get('inventory', ()) if not _environment(p)}
        for row in reversed(self.rows()):
            data = row['result']
            hashes = row.get('input_hashes')
            if (row.get('source_presentation') != SOURCE_PRESENTATION
                    or row['expires_at'] <= self.now() or data['mode'] != 'release' or not hashes
                    or not required.issubset(hashes) or auxiliary != row.get('configuration')
                    or any(known.get(p) != sha for p, sha in hashes.items())
                    or any(p in baseline.get('inventory', ()) for p in row.get('absent', ()) )):
                continue
            proof = data['scanner_diagnostics'].get('comparison_proof') or {}
            targets = set(data['scan_context'].get('input_files', ()))
            if not all(f.file_path in targets and all(
                    current_proof.get('providers', {}).get(s) and
                    current_proof['providers'][s] == proof.get('providers', {}).get(s)
                    for s in f.scanner_sources) for f in findings):
                continue
            # Project-level context must not have been incomplete at capture.
            if data['target_profile']['skipped_files']:
                continue
            return dict(row, result=materialize(data))
        return None


def materialize(data):
    from .models import ScanResult, Finding, ScannerRun, TargetProfile
    data = copy.deepcopy(data)
    data.update(target_profile=TargetProfile(**data['target_profile']),
        findings=[Finding(**f) for f in data['findings']],
        scanner_runs=[ScannerRun(**r) for r in data['scanner_runs']])
    return ScanResult(**data)


def restore(row, runtime, context, profile, view, source_context, attempt):
    """Publish new applicability, preserving the original scanner provenance."""
    from .models import ScanResult, Finding, ScannerRun
    from .scan_freshness import complete
    data = copy.deepcopy(row['result'])
    original = data['scan_id']
    data.update(scan_id=str(uuid.uuid4()), target_profile=profile,
        findings=[Finding(**f) for f in data['findings']],
        scanner_runs=[ScannerRun(**r) for r in data['scanner_runs']], duration_ms=0)
    result = ScanResult(**data)
    view.assert_intact()
    attempt.checkpoint(force=True)
    source_context.update(input_files=list(context.files), context_files=list(context.context_files),
        dependency_changes=list(context.dependency_changes or ()), execution_attempt=attempt.receipt,
        execution_bindings=data['scan_context'].get('execution_bindings', {}))
    result.scan_context = complete(source_context, view.execution_root, runtime.store, input_view=view,
                                  applicability=attempt.applicability(view))
    allowed = {'CURRENT', 'HISTORICAL'} if getattr(attempt, 'original_task_comparison', False) else {'CURRENT'}
    if result.scan_context['fixed_input']['applicability'] not in allowed:
        raise ValueError('Cached source no longer current')
    result.scanner_diagnostics = dict(comparison_proof=data['scanner_diagnostics'].get('comparison_proof'),
        result_reuse=dict(contract=CONTRACT, reused=True,
        artifact_ref=row['key'], original_scan_id=original, scanner_run=False,
        original_duration_ms=row['result']['duration_ms'], verification='EXACT_INPUT_AND_PROVIDER'))
    runtime.store.save(result)
    attempt.after_scan(view, result)
    return result


def coverage_receipts(plans, runs):
    """Positive rule/file coverage only; success alone never proves absence."""
    values = {}
    for name, plan in plans.items():
        run = next((r for r in runs if r.scanner == name), None)
        if (run is None or run.status != 'SUCCESS' or run.coverage_contract != 'FULL'
                or getattr(plan, 'unscoped_error', True)):
            continue
        files = set(plan.scanned_files)-set(plan.errored_files)-set(getattr(plan, 'skipped_files', {}))
        values[name] = dict(files=sorted(files), provider=run.provider, version=run.version,
            checksum=plan.pack.checksum, rules={r.rule_id:r.rule_version for r in plan.rules
                                              if r.rule_id in plan.confirmed_rules})
    return values
