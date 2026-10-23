"""Task-relative risk facts and evidence-bound host causal assessments.

Presence comparison is independent of authorship. A changed file, an increased
alert count or a higher severity never establishes new/wider impact.
"""
from dataclasses import asdict, replace
import time

from .baseline_inputs import BaselineInputs, CONTRACT
from ..equivalence import equivalence_key

KINDS = ('EXISTING', 'INTRODUCED', 'EXPANDED', 'UNKNOWN')


def unknown(reason):
    return dict(contract=CONTRACT, origin='UNKNOWN', presence='UNKNOWN',
        impact='NOT_ASSESSED', authorship='UNPROVEN_SHARED_WORKSPACE',
        reason=reason, assessment='STATIC_COMPARISON_ONLY')


class HistoricalExecution:
    """Use the parent's cancellation/lease without replacing its end input."""
    artifact_cache = True
    original_task_comparison = True

    def __init__(self, parent, root, expected):
        self.parent, self.source_root, self.expected = parent, root, expected
        self.store, self.private_parent = parent.store, parent.private_parent
        self.input_id = self.source_revision = None

    def __getattr__(self, name):
        return getattr(self.parent, name)

    def input_ready(self, view):
        from .security import hash_bytes
        self.parent.checkpoint(force=True)
        view.assert_intact()
        for entry in view.manifest:
            if entry.role in {'TARGET', 'CONTEXT'}:
                if self.expected.get(entry.path) != hash_bytes((view.execution_root/entry.path).read_bytes()):
                    raise ValueError('Historical scan input mismatch')
            elif entry.role == 'ABSENT' and self.expected.get(entry.path) is not None:
                raise ValueError('Historical absence mismatch')
        self.input_id, self.source_revision = view.input_id, view.source_revision

    def after_scan(self, view, result):
        self.parent.checkpoint(force=True)
        view.assert_intact()

    def applicability(self, view):
        from ..scan_input import _verify_source, InputApplicability
        self.input_ready(view)
        _verify_source(view, source_root=self.source_root)
        return InputApplicability(view.input_id, view.request.source_kind, 'HISTORICAL',
                                  scope='ORIGINAL_TASK_BASELINE')

    @property
    def receipt(self):
        return dict(self.parent.receipt, input_id=self.input_id, source_revision=self.source_revision,
                    applicability_scope='ORIGINAL_TASK_BASELINE', publication='HISTORICAL_COMPARISON_ONLY')


class _ComparisonStore:
    """No historical scan alerts in the user's current finding/disposition DB."""
    def __init__(self, store):
        self.store = store

    def evidence_key(self):
        return self.store.evidence_key()

    def save(self, result):
        pass


def _covered(finding, proof):
    details = finding.get('technical_details') or {}
    sources = finding.get('scanner_sources') or []
    if not sources or not details.get('rule_id') or not details.get('rule_version'):
        return False
    for source in sources:
        row = proof.get('coverage', {}).get(source, {})
        if (finding['file_path'] not in row.get('files', ())
                or row.get('rules', {}).get(details['rule_id']) != details['rule_version']
                or row.get('checksum') != details.get('rule_pack_checksum')
                or row.get('provider') != details.get('engine')):
            return False
    return True


def classify(after, before):
    """Return conservative candidates; host must establish causal introduction."""
    results = {}
    current_proof = after.scanner_diagnostics.get('comparison_proof') or {}
    old_proof = before.scanner_diagnostics.get('comparison_proof') or {}
    old = [asdict(f) for f in before.findings]
    new = [asdict(f) for f in after.findings]
    def occurrence_group(scope):
        metadata = (scope or {}).get('metadata') or {}
        return tuple(metadata.get(k) for k in ('file', 'symbol', 'statement_hash'))
    for item in after.findings:
        f = asdict(item)
        equivalent = bool(f['scanner_sources']) and all(current_proof.get('providers', {}).get(s)
            and current_proof['providers'][s] == old_proof.get('providers', {}).get(s) for s in f['scanner_sources'])
        value = unknown('COMPARISON_OR_MAPPING_UNPROVEN')
        scope = (after.source_scopes or {}).get(f['id'])
        family = equivalence_key(f)
        candidates = [b for b in old if family and equivalence_key(b) == family]
        matches = [b for b in candidates if scope and (before.source_scopes or {}).get(b['id'],
                   {}).get('issue_key') == scope['issue_key']]
        # Inserting a duplicate statement can shift all ordinals. Never choose
        # one old occurrence merely because its new ordinal happens to match.
        if scope:
            group = occurrence_group(scope)
            old_count = sum(occurrence_group((before.source_scopes or {}).get(b['id'])) == group for b in candidates)
            new_count = sum(equivalence_key(b) == family and occurrence_group(
                (after.source_scopes or {}).get(b['id'])) == group for b in new)
            if old_count != new_count:
                matches = []
        if equivalent and len(matches) == 1:
            previous = (before.source_scopes or {})[matches[0]['id']]
            value.update(origin='EXISTING', presence='PRESENT_BEFORE',
                reason='MATCHED_ORIGINAL_OCCURRENCE', before_finding_id=matches[0]['id'],
                impact='REQUIRES_REVIEW', issue_key=scope['issue_key'],
                evidence_revision=scope['evidence_revision'],
                local_semantics_unchanged=scope['evidence_revision'] == previous['evidence_revision'])
        elif equivalent and not candidates and _covered(f, old_proof):
            # No family in the fully covered before target: candidate only.
            value.update(presence='ABSENT_BEFORE', reason='CAUSAL_CHANGE_REVIEW_REQUIRED',
                         candidate_origin='INTRODUCED')
        if scope:
            value.update(issue_key=scope['issue_key'], evidence_revision=scope['evidence_revision'])
        if current_proof.get('provider_identity'):
            value['detector_identity'] = current_proof['provider_identity']
        results[f['id']] = value
    return results


def compare(service, root, record, engine, result, execution, scope):
    """At most one grouped before scan, only when current findings need it."""
    started = time.perf_counter()
    result_map = {f.id:unknown('ORIGINAL_SCANNER_INPUT_UNAVAILABLE') for f in result.findings}
    metrics = dict(before_scan_run=False, before_cache_reused=False)
    if not result.findings:
        return dict(findings=result_map, status='NO_CURRENT_FINDINGS', **metrics)
    try:
        if record.get('attribution_contract') != CONTRACT:
            raise ValueError('Legacy task has no original scanner input')
        saved = record.get('before_scan_inputs') or {}
        baseline = record['baseline']
        if (not baseline.get('inventory_complete') or baseline.get('read_limitations')
                or saved.get('auxiliary') != record.get('end_auxiliary_hashes')):
            raise ValueError('Original coverage/configuration incomplete')
        from ..scan_artifacts import ScanArtifacts
        cached = ScanArtifacts(service.hooks, root, now=service.now).original_project(
            record['baseline'], saved.get('auxiliary', {}), result.findings,
            result.scanner_diagnostics.get('comparison_proof') or {})
        if cached is not None:
            result_map = classify(result, cached['result'])
            if record.get('workspace_isolation'):
                for attribution in result_map.values():
                    attribution['authorship'] = 'ISOLATED_DIRECTORY_NOT_HOST_WRITE_SANDBOX'
            return dict(findings=result_map, status='COMPARED', before_scan_run=False,
                before_cache_reused=True, original_project_artifact=cached['key'],
                before_comparison_ms=round((time.perf_counter()-started)*1000))
        if saved.get('status') != 'AVAILABLE':
            raise ValueError('Original input unavailable')
        inputs = BaselineInputs(service.hooks, root, now=service.now)
        row = inputs.read(saved['ref'])
        from .security import digest_value
        if (row is None or row['task_ref'] != record['task_ref'] or
                row['baseline_digest'] != digest_value(record['baseline']['hashes'])):
            raise ValueError('Original task input mismatch')
        before_root = inputs.open(saved['ref'])
        from ..runtime import SecurityRuntime
        from ..scan_input import scoped_request
        from ..dependency_inputs import is_dependency_input
        if not isinstance(engine, SecurityRuntime):
            raise ValueError('Unknown comparison provider')
        targets = sorted({f.file_path for f in result.findings if f.file_path in scope})
        if not targets or len(targets) > 128:
            raise ValueError('Before comparison target budget exceeded')
        request = replace(scoped_request(before_root, targets,
            dependency_changes=[p for p in targets if is_dependency_input(p)]), workspace_root=root)
        historical = HistoricalExecution(execution, before_root, row['hashes'])
        before = SecurityRuntime(engine.registry, _ComparisonStore(engine.store)).scan(root,
            request=request, execution=historical)
        metrics.update(before_scan_run=not before.scanner_diagnostics.get('result_reuse', {}).get('reused', False),
                       before_cache_reused=before.scanner_diagnostics.get('result_reuse', {}).get('reused', False))
        result_map = classify(result, before)
        for finding in result.findings:
            if finding.file_path not in baseline.get('inventory', ()):
                result_map[finding.id].update(presence='ABSENT_BEFORE',
                    candidate_origin='INTRODUCED', reason='PROVEN_NEW_FILE_REQUIRES_CAUSAL_REVIEW')
        status = 'COMPARED'
    except (OSError, ValueError, KeyError, TypeError, AttributeError, __import__('sqlite3').DatabaseError):
        status = 'COMPARISON_UNAVAILABLE'
    metrics['before_comparison_ms'] = round((time.perf_counter()-started)*1000)
    if record.get('workspace_isolation'):
        for attribution in result_map.values():
            attribution['authorship'] = 'ISOLATED_DIRECTORY_NOT_HOST_WRITE_SANDBOX'
    return dict(findings=result_map, status=status, **metrics)


def apply_assessments(record, accepted, assessments):
    from pydantic import TypeAdapter, ValidationError
    from ..task_review.contract import RiskAttributions, TaskReviewInputError
    from .security import _clean
    try:
        assessments = TypeAdapter(RiskAttributions).validate_python(assessments)
    except ValidationError:
        raise TaskReviewInputError([dict(field='risk_attributions', code='INVALID_VALUE',
            correction='Use bounded attribution records and issued evidence IDs.')]) from None
    if assessments and record.get('attribution_contract') != CONTRACT:
        raise ValueError('Legacy task has no attribution contract; preserve its original baseline')
    rows = {f['id']:f for f in [*(record.get('static') or {}).get('findings', []), *accepted]}
    seen = set()
    for finding in accepted:
        if record.get('attribution_contract') == CONTRACT:
            finding.setdefault('risk_attribution', unknown('HOST_FINDING_ORIGIN_NOT_ASSESSED'))
    for assessment in assessments:
        identifier = assessment['finding_id']
        if identifier not in rows or identifier in seen:
            raise ValueError('Attribution must identify one original current-task finding')
        seen.add(identifier)
        finding = rows[identifier]
        prior = finding.get('risk_attribution', unknown('LEGACY_ORIGIN_UNAVAILABLE'))
        refs = assessment['evidence_refs']
        if any(ref not in record['evidence'] for ref in refs):
            raise ValueError('Attribution requires issued current review evidence')
        evidence = [record['evidence'][ref] for ref in refs]
        if not any(e['path'] == finding['file_path'] and e['location_version'] == 'CURRENT_TASK_END'
                   and e['start_line'] <= finding['line_start'] <= e['end_line'] for e in evidence):
            raise ValueError('Attribution needs current finding source evidence')
        has_before = any(e['location_version'] == 'BEFORE_TASK' and e['path'] == finding['file_path'] for e in evidence)
        changed = {c['path'] for c in record.get('changes', [])}
        has_change = any(e['path'] in changed and e['location_version'] == 'CURRENT_TASK_END' for e in evidence)
        origin, impact = assessment['origin'], assessment['impact']
        host_only = finding.get('source') == 'HOST_TASK_REVIEW' and not finding.get('same_issue_as')
        if host_only and origin != 'UNKNOWN':
            baseline = record['baseline']
            new_file = (baseline.get('inventory_complete') and finding['file_path'] not in baseline.get('inventory', ()))
            if not has_before and not (new_file and origin == 'INTRODUCED'):
                raise ValueError('Host attribution requires original source evidence or proven file absence')
            prior = dict(prior, presence='ABSENT_BEFORE' if origin == 'INTRODUCED' else 'PRESENT_BEFORE',
                         presence_basis='HOST_CODE_REASONING_NOT_SCANNER_PROOF')
        if origin in {'EXISTING', 'EXPANDED'} and (prior['presence'] != 'PRESENT_BEFORE' or not has_before):
            raise ValueError('Existing/expanded risk requires matched original occurrence and before evidence')
        if origin == 'INTRODUCED' and (prior['presence'] != 'ABSENT_BEFORE' or not has_change):
            raise ValueError('Introduction requires comparable absence and changed-code evidence')
        if origin == 'INTRODUCED' and finding['file_path'] in record['baseline'].get('inventory', ()) and not has_before:
            raise ValueError('Introduction in an existing file requires before evidence')
        if origin == 'EXPANDED' and (impact != 'EXPANDED' or not has_change):
            raise ValueError('Expanded impact requires changed reachability/control evidence')
        if impact == 'EXPANDED' and origin != 'EXPANDED' or origin == 'UNKNOWN' and impact != 'UNKNOWN':
            raise ValueError('Inconsistent attribution assessment')
        finding['risk_attribution'] = dict(prior, origin=origin, impact=impact,
            assessment='HOST_REASONING_NOT_SCANNER_PROOF', rationale=_clean(assessment['rationale'], 1200),
            evidence_refs=list(dict.fromkeys(refs)))
    for finding in accepted:
        if finding.get('same_issue_as'):
            finding['risk_attribution'] = dict(rows[finding['same_issue_as']].get(
                'risk_attribution', unknown('ORIGINAL_ORIGIN_UNAVAILABLE')))
