"""Version-bound development findings and repairs, independent of scanner truth.

Both sources use Finding. Raw observations are retained; an evidence-backed host
assessment controls the effective decision, never the scanner's original output.
No method in this module runs a scanner or captures a project baseline.
"""
from dataclasses import asdict
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .development_check import root_identity
from .local_evidence import WorkspaceReader
from .models import Finding
from .redactor import SecretRedactor
from .scan_request import relative_path
from .tasks.durable import SignedRecords


class Observation(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    issue_key: str = Field(min_length=1, max_length=160)
    file_path: str = Field(min_length=1, max_length=500)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    category: str = Field(min_length=1, max_length=80)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    impact: str = Field(min_length=1, max_length=2000)
    fix_advice: str = Field(min_length=1, max_length=2000)
    severity: Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNRATED']
    decision: Literal['CONFIRMED', 'DISMISSED', 'INCONCLUSIVE']
    rationale: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)
    same_issue_as: str | None = Field(default=None, max_length=160)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class DevelopmentRiskError(ValueError):
    def __init__(self, reason):
        self.reason_code = reason
        super().__init__(reason)


def require(value, reason):
    if not value:
        raise DevelopmentRiskError(reason)


def safe(value):
    return SecretRedactor().redact(value)


class DevelopmentRisks:
    def __init__(self, development, root, check_ref):
        self.development, self.ref = development, check_ref
        self.checks = development.store(root)
        self.root = self.checks.root
        self.check = self.checks.load(check_ref, development.owner)
        self.store = SignedRecords(development.hooks, self.root, 'development-risks.db')

    def fresh(self):
        return dict(contract='development-risks-v1', check_ref=self.ref,
                    owner=self.development.owner, root_identity=root_identity(self.root),
                    risks={}, aliases={}, evidence={}, reviews=[])

    def load(self, db=None):
        row = self.store._get(db, self.ref) if db is not None else self.store.read(self.ref)
        if row is None:
            return self.fresh()
        require(row['owner'] == self.development.owner and
                row['root_identity'] == root_identity(self.root), 'DEVELOPMENT_RISK_OWNER_MISMATCH')
        return row

    def current_check(self):
        return self.checks.load(self.ref, self.development.owner)

    def read(self, file_path, start_line=1, end_line=80, *, related=False):
        name = relative_path(file_path)
        check = self.current_check()
        require(name in check['observed_paths'] or related is True, 'DEVELOPMENT_RISK_PATH_NOT_OBSERVED')
        require(type(start_line) is int and type(end_line) is int and
                1 <= start_line <= end_line < start_line + 80, 'DEVELOPMENT_RISK_RANGE_INVALID')
        raw, text = WorkspaceReader(self.root).read(name)
        lines = text.splitlines()
        require(start_line <= len(lines), 'DEVELOPMENT_RISK_RANGE_INVALID')
        end_line = min(end_line, len(lines))
        excerpt = safe('\n'.join(lines[start_line-1:end_line]))
        require(len(excerpt) <= 24000, 'DEVELOPMENT_RISK_EXCERPT_TOO_LARGE')
        evidence = dict(file_path=name, line_start=start_line, line_end=end_line,
                        sha256=hashlib.sha256(raw).hexdigest(), dirty_seq=check['dirty_seq'])
        ref = 'dre1-' + digest([self.ref, evidence])[:32]
        with self.store.transaction() as db:
            row = self.load(db)
            require(ref in row['evidence'] or len(row['evidence']) < 256, 'DEVELOPMENT_RISK_EVIDENCE_LIMIT')
            row['evidence'][ref] = evidence
            self.store._put(db, self.ref, row)
        return dict(evidence_ref=ref, **evidence,
                    content=excerpt,
                    trust='UNTRUSTED_SOURCE', scanner_run=False)

    def evidence(self, row, refs):
        require(isinstance(refs, list) and 1 <= len(refs) <= 20, 'DEVELOPMENT_RISK_EVIDENCE_REQUIRED')
        result = []
        for ref in refs:
            require(ref in row['evidence'], 'DEVELOPMENT_RISK_EVIDENCE_UNKNOWN')
            item = row['evidence'][ref]
            raw, _ = WorkspaceReader(self.root).read(item['file_path'])
            require(hashlib.sha256(raw).hexdigest() == item['sha256'], 'DEVELOPMENT_RISK_EVIDENCE_STALE')
            result.append(item)
        return result

    def import_scanner(self, row, check):
        if not check.get('scan_id'):
            return
        from .storage import ReadOnlySQLiteStore
        from .hook_state import no_links
        from pathlib import Path
        no_links(Path(check['scan_path']))
        scan = ReadOnlySQLiteStore(Path(check['scan_path'])).get_scan(check['scan_id'])
        require(scan is not None and Path(scan['target_profile']['path']).resolve() == self.root,
                'DEVELOPMENT_RISK_SCAN_UNAVAILABLE')
        require(len(scan['findings']) <= 100, 'DEVELOPMENT_RISK_LIMIT')
        for original in scan['findings']:
            # Scanner identity is occurrence-specific. Never group by CWE/title alone.
            identity = original.get('fingerprint') or original['id']
            key = 'dr1-' + digest([self.ref, 'scanner', original['file_path'], identity])[:32]
            linked = next((r for r in row['risks'].values() if any(
                o.get('scanner_id') == original['id'] and o.get('scan_id') == check['scan_id']
                for o in r['observations'])), None)
            risk = linked or row['risks'].setdefault(key, dict(id=key, finding=original,
                decision='INCONCLUSIVE', status='OPEN', observations=[], assessments=[], repairs=[]))
            obs = dict(source='SCANNER', scan_id=check['scan_id'], scanner_id=original['id'],
                       scanned_seq=check['scanned_seq'], finding=original)
            if obs not in risk['observations']:
                require(len(risk['observations']) < 128, 'DEVELOPMENT_RISK_HISTORY_LIMIT')
                risk['observations'].append(obs)

    def submit(self, observations, expected_seq):
        require(type(expected_seq) is int, 'DEVELOPMENT_RISK_VERSION_INVALID')
        values = [Observation.model_validate(v) for v in observations]
        require(len(values) <= 50, 'DEVELOPMENT_RISK_LIMIT')
        with self.store.transaction() as db:
            check = self.current_check()
            require(check['dirty_seq'] == expected_seq, 'DEVELOPMENT_RISK_VERSION_STALE')
            row = self.load(db)
            self.import_scanner(row, check)
            for value in values:
                name = relative_path(value.file_path)
                require(name in check['observed_paths'] and value.line_end >= value.line_start,
                        'DEVELOPMENT_RISK_LOCATION_INVALID')
                evidence = self.evidence(row, value.evidence_refs)
                require(any(e['file_path'] == name and e['line_start'] <= value.line_start and
                            e['line_end'] >= value.line_end for e in evidence), 'DEVELOPMENT_RISK_LOCATION_UNREAD')
                key = 'dr1-' + digest([self.ref, 'host', name, value.category, value.issue_key])[:32]
                host_key = key
                key = row['aliases'].get(key, key)
                if value.same_issue_as:
                    matches = [r for r in row['risks'].values() if r['id'] == value.same_issue_as or any(
                        o.get('scanner_id') == value.same_issue_as for o in r['observations'])]
                    require(len(matches) == 1, 'DEVELOPMENT_RISK_LINK_UNKNOWN')
                    target = matches[0]
                    original = target['finding']
                    require(original['file_path'] == name and original['line_start'] <= value.line_end
                            and original['line_end'] >= value.line_start, 'DEVELOPMENT_RISK_LINK_LOCATION_MISMATCH')
                    if key in row['risks'] and key != target['id']:
                        # AI-first then scanner: preserve the original AI risk and its repairs.
                        require(not target['assessments'] and not target['repairs'],
                                'DEVELOPMENT_RISK_LINK_HAS_INDEPENDENT_HISTORY')
                        row['risks'][key]['observations'].extend(target['observations'])
                        del row['risks'][target['id']]
                    else:
                        key = target['id']
                    row['aliases'][host_key] = key
                finding = asdict(Finding(id=key, category=value.category, title=safe(value.title),
                    plain_title=safe(value.title), description=safe(value.description), impact=safe(value.impact),
                    severity=value.severity, confidence='HOST_REVIEWED', file_path=name,
                    line_start=value.line_start, line_end=value.line_end, evidence=safe(value.rationale),
                    fix_advice=safe(value.fix_advice), scanner_sources=[], fingerprint=key,
                    technical_details=dict(source='HOST_REVIEW', evidence_refs=value.evidence_refs)))
                risk = row['risks'].setdefault(key, dict(id=key, finding=finding, decision='INCONCLUSIVE',
                    status='OPEN', observations=[], assessments=[], repairs=[]))
                assessment = dict(decision=value.decision, rationale=safe(value.rationale),
                    evidence_refs=value.evidence_refs, source_hashes={e['file_path']:e['sha256'] for e in evidence},
                    dirty_seq=expected_seq, finding=finding)
                if assessment not in risk['assessments']:
                    require(len(risk['assessments']) < 64, 'DEVELOPMENT_RISK_HISTORY_LIMIT')
                    risk['assessments'].append(assessment)
                if risk.get('assessment') != assessment:
                    risk.update(finding=finding, decision=value.decision, assessment=assessment,
                                status='DISMISSED' if value.decision == 'DISMISSED' else 'OPEN')
                obs = dict(source='HOST_REVIEW', finding=finding)
                if obs not in risk['observations']:
                    require(len(risk['observations']) < 128, 'DEVELOPMENT_RISK_HISTORY_LIMIT')
                    risk['observations'].append(obs)
            require(len(row['risks']) <= 100, 'DEVELOPMENT_RISK_LIMIT')
            # Check again before publication: path events during evidence reads invalidate submission.
            require(self.current_check()['dirty_seq'] == expected_seq, 'DEVELOPMENT_RISK_VERSION_STALE')
            # Revalidate every submitted evidence receipt before committing the batch.
            for value in values:
                self.evidence(row, value.evidence_refs)
            review = dict(dirty_seq=expected_seq, scan_id=check.get('scan_id'), risk_ids=list(row['risks']))
            if review not in row['reviews']:
                require(len(row['reviews']) < 256, 'DEVELOPMENT_RISK_HISTORY_LIMIT')
                row['reviews'].append(review)
            # Retain the original ownership/path journal while its risks exist.
            # A failed risk commit may leave a harmless retention pin, never a lost risk.
            with self.checks.transaction() as checks_db:
                current = self.checks._get(checks_db, self.ref)
                require(current['dirty_seq'] == expected_seq, 'DEVELOPMENT_RISK_VERSION_STALE')
                self.checks._put(checks_db, self.ref, dict(current, has_unified_risks=bool(row['risks']),
                                                         has_development_review=True))
            self.store._put(db, self.ref, row)
        return self.get()

    def get(self, offset=0, limit=5):
        require(type(offset) is int and offset >= 0 and type(limit) is int and 1 <= limit <= 20,
                'DEVELOPMENT_RISK_PAGE_INVALID')
        row = self.load()
        risks = list(row['risks'].values())
        items = [dict(id=r['id'], finding=dict(r['finding'], status=r['status']), decision=r['decision'], status=r['status'],
                      disposition=r.get('disposition', 'ACTIVE'),
                      reminder_suppressed=r.get('disposition', 'ACTIVE') != 'ACTIVE' or r['decision'] == 'DISMISSED'
                          or r['status'] == 'CODE_REVIEWED_RESOLVED',
                      sources=sorted({o['source'] for o in r['observations']}),
                      scanner_observations=[dict(scan_id=o['scan_id'], scanner_id=o['scanner_id'])
                                            for o in r['observations'] if o['source'] == 'SCANNER'],
                      assessment=r.get('assessment'), repairs=r['repairs'][-1:],
                      observation_count=len(r['observations']), assessment_count=len(r['assessments']))
                 for r in risks[offset:offset+limit]]
        return dict(contract='development-risks-v1', check_ref=self.ref,
                    risks=items, total=len(risks), next_offset=offset+limit if offset+limit < len(risks) else None,
                    review_versions=row['reviews'],
                    decision_policy='EVIDENCE_BACKED_HOST_REVIEW', scanner_run=False,
                    source_freshness='NOT_RECHECKED_ON_READ', repair_authorized=False)

    def prepare_fix(self, risk_id, proposal, preserve, evidence_refs, user_requested, *,
                    impact_summary, critical_unknowns, repair_paths=None):
        require(user_requested is True, 'DEVELOPMENT_RISK_FIX_AUTHORIZATION_REQUIRED')
        require(isinstance(proposal, str) and 1 <= len(proposal) <= 2000 and
                isinstance(preserve, list) and 1 <= len(preserve) <= 20 and
                all(isinstance(x, str) and 1 <= len(x) <= 500 for x in preserve), 'DEVELOPMENT_RISK_PROPOSAL_INVALID')
        require(isinstance(impact_summary, str) and 1 <= len(impact_summary) <= 2000 and
                isinstance(critical_unknowns, list) and not critical_unknowns, 'DEVELOPMENT_RISK_IMPACT_UNRESOLVED')
        with self.store.transaction() as db:
            row = self.load(db)
            require(risk_id in row['risks'], 'DEVELOPMENT_RISK_UNKNOWN')
            risk = row['risks'][risk_id]
            require(risk.get('disposition', 'ACTIVE') == 'ACTIVE', 'DEVELOPMENT_RISK_DISPOSITION_INACTIVE')
            require(risk['decision'] == 'CONFIRMED' and risk['status'] in {'OPEN', 'STILL_PRESENT'}, 'DEVELOPMENT_RISK_NOT_ACTIVE')
            evidence = self.evidence(row, evidence_refs)
            assessment = risk['assessment']
            hashes = {e['file_path']: e['sha256'] for e in evidence}
            targets = repair_paths
            require(isinstance(targets, list) and 1 <= len(targets) <= 20 and
                    all(isinstance(p, str) and p in hashes for p in targets) and
                    len(set(targets)) == len(targets), 'DEVELOPMENT_RISK_REPAIR_PATH_INVALID')
            require(all(hashes.get(k) == v for k, v in assessment['source_hashes'].items()),
                    'DEVELOPMENT_RISK_REVIEW_CHANGED')
            require(any(e['file_path'] == risk['finding']['file_path'] and
                        e['line_start'] <= risk['finding']['line_start'] and
                        e['line_end'] >= risk['finding']['line_end'] for e in evidence),
                    'DEVELOPMENT_RISK_LOCATION_UNREAD')
            fix = dict(proposal=safe(proposal), preserve=[safe(x) for x in preserve],
                       impact_summary=safe(impact_summary), critical_unknowns=[],
                       before_hashes=hashes, repair_paths=targets, assessment_digest=digest(assessment),
                       evidence_refs=evidence_refs, user_requested=True,
                       authorization_trust='HOST_REPORTED_USER_REQUEST', status='PREPARED')
            fix['repair_ref'] = 'drf1-' + digest([self.ref, risk_id, fix])[:32]
            existing = next((r for r in risk['repairs'] if r['repair_ref'] == fix['repair_ref']), None)
            require(not any(r['status'] == 'PREPARED' and r['repair_ref'] != fix['repair_ref']
                            for r in risk['repairs']), 'DEVELOPMENT_RISK_FIX_ALREADY_ACTIVE')
            if existing is None:
                require(len(risk['repairs']) < 20, 'DEVELOPMENT_RISK_REPAIR_LIMIT')
                risk['repairs'].append(fix)
            else:
                fix = existing
            self.store._put(db, self.ref, row)
        return dict(fix, risk_id=risk_id, ready_for_host_fix=fix['status'] == 'PREPARED',
                    scanner_run=False, source_modified=False, scope=fix.get('repair_paths', [risk['finding']['file_path']]))

    def resolve(self, risk_id, repair_ref, outcome, evidence_refs, rationale):
        require(outcome in {'CODE_REVIEWED_RESOLVED', 'STILL_PRESENT', 'INCONCLUSIVE'},
                'DEVELOPMENT_RISK_OUTCOME_INVALID')
        require(isinstance(rationale, str) and 1 <= len(rationale) <= 2000, 'DEVELOPMENT_RISK_RATIONALE_REQUIRED')
        with self.store.transaction() as db:
            row = self.load(db)
            require(risk_id in row['risks'], 'DEVELOPMENT_RISK_UNKNOWN')
            risk = row['risks'][risk_id]
            fixes = [f for f in risk['repairs'] if f['repair_ref'] == repair_ref]
            require(len(fixes) == 1, 'DEVELOPMENT_RISK_REPAIR_UNKNOWN')
            fix = fixes[0]
            require(digest(risk['assessment']) == fix['assessment_digest'], 'DEVELOPMENT_RISK_ASSESSMENT_CHANGED')
            evidence = self.evidence(row, evidence_refs)
            hashes = {e['file_path']:e['sha256'] for e in evidence}
            require(set(fix['before_hashes']).issubset(hashes), 'DEVELOPMENT_RISK_RECHECK_INCOMPLETE')
            require(any(e['file_path'] == risk['finding']['file_path'] and
                        e['line_start'] <= risk['finding']['line_start'] <= e['line_end'] for e in evidence),
                    'DEVELOPMENT_RISK_LOCATION_UNREAD')
            if outcome == 'CODE_REVIEWED_RESOLVED':
                targets = fix.get('repair_paths', [risk['finding']['file_path']])
                require(any(hashes[path] != fix['before_hashes'][path] for path in targets),
                        'DEVELOPMENT_RISK_NO_REPAIR_CHANGE')
            result = dict(outcome=outcome, evidence_refs=evidence_refs, after_hashes=hashes,
                          rationale=safe(rationale), proof='HOST_CODE_REVIEW_NOT_SCANNER_PROOF')
            require(fix['status'] == 'PREPARED' or fix.get('result') == result, 'DEVELOPMENT_RISK_REPAIR_ALREADY_CLOSED')
            fix.update(status='COMPLETE' if outcome != 'INCONCLUSIVE' else 'PREPARED', result=result)
            risk['status'] = outcome
            self.store._put(db, self.ref, row)
        return dict(risk_id=risk_id, repair_ref=repair_ref, **result, scanner_run=False)

    def disposition(self, risk_id, decision, user_requested):
        require(user_requested is True, 'DEVELOPMENT_RISK_USER_DECISION_REQUIRED')
        require(decision in {'DEFER', 'EXCLUDE', 'RESTORE'}, 'DEVELOPMENT_RISK_DISPOSITION_INVALID')
        with self.store.transaction() as db:
            row = self.load(db)
            require(risk_id in row['risks'], 'DEVELOPMENT_RISK_UNKNOWN')
            risk = row['risks'][risk_id]
            risk['disposition'] = 'ACTIVE' if decision == 'RESTORE' else decision
            self.store._put(db, self.ref, row)
        return dict(risk_id=risk_id, disposition=risk['disposition'], saved=True,
                    risk_closed=False, scanner_run=False)
