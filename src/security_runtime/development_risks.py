"""Version-bound development findings and repairs, independent of scanner truth.

Both sources use Finding. Raw observations are retained; an evidence-backed host
assessment controls the effective decision, never the scanner's original output.
No method in this module runs a scanner or captures a project baseline.
"""
from dataclasses import asdict
import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from .development_check import root_identity
from .local_evidence import WorkspaceReader
from .models import Finding
from .redactor import SecretRedactor
from .scan_request import relative_path
from .tasks.durable import SignedRecords
import sqlite3
from .performance_trace import review_mark, span
from .development_report import ReportContent, business_coverage


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
    duplicate_of: str | None = Field(default=None, min_length=1, max_length=160)
    report_text: str | None = Field(default=None, min_length=1, max_length=3000)
    report_content: ReportContent | None = None
    # Empty lists are rejected by the domain with an actionable recovery step.
    evidence_refs: list[str] = Field(max_length=20)
    same_issue_as: str | None = Field(default=None, max_length=160)
    scan_id: str | None = Field(default=None, max_length=160)


ScanId = Annotated[str, Field(min_length=1, max_length=160)]


class ScannerReview(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    same_issue_as: str = Field(min_length=1, max_length=160)
    scan_id: ScanId | None = None
    decision: Literal['CONFIRMED', 'DISMISSED', 'INCONCLUSIVE']
    rationale: str = Field(min_length=1, max_length=2000)
    duplicate_of: str | None = Field(default=None, min_length=1, max_length=160)
    report_text: str | None = Field(default=None, min_length=1, max_length=3000)
    report_content: ReportContent | None = None
    evidence_refs: list[str] = Field(max_length=20)


class BusinessReview(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    file_path: str = Field(min_length=1, max_length=500)
    rationale: str = Field(min_length=1, max_length=2000)
    evidence_refs: list[str] = Field(max_length=20)
    limitations: list[str] = Field(default_factory=list, max_length=20)
    coverage: Literal['COMPLETE', 'PARTIAL'] | None = None
    uncovered: list[Annotated[str, Field(min_length=1, max_length=1000)]] = Field(default_factory=list, max_length=20)


class ReviewSubmission(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    check_ref: str
    expected_seq: int
    observations: list[ScannerReview | Observation]
    scan_id: ScanId | None = None
    audit_id: str | None = None
    workspace_path: str | None = None
    session_ref: str | None = None
    business_reviews: list[BusinessReview] | None = None
    return_risks: bool = False
    response_view: Literal['batch', 'final_report'] = 'batch'


def review_input_failure(arguments, *, require_workspace=False):
    """Explain invalid fields before routing or saving; never echo their values."""
    from pydantic import ValidationError
    fields = set().union(*(model.model_fields for model in
        (ReviewSubmission, ScannerReview, Observation, BusinessReview)))
    errors = []
    try:
        request = ReviewSubmission.model_validate(arguments)
        if request.scan_id is None and any(o.same_issue_as and o.scan_id is None for o in request.observations):
            errors.append(dict(field='scan_id', code='missing'))
        if require_workspace and not request.workspace_path:
            errors.append(dict(field='workspace_path', code='missing'))
    except ValidationError as exc:
        for error in exc.errors(include_input=False, include_context=False, include_url=False)[:12]:
            path = ''
            for part in error['loc']:
                if isinstance(part, int):
                    path += f'[{part}]'
                elif part not in {'ScannerReview', 'Observation', 'BusinessReview'}:
                    path += ('.' if path else '') + (part if part in fields else '<unknown>')
            errors.append(dict(field=path or '$', code=error['type']))
    if not errors:
        return None
    for error in errors:
        field = error['field']
        error['correction'] = (
            '在批次顶层传入本次取证返回的 scan_id。' if field == 'scan_id' else
            '传入当前检查的 dirty_seq 整数。' if field == 'expected_seq' else
            '传入 prepare 返回的 audit_id 字符串，保留原发现和证据。' if field == 'audit_id' else
            '传入字符串数组；没有限制时使用 []，不要传入单个字符串。' if field.endswith('limitations') else
            '使用实际读取返回的 evidence_ref 数组。' if field.endswith('evidence_refs') else
            '按工具参数类型补齐或修正此字段。')
    return dict(status='INCONCLUSIVE', reason_code='DEVELOPMENT_REVIEW_INPUT_INVALID',
        field_errors=errors, recoverable=True, review_saved=False, scanner_run=False,
        source_modified=False, repair_authorized=False, security_proof=False,
        message='复核参数有误，本批未保存。只修正报错字段，保留原 observations、证据和完整报告；不要清空已发现漏洞。修正后重试一次；同错再现则报告未保存，不重新扫描。')


def review_progress(check, row):
    """Project saved coverage only; never infer completion from a submission."""
    from .user_config import batch_config
    policy = batch_config(check)['agent']
    current = bool(check.get('scan_id') and check['scanned_seq'] == check['dirty_seq'])
    reviews = [r for r in row['reviews'] if current and
               r['dirty_seq'] == check['dirty_seq'] and r.get('scan_id') == check['scan_id']]
    candidates = {r['id'] for r in row['risks'].values() if any(
        o.get('source') == 'SCANNER' and o.get('scan_id') == check.get('scan_id')
        for o in r['observations'])}
    assessed = {key for r in reviews for key in r.get('reviewed_scanner_ids', [])}
    assessed = {key for key in assessed if key in row['risks'] and
                row['risks'][key].get('assessment', {}).get('scan_id') == check.get('scan_id') and
                row['risks'][key].get('assessment', {}).get('dirty_seq') == check['dirty_seq']}
    inconclusive = sorted(key for key in assessed if row['risks'][key]['assessment']['decision'] == 'INCONCLUSIVE')
    job = check.get('parallel_audit') or {}
    early = [r for r in row['reviews'] if current and job.get('status') in {'COMPLETE', 'PARTIAL'}
             and job.get('dirty_seq') == check['dirty_seq'] and r.get('audit_id') == job.get('audit_id')
             and r.get('audit_id') and r['dirty_seq'] == check['dirty_seq']]
    latest_business = {b['file_path']: b for r in [*early, *reviews]
                       if not r.get('audit_id') or (job.get('status') in {'COMPLETE', 'PARTIAL'} and
                           r['audit_id'] == job.get('audit_id') and job.get('dirty_seq') == check['dirty_seq'])
                       for b in r.get('business_reviews', []) if not r.get('stream_batch_id')}
    if check.get('audit_stream'):
        from .audit_stream_service import valid_reviews
        latest_business.update(valid_reviews(check))
    coverage = set(latest_business)
    coverage_gaps = [dict(file_path=name, coverage=business_coverage(b),
                        reasons=b.get('uncovered') or b.get('limitations', []))
                     for name, b in latest_business.items() if business_coverage(b) != 'COMPLETE']
    excluded = (check.get('result') or {}).get('generated_outputs', {}).get('excluded_paths', [])
    pending_paths = sorted(set(check['observed_paths']) - set(excluded) - coverage)
    imported = (check.get('risk_import_status', 'AVAILABLE') == 'AVAILABLE' and
                row.get('imported_scan_id') == check.get('scan_id'))
    scanner_done = current and imported and not (candidates - assessed)
    business_done = current and not pending_paths
    complete = current and any(policy.values()) and (
        not policy['review_scanner_findings'] or scanner_done) and (
        not policy['audit_business_logic'] or business_done)
    return dict(host_review_completed=bool(complete),
        scanner_review=('SKIPPED_BY_CONFIG' if not policy['review_scanner_findings'] else
                        'COMPLETE' if scanner_done else 'PENDING'),
        business_review=('SKIPPED_BY_CONFIG' if not policy['audit_business_logic'] else
                         ('PARTIAL' if coverage_gaps else 'COMPLETE') if business_done else 'PENDING'),
        inconclusive_scanner_ids=inconclusive if policy['review_scanner_findings'] else [],
        business_coverage_gaps=coverage_gaps if policy['audit_business_logic'] else [],
        pending_scanner_ids=sorted(candidates - assessed) if policy['review_scanner_findings'] else [],
        pending_business_paths=pending_paths if policy['audit_business_logic'] else [])


def current_assessment(check, assessment, file_path):
    """One current-version rule for reports, reminders and scanner projection."""
    if not assessment:
        return False
    if assessment.get('stream_batch_id'):
        from .audit_stream_service import assessment_current
        return assessment_current(check, assessment, file_path)
    if (check.get('scan_id') and check['scanned_seq'] == check['dirty_seq']
            and (assessment.get('dirty_seq'), assessment.get('scan_id')) ==
                (check['dirty_seq'], check['scan_id'])):
        return True
    job = check.get('parallel_audit') or {}
    return bool(assessment.get('audit_id') and assessment['audit_id'] == job.get('audit_id')
                and job.get('status') in {'COMPLETE', 'PARTIAL'}
                and assessment.get('dirty_seq') == job.get('dirty_seq') == check['dirty_seq'])


def current_risk(check, risk):
    """Keep history intact; old technical decisions cannot suppress new hits."""
    if current_assessment(check, risk.get('assessment'), risk['finding']['file_path']):
        return risk
    observed = next((o for o in reversed(risk['observations'])
                     if o.get('source') == 'SCANNER' and o.get('scan_id') == check.get('scan_id')), None)
    if observed is None:
        return risk
    return dict(risk, finding=observed['finding'], decision='INCONCLUSIVE', status='OPEN', assessment=None)


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
        from .development_result_store import DevelopmentResultStore
        self.store = DevelopmentResultStore(self.checks)

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
        if self.store.active.get() is not None:
            return self.checks._get(self.store.active.get(), self.ref)
        return self.checks.load(self.ref, self.development.owner)

    def read(self, file_path, start_line=1, end_line=80, *, related=False):
        name = relative_path(file_path)
        check = self.current_check()
        require(name in check['observed_paths'] or related is True, 'DEVELOPMENT_RISK_PATH_NOT_OBSERVED')
        require(type(start_line) is int and type(end_line) is int and
                1 <= start_line <= end_line < start_line + 80, 'DEVELOPMENT_RISK_RANGE_INVALID')
        with span('review.source_read'):
            raw, text = WorkspaceReader(self.root).read(name)
        lines = text.splitlines()
        require(start_line <= len(lines), 'DEVELOPMENT_RISK_RANGE_INVALID')
        end_line = min(end_line, len(lines))
        excerpt = safe('\n'.join(lines[start_line-1:end_line]))
        require(len(excerpt) <= 24000, 'DEVELOPMENT_RISK_EXCERPT_TOO_LARGE')
        evidence = dict(file_path=name, line_start=start_line, line_end=end_line,
                        sha256=hashlib.sha256(raw).hexdigest(), dirty_seq=check['dirty_seq'])
        ref = 'dre1-' + digest([self.ref, evidence])[:32]
        with span('review.evidence_save'), self.store.transaction() as db:
            row = self.load(db)
            require(ref in row['evidence'] or len(row['evidence']) < 256, 'DEVELOPMENT_RISK_EVIDENCE_LIMIT')
            row['evidence'][ref] = evidence
            self.store._put(db, self.ref, row)
        from .performance_trace import review_event
        review_event('evidence_read', check)
        return dict(evidence_ref=ref, **evidence,
                    content=excerpt,
                    trust='UNTRUSTED_SOURCE', scanner_run=False)

    def evidence(self, row, refs, *, include_source=False):
        require(isinstance(refs, list) and 1 <= len(refs) <= 20, 'DEVELOPMENT_RISK_EVIDENCE_REQUIRED')
        result = []
        for ref in refs:
            require(ref in row['evidence'], 'DEVELOPMENT_RISK_EVIDENCE_UNKNOWN')
            item = row['evidence'][ref]
            if item.get('kind') == 'ABSENCE':
                from .audit_stream_service import absent
                require(absent(self.root, item['file_path']), 'DEVELOPMENT_RISK_EVIDENCE_STALE')
                result.append(item)
                continue
            raw, text = WorkspaceReader(self.root).read(item['file_path'])
            require(hashlib.sha256(raw).hexdigest() == item['sha256'], 'DEVELOPMENT_RISK_EVIDENCE_STALE')
            result.append(dict(item, _source=text) if include_source else item)
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
        row['imported_scan_id'] = check['scan_id']
        # Original findings are retained under each finding's SCANNER observation.
        # Store the remaining immutable execution facts in the same result object.
        row.setdefault('scan_facts', {})[check['scan_id']] = {
            key: value for key, value in scan.items() if key != 'findings'}

    def publish_scan(self, db, check):
        """Merge scan facts into the canonical object before READY commits."""
        row = self.load(db)
        self.import_scanner(row, check)
        from .business_audit import revalidate
        revalidate(self, check, row)
        from .risk_management import revalidate_dispositions
        revalidate_dispositions(self.root, row['risks'])
        check = dict(check, security_result=row, result_storage='embedded-development-result-v1',
                     has_unified_risks=bool(row['risks']), risk_import_status='AVAILABLE')
        self.checks._put(db, self.ref, check)
        return check

    def sync_scanner(self):
        """Persist scanner observations independently of any Agent review."""
        with self.store.transaction() as db:
            self.publish_scan(db, self.current_check())

    def submit(self, observations, expected_seq, *, business_reviews=(), return_risks=False, scan_id=None, audit_id=None, final_report=False):
        try:
            return self._submit(observations, expected_seq, business_reviews=business_reviews,
                                return_risks=return_risks, scan_id=scan_id, audit_id=audit_id, final_report=final_report)
        except DevelopmentRiskError as error:
            if not hasattr(error, 'recovery'):
                error.recovery = dict(tool='get_development_check', arguments=dict(
                    check_ref=self.ref, workspace_path=str(self.root)))
            raise

    def _submit(self, observations, expected_seq, *, business_reviews, return_risks, scan_id, audit_id, final_report=False, stream_commit=None):
        require(type(expected_seq) is int, 'DEVELOPMENT_RISK_VERSION_INVALID')
        values = [(ScannerReview if 'issue_key' not in v else Observation).model_validate(v)
                  for v in observations]
        business = [BusinessReview.model_validate(v) for v in business_reviews]
        for value in business:
            require(value.coverage != 'PARTIAL' or bool(value.uncovered), 'BUSINESS_COVERAGE_DETAIL_REQUIRED')
            require(value.coverage != 'COMPLETE' or not value.uncovered, 'BUSINESS_COVERAGE_CONFLICT')
        require(len(values) <= 50, 'DEVELOPMENT_RISK_LIMIT')
        require(len(business) <= 50, 'DEVELOPMENT_RISK_LIMIT')
        review_mark('validated_arguments')
        with self.store.transaction() as db:
            review_mark('transaction_open')
            check = self.current_check()
            require(check['dirty_seq'] == expected_seq, 'DEVELOPMENT_RISK_VERSION_STALE')
            if stream_commit is not None:
                from .audit_stream_service import authenticate, validate_commit
                authenticate(check, stream_commit['token'], stream_commit['agent_ref'])
                validate_commit(check, stream_commit)
            if audit_id is not None:
                import time
                job = check.get('parallel_audit') or {}
                require(job.get('audit_id') == audit_id and job.get('dirty_seq') == expected_seq
                    and job.get('status') in {'RUNNING', 'COMPLETE', 'PARTIAL'}
                    and job.get('lease_until', 0) >= time.time(), 'BUSINESS_AUDIT_VERSION_STALE')
            if scan_id is not None:
                require(scan_id == check.get('scan_id') and check['scanned_seq'] == expected_seq,
                        'DEVELOPMENT_RISK_SCAN_VERSION_STALE')
            from .user_config import batch_config
            policy = batch_config(check)['agent']
            for value in values:
                required = 'review_scanner_findings' if value.same_issue_as else 'audit_business_logic'
                require(policy[required], 'DEVELOPMENT_AGENT_ANALYSIS_DISABLED')
            require(any(policy.values()), 'DEVELOPMENT_AGENT_ANALYSIS_DISABLED')
            require(not business or policy['audit_business_logic'], 'DEVELOPMENT_AGENT_ANALYSIS_DISABLED')
            row = self.load(db)
            self.import_scanner(row, check)
            reviewed_ids = []
            normalized = []
            for index, value in enumerate(values):
                if value.same_issue_as:
                    try:
                        if value.scan_id is None:
                            value = value.model_copy(update={'scan_id': scan_id})
                        require(value.scan_id is not None and value.scan_id == check.get('scan_id') and
                                check['scanned_seq'] == expected_seq, 'DEVELOPMENT_RISK_SCAN_VERSION_STALE')
                        matches = [(r, o) for r in row['risks'].values() for o in r['observations']
                                   if o.get('source') == 'SCANNER' and o.get('scan_id') == value.scan_id
                                   and (r['id'] == value.same_issue_as or o['scanner_id'] == value.same_issue_as)]
                        require(len(matches) == 1, 'DEVELOPMENT_RISK_LINK_UNKNOWN')
                    except DevelopmentRiskError as error:
                        error.item_index = index
                        error.recovery = dict(tool='get_development_risks', arguments=dict(
                            check_ref=self.ref, workspace_path=str(self.root), offset=0))
                        raise
                    target, original_observation = matches[0]
                    original = original_observation['finding']
                    # Identity and location come from the immutable scan observation.
                    if isinstance(value, ScannerReview):
                        value = Observation(**{k: original[k] for k in (
                            'file_path', 'line_start', 'line_end', 'category', 'title', 'description',
                            'impact', 'fix_advice', 'severity')}, issue_key=target['id'], **value.model_dump())
                    else:
                        value = value.model_copy(update={k: original[k] for k in (
                            'file_path', 'line_start', 'line_end')})
                    value = value.model_copy(update={'same_issue_as': target['id']})
                normalized.append(value)
            values = normalized
            for index, value in enumerate(values):
                name = relative_path(value.file_path)
                # Linked scanner locations were resolved from this scan above.
                require((value.same_issue_as is not None or name in check['observed_paths'])
                        and value.line_end >= value.line_start,
                        'DEVELOPMENT_RISK_LOCATION_INVALID')
                try:
                    evidence = (self.evidence(row, value.evidence_refs, include_source=True) if stream_commit is not None
                                else self.evidence(row, value.evidence_refs))
                    require(any(e['file_path'] == name and e['line_start'] <= value.line_start and
                                e['line_end'] >= value.line_end for e in evidence), 'DEVELOPMENT_RISK_LOCATION_UNREAD')
                except DevelopmentRiskError as error:
                    error.item_index = index
                    if error.reason_code in {'DEVELOPMENT_RISK_EVIDENCE_REQUIRED',
                            'DEVELOPMENT_RISK_EVIDENCE_UNKNOWN', 'DEVELOPMENT_RISK_EVIDENCE_STALE',
                            'DEVELOPMENT_RISK_LOCATION_UNREAD'}:
                        error.recovery = dict(tool='read_development_risk_context', arguments=dict(
                            check_ref=self.ref, workspace_path=str(self.root), file_path=name,
                            start_line=value.line_start, end_line=min(value.line_end, value.line_start+79)))
                    raise
                key = 'dr1-' + digest([self.ref, 'host', name, value.category, value.issue_key])[:32]
                host_key = key
                key = row['aliases'].get(key, key)
                if stream_commit is not None and not value.same_issue_as:
                    from .development_duplicates import confirmed_sql_target
                    primary = confirmed_sql_target(check, row, value, evidence)
                    if primary is not None:
                        key = primary
                        row['aliases'][host_key] = primary
                if value.same_issue_as:
                    matches = [r for r in row['risks'].values() if r['id'] == value.same_issue_as or any(
                        o.get('scanner_id') == value.same_issue_as for o in r['observations'])]
                    require(len(matches) == 1, 'DEVELOPMENT_RISK_LINK_UNKNOWN')
                    target = matches[0]
                    if key in row['risks'] and key != target['id']:
                        # AI-first then scanner: preserve the original AI risk and its repairs.
                        require(not target['assessments'] and not target['repairs'],
                                'DEVELOPMENT_RISK_LINK_HAS_INDEPENDENT_HISTORY')
                        row['risks'][key]['observations'].extend(target['observations'])
                        del row['risks'][target['id']]
                    else:
                        key = target['id']
                    row['aliases'][host_key] = key
                    reviewed_ids.append(key)
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
                    dirty_seq=expected_seq, scan_id=check.get('scan_id'),
                    finding=finding)
                if stream_commit is not None:
                    assessment['stream_batch_id'] = stream_commit['batch_id']
                if audit_id is not None:
                    assessment['audit_id'] = audit_id
                if value.duplicate_of is not None:
                    require(value.same_issue_as and value.decision == 'DISMISSED', 'DEVELOPMENT_DUPLICATE_INVALID')
                    assessment['duplicate_of'] = value.duplicate_of
                    row['has_duplicate_links'] = True
                if value.report_text and value.decision == 'CONFIRMED':
                    assessment['report_text'] = safe(value.report_text)
                if value.report_content is not None:
                    assessment['report_content'] = {k: safe(v) for k, v in value.report_content.model_dump().items()}
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
            if row.get('has_duplicate_links'):
                # Validate the finished batch independently of item order, including
                # later amendments to a primary decision. Exceptions roll it back.
                for risk in row['risks'].values():
                    linked = risk.get('assessment') or {}
                    primary_id = linked.get('duplicate_of')
                    if not primary_id or (linked['scan_id'], linked['dirty_seq']) != (check['scan_id'], expected_seq):
                        continue
                    primary = row['risks'].get(primary_id) or {}
                    proof = primary.get('assessment') or {}
                    stream_primary = bool(proof.get('stream_batch_id') and
                        current_assessment(check, proof, proof['finding']['file_path']))
                    source_current = (stream_primary or
                        ((proof.get('scan_id'), proof.get('dirty_seq')) == (check['scan_id'], expected_seq)
                         and any(o['source'] == 'SCANNER' and o.get('scan_id') == check['scan_id']
                                 for o in primary.get('observations', []))))
                    # A business finding may anchor the source line while the
                    # scanner anchors the sink. Require current issued evidence
                    # covering that location; matching filenames alone never suffice.
                    covered = bool(proof.get('finding') and
                        proof['finding']['line_start'] <= linked['finding']['line_end'] and
                        linked['finding']['line_start'] <= proof['finding']['line_end'])
                    if stream_primary:
                        covered = any(e['file_path'] == linked['finding']['file_path'] and
                            e['line_start'] <= linked['finding']['line_start'] and
                            e['line_end'] >= linked['finding']['line_end']
                            for e in self.evidence(row, proof['evidence_refs']))
                    require(primary_id != risk['id'] and proof.get('decision') == 'CONFIRMED'
                        and source_current
                        and proof['finding']['file_path'] == linked['finding']['file_path']
                        and covered, 'DEVELOPMENT_DUPLICATE_INVALID')
            # Check again before publication: path events during evidence reads invalidate submission.
            require(self.current_check()['dirty_seq'] == expected_seq, 'DEVELOPMENT_RISK_VERSION_STALE')
            review_mark('decisions_checked')
            # Revalidate every submitted evidence receipt before committing the batch.
            for value in values:
                self.evidence(row, value.evidence_refs)
            business_records = []
            for value in business:
                name = relative_path(value.file_path)
                require(name in check['observed_paths'], 'DEVELOPMENT_RISK_PATH_NOT_OBSERVED')
                try:
                    evidence = self.evidence(row, value.evidence_refs)
                    require(any(e['file_path'] == name for e in evidence), 'DEVELOPMENT_RISK_LOCATION_UNREAD')
                except DevelopmentRiskError as error:
                    error.recovery = dict(tool='read_development_risk_context', arguments=dict(
                        check_ref=self.ref, workspace_path=str(self.root), file_path=name))
                    raise
                business_records.append(dict(file_path=name, rationale=safe(value.rationale),
                    evidence_refs=value.evidence_refs, limitations=[safe(s) for s in value.limitations],
                    coverage=value.coverage, uncovered=[safe(s) for s in value.uncovered]))
            for value in business:
                self.evidence(row, value.evidence_refs)
            require(self.current_check().get('scan_id') == check.get('scan_id'),
                    'DEVELOPMENT_RISK_SCAN_VERSION_STALE')
            review = dict(dirty_seq=expected_seq, scan_id=check.get('scan_id'),
                          reviewed_scanner_ids=reviewed_ids, business_reviews=business_records)
            if stream_commit is not None:
                review['stream_batch_id'] = stream_commit['batch_id']
            if audit_id is not None:
                review['audit_id'] = audit_id
            if not row['reviews'] or review != row['reviews'][-1]:
                require(len(row['reviews']) < 256, 'DEVELOPMENT_RISK_HISTORY_LIMIT')
                row['reviews'].append(review)
            # Retain the original ownership/path journal while its risks exist.
            # A failed risk commit may leave a harmless retention pin, never a lost risk.
            current = self.checks._get(db, self.ref)
            require(current['dirty_seq'] == expected_seq, 'DEVELOPMENT_RISK_VERSION_STALE')
            require(current.get('scan_id') == check.get('scan_id'), 'DEVELOPMENT_RISK_SCAN_VERSION_STALE')
            if audit_id is not None:
                coverage = {b['file_path']: b for r in row['reviews'] if r.get('audit_id') == audit_id
                            for b in r.get('business_reviews', [])}
                covered = {k for k,b in coverage.items() if business_coverage(b) == 'COMPLETE'}
                current['parallel_audit']['status'] = ('COMPLETE' if set(check['observed_paths']) <= covered else
                    'PARTIAL' if set(check['observed_paths']) <= set(coverage) else 'RUNNING')
                current['parallel_audit']['covered_paths'] = sorted(covered)
                current['parallel_audit']['reviewed_paths'] = sorted(coverage)
            if stream_commit is not None:
                from .incremental_audit import complete
                complete(current, stream_commit['batch_id'], stream_commit['request_id'],
                         stream_commit['valid_paths'], dependencies=stream_commit['dependencies'])
                current['audit_result_revision'] = current.get('audit_result_revision', 0) + 1
            if final_report:
                current['stop_offered_audit_revision'] = current.get('audit_result_revision', 0)
            review_mark('before_write')
            self.checks._put(db, self.ref, dict(current, has_unified_risks=bool(row['risks']),
                                               has_development_review=True))
            self.store._put(db, self.ref, row)
        review_mark('committed')
        if audit_id and current.get('parallel_audit', {}).get('status') in {'COMPLETE', 'PARTIAL'}:
            from .audit_leases import release
            try:
                release(audit_id)
            except (OSError, sqlite3.Error):
                pass  # The short lease expires; the saved review remains successful.
        from .development_reporting import reporting
        version = (expected_seq, check.get('scan_id'))
        reread = reporting(self.ref, self.root, after_review=True)['next_action']
        reread['arguments'].update(view='final_report' if final_report else 'batch', expected_seq=expected_seq, scan_id=version[1])
        try:
            review_mark('readback_start')
            result = self.get(offset=0, limit=20 if return_risks else 5, include_history=False,
                              batch_version=version, whole_report=final_report)
        except (ValueError, OSError, sqlite3.Error):
            return dict(review_saved=True, reread_required=True, post_commit_read=False,
                        next_action=reread)
        review_mark('readback_done')
        from .performance_trace import review_event
        review_event('saved', check, result['review_progress'] if 'review_progress' in result else review_progress(check, row))
        if return_risks and (result.get('candidates_ready') or result.get('view') == 'final_report') and (
                result['dirty_seq'], result['scan_id']) == (expected_seq, check.get('scan_id')):
            result.update(review_saved=True, post_commit_read=True, reread_required=False)
            return result
        result['reporting'] = reporting(self.ref, self.root, after_review=True)
        result['next_action'] = result['reporting']['next_action'] = reread
        return result

    def get(self, offset=0, limit=5, *, include_history=True, review_only=False, batch_version=None,
            whole_report=False, report_digest=None):
        require(type(offset) is int and offset >= 0 and (limit is None or type(limit) is int and 1 <= limit <= 20),
                'DEVELOPMENT_RISK_PAGE_INVALID')
        check = self.current_check()
        if batch_version is not None:
            require(batch_version == (check['dirty_seq'], check.get('scan_id')),
                    'DEVELOPMENT_RISK_VERSION_STALE')
        row = check.get('security_result') or self.load()
        require(row['owner'] == self.development.owner and
                row['root_identity'] == root_identity(self.root), 'DEVELOPMENT_RISK_OWNER_MISMATCH')
        # Missing/stale projection is unknown, never a successful empty page.
        if ((check.get('finish_requested') and check['state'] in {'QUEUED', 'RUNNING'}) or
                (check.get('scan_id') and (row.get('imported_scan_id') != check['scan_id'] or
                 check.get('risk_import_status', 'AVAILABLE') != 'AVAILABLE'))):
            failed = check.get('risk_import_status') == 'UNAVAILABLE'
            return dict(contract='development-risks-v1', check_ref=self.ref,
                scan_id=check.get('scan_id'), dirty_seq=check['dirty_seq'],
                candidate_status='UNAVAILABLE' if failed else 'PENDING', candidates_ready=False,
                reason_code='DEVELOPMENT_CANDIDATES_UNAVAILABLE' if failed else 'DEVELOPMENT_CANDIDATES_PENDING',
                total=None, next_offset=None, review_progress=review_progress(check, row),
                next_action=dict(tool='get_development_check' if failed else 'wait_development_check',
                    arguments=dict(check_ref=self.ref, workspace_path=str(self.root))),
                scanner_run=False, repair_authorized=False)
        if review_only:
            from .development_views import review_page
            return review_page(self, check, row, review_progress(check, row), offset, limit)
        limit = limit or 20
        report_offset = offset
        if whole_report:
            offset = 0
        risks = list(row['risks'].values())
        if batch_version is not None:
            seq, scan = batch_version
            # Earlier business assessments recorded a sequence only.
            legacy_batch = {v.get('scan_id') for v in row['reviews'] if v['dirty_seq'] == seq} == {scan}
            from .audit_stream_service import assessment_current
            risks = [r for r in risks if any(assessment_current(check, a, r['finding']['file_path']) for a in r['assessments']) or any(o['source'] == 'SCANNER' and o.get('scan_id') == scan
                                            for o in r['observations']) or any(
                not a.get('stream_batch_id') and a['dirty_seq'] == seq and (a.get('scan_id') == scan or
                    (legacy_batch and a.get('scan_id') is None) or
                    (a.get('audit_id') and a.get('audit_id') == (check.get('parallel_audit') or {}).get('audit_id')
                     and (check.get('parallel_audit') or {}).get('status') in {'COMPLETE', 'PARTIAL'})) for a in r['assessments'])]
        risks = [current_risk(check, risk) for risk in risks]
        if whole_report:
            limit = max(1, len(risks))
        from .risk_management import revision
        items = [dict(id=r['id'], **({'revision':revision(r)} if include_history else {}), finding=dict(r['finding'], status=r['status']), decision=r['decision'], status=r['status'],
                      disposition=r.get('disposition', 'ACTIVE'),
                      reminder_suppressed=r.get('disposition', 'ACTIVE') != 'ACTIVE' or r['decision'] == 'DISMISSED'
                          or r['status'] == 'CODE_REVIEWED_RESOLVED',
                      sources=sorted({o['source'] for o in r['observations']}),
                      scanner_observations=[dict(scan_id=o['scan_id'], scanner_id=o['scanner_id'])
                                            for o in r['observations'] if o['source'] == 'SCANNER'],
                      assessment=r.get('assessment'), repairs=r['repairs'][-1:],
                      management=r.get('management', {}),
                      observation_count=len(r['observations']), assessment_count=len(r['assessments']))
                 for r in risks[offset:offset+limit]]
        from .development_reporting import reporting
        next_offset = offset+limit if offset+limit < len(risks) else None
        report = reporting(self.ref, self.root, offset=next_offset)
        result = dict(contract='development-risks-v1', check_ref=self.ref,
                    candidate_status='AVAILABLE', candidates_ready=True,
                    scan_id=check.get('scan_id'), dirty_seq=check['dirty_seq'],
                    review_progress=review_progress(check, row),
                    reporting=report, next_action=report.get('next_action'),
                    risks=items, total=len(risks), next_offset=offset+limit if offset+limit < len(risks) else None,
                    **({'review_versions': row['reviews']} if include_history else {}),
                    review_version_count=len(row['reviews']), history_included=include_history,
                    decision_policy='EVIDENCE_BACKED_HOST_REVIEW', scanner_run=False,
                    source_freshness='NOT_RECHECKED_ON_READ', repair_authorized=False)
        if batch_version is not None:
            from .development_views import batch_report_page
            active = [r for r in risks if r.get('disposition', 'ACTIVE') == 'ACTIVE'
                      and r['status'] != 'CODE_REVIEWED_RESOLVED']
            result['offset'] = offset
            result['report_totals'] = dict(
                confirmed=sum(r['decision'] == 'CONFIRMED' for r in active),
                actionable_confirmed=sum(r['decision'] == 'CONFIRMED' for r in active),
                inconclusive=sum(r['decision'] == 'INCONCLUSIVE' for r in active),
                duplicates=sum(r['decision'] == 'DISMISSED' and bool((r.get('assessment') or {}).get('duplicate_of')) for r in active),
                false_positives=sum(r['decision'] == 'DISMISSED' and not (r.get('assessment') or {}).get('duplicate_of') for r in active))
            page = batch_report_page(result, check)
            if whole_report and 'report_text' in page:
                from .review_delivery import report_page
                return report_page(page, check, self.root, report_offset, report_digest)
            if whole_report:
                require(report_digest is None, 'DEVELOPMENT_RISK_VERSION_STALE')
                from .review_delivery import pending_report_receipt
                return pending_report_receipt(page, self.root)
            return page
        return result

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
            request = risk.get('management', {}).get('repair_request')
            if request:
                request.update(status='PREPARED', repair_ref=fix['repair_ref'])
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
            request = risk.get('management', {}).get('repair_request')
            if request and request.get('repair_ref') == repair_ref:
                request['status'] = 'COMPLETE' if outcome == 'CODE_REVIEWED_RESOLVED' else 'NEEDS_REVIEW'
            self.store._put(db, self.ref, row)
        return dict(risk_id=risk_id, repair_ref=repair_ref, **result, scanner_run=False)

    def manage(self, risk_id, request):
        from .risk_management import apply
        with self.store.transaction() as db:
            row = self.load(db)
            require(risk_id in row['risks'], 'DEVELOPMENT_RISK_UNKNOWN')
            risk, receipt = apply(row['risks'][risk_id], request)
            if not receipt['repeated']:
                if request.get('action') in {'EXCLUDE', 'DEFER'}:
                    from .risk_management import bind_disposition, revision
                    bind_disposition(self.root, risk)
                    receipt['revision'] = revision(risk)
                row['risks'][risk_id] = risk
                self.store._put(db, self.ref, row)
        return dict(receipt, risk_id=risk_id, scanner_run=False, risk_closed=False)

    def disposition(self, risk_id, decision, user_requested, *, reason='', expected_seq=None,
                    expected_revision=None, request_id=None):
        require(user_requested is True, 'DEVELOPMENT_RISK_USER_DECISION_REQUIRED')
        require(decision in {'DEFER', 'EXCLUDE', 'RESTORE'}, 'DEVELOPMENT_RISK_DISPOSITION_INVALID')
        from .risk_management import apply, bind_disposition, revision, revalidate_dispositions
        require(isinstance(reason, str) and len(reason) <= 4000, 'MANAGEMENT_REASON_REQUIRED')
        with self.store.transaction() as db:
            check = self.current_check()
            require(expected_seq is None or (type(expected_seq) is int and expected_seq == check['dirty_seq']),
                    'DEVELOPMENT_RISK_VERSION_STALE')
            row = self.load(db)
            require(risk_id in row['risks'], 'DEVELOPMENT_RISK_UNKNOWN')
            risk = row['risks'][risk_id]
            # Legacy callers omitted a reason. Record that absence, never invent one.
            reason = reason.strip() or '用户明确选择，未填写具体原因'
            history = risk.get('management', {}).get('history', [])
            previous = next((h for h in history if request_id and h['request_id'] == request_id), None)
            before_validation = revision(risk)
            if not previous:
                revalidate_dispositions(self.root, {risk_id: risk})
            request = dict(action=decision, reason=reason, expected_revision=expected_revision or
                           (previous or {}).get('expected_revision') or revision(risk))
            request['request_id'] = request_id or 'chat-' + digest([risk_id, request])[:40]
            prior = risk.get('management', {})
            repeated = (request_id is None and expected_revision is None
                and revision(risk) == before_validation
                and risk.get('disposition', 'ACTIVE') == ('ACTIVE' if decision == 'RESTORE' else decision)
                and prior.get('disposition_reason') == safe(reason))
            if repeated:
                receipt = dict(saved=True, repeated=True, revision=revision(risk))
            else:
                risk, receipt = apply(risk, request)
                if not receipt['repeated']:
                    if decision in {'DEFER', 'EXCLUDE'}:
                        bind_disposition(self.root, risk)
                        receipt['revision'] = revision(risk)
                    row['risks'][risk_id] = risk
                    self.store._put(db, self.ref, row)
        return dict(**receipt, risk_id=risk_id, disposition=risk.get('disposition', 'ACTIVE'),
                    risk_closed=False, scanner_run=False)
