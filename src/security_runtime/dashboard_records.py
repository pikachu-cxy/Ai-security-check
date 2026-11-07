"""Public read models and locally authorized writes; never scan or edit source."""
from pathlib import Path
import re
import secrets
import time
from .hook_state import HookStateStore, no_links
from .tasks.durable import SignedRecords
from .project_identity import describe
from .risk_management import revision, apply
from .redactor import SecretRedactor


def enrich(item, row, risk, scope=None):
    redact = SecretRedactor().redact
    scope = scope or describe(row['workspace'])
    management = risk.get('management', {})
    finding = risk.get('finding', {})
    observations = risk.get('observations', [])
    assessment = risk.get('assessment') or {}
    return dict(item, **scope, session_id=(row.get('owner') or {}).get('session', ''),
        check_id=row.get('key', ''), revision=revision(risk),
        archived=bool(management.get('archived')), management=management,
        file_path=item.get('location', '').rsplit(':', 1)[0] if finding.get('line_start') else finding.get('file_path', ''),
        line_start=finding.get('line_start'), line_end=finding.get('line_end'),
        rule_id=redact(str((finding.get('technical_details') or {}).get('rule_id', finding.get('category', '')))),
        scanner_sources=finding.get('scanner_sources', []),
        scan_ids=sorted({str(o['scan_id']) for o in observations if o.get('scan_id')}),
        observation_count=len(observations), decision=risk.get('decision'),
        scanner_candidate=any(o.get('source') == 'SCANNER' for o in observations),
        confirmed_risk=risk.get('decision') == 'CONFIRMED' and not assessment.get('duplicate_of'),
        evidence=redact(str(finding.get('evidence', '')))[:8000],
        report_text=redact(str(assessment.get('report_text', '')))[:20000],
        assessment=redact(str(assessment.get('rationale', '')))[:4000],
        source_freshness='HISTORICAL_NOT_RECHECKED', editable=bool(row.get('owner')),
        disposition_review_required=bool(management.get('disposition_review_required') or
            management.get('disposition_evidence_revision') and
            management['disposition_evidence_revision'] != revision(finding)))


def locate(identifier, *, allow_scope=False):
    from . import risk_dashboard as dashboard
    if not isinstance(identifier, str) or len(identifier) > 500:
        raise ValueError('MANAGEMENT_INVALID_ID')
    parts = identifier.split(':')
    if len(parts) != 4:
        raise ValueError('MANAGEMENT_INVALID_ID')
    editor, wid, check, rid = parts
    sources = {k: folder for k, _, folder in dashboard.SOURCES}
    if editor not in sources or not re.fullmatch('[a-f0-9]{64}', wid) or any(
            not re.fullmatch('[A-Za-z0-9_$.-]{1,180}', x) for x in (check, rid)):
        raise ValueError('MANAGEMENT_INVALID_ID')
    wd = dashboard.STATE / sources[editor] / wid
    no_links(wd)
    paths = [wd/'hooks'/wid/'development-checks.db', wd/'hooks'/wid/'development-risks.db']
    if check == 'manual':
        paths = [wd/'hooks'/wid/'manual-risks.db']
    for path in paths:
        if not path.exists():
            continue
        rows = dashboard.signed_rows(path, wd)
        row = next((v for v in rows if v.get('key') == check), None)
        if row and (rid in row.get('risks', {}) or allow_scope and rid == '$scope'):
            return wd, row, rid
    raise ValueError('MANAGEMENT_RECORD_UNAVAILABLE')


def mutate(identifier, request):
    wd, row, rid = locate(identifier)
    hooks, root = HookStateStore(wd/'hooks'), Path(row['workspace'])
    if row['key'] == 'manual':
        store = SignedRecords(hooks, root, 'manual-risks.db')
        with store.transaction() as db:
            row = store._get(db, 'manual')
            row['risks'][rid], receipt = apply(row['risks'][rid], request)
            if not receipt['repeated']:
                store._put(db, 'manual', row)
        return receipt
    from .development_check import DevelopmentCheckService
    from .development_risks import DevelopmentRisks
    service = DevelopmentCheckService(None, hooks, owner=row.get('owner'))
    if request.get('action') == 'REPAIR' and request.get('fields', {}).get('target_host', 'codex') != row['owner']['host']:
        raise ValueError('MANAGEMENT_ORIGINAL_HOST_REQUIRED')
    risks = DevelopmentRisks(service, root, row['key'])
    receipt = risks.manage(rid, request)
    if request.get('action') == 'REPAIR':
        from .repair_notifications import enqueue
        enqueue(hooks, root, dict(risks.load(), key=row['key']), rid)
    return receipt


def create(data):
    """Manual records attach only to an already verified project, never an arbitrary path."""
    if not isinstance(data, dict) or set(data) != {'anchor_id', 'request_id', 'finding'}:
        raise ValueError('MANAGEMENT_INVALID_CREATE')
    wd, anchor, _ = locate(data['anchor_id'], allow_scope=True)
    finding = data['finding']
    fields = {'title', 'file_path', 'line_start', 'line_end', 'description', 'impact', 'fix_advice', 'severity', 'category', 'evidence'}
    if not isinstance(finding, dict) or set(finding) - fields or not finding.get('title'):
        raise ValueError('MANAGEMENT_INVALID_FINDING')
    from .finding_quality import relative_file
    finding = dict(finding, file_path=relative_file(finding.get('file_path', '')))
    for key in ('line_start', 'line_end'):
        if type(finding.get(key)) is not int or finding[key] < 1:
            raise ValueError('MANAGEMENT_INVALID_LOCATION')
    if finding['line_end'] < finding['line_start'] or finding.get('severity') not in {'CRITICAL','HIGH','MEDIUM','LOW','INFO'}:
        raise ValueError('MANAGEMENT_INVALID_FINDING')
    if any(not isinstance(v, str) or len(v) > 8000 for k, v in finding.items() if k not in {'line_start','line_end'}):
        raise ValueError('MANAGEMENT_INVALID_FINDING')
    request_id = data['request_id']
    if not isinstance(request_id, str) or not re.fullmatch('[A-Za-z0-9_-]{8,100}', request_id):
        raise ValueError('MANAGEMENT_INVALID_REQUEST_ID')
    redact = SecretRedactor().redact
    finding = {k: redact(v) if isinstance(v, str) else v for k, v in finding.items()}
    store = SignedRecords(HookStateStore(wd/'hooks'), Path(anchor['workspace']), 'manual-risks.db')
    rid = 'manual-' + request_id
    with store.transaction() as db:
        row = store._get(db, 'manual') or dict(risks={}, owner=None)
        risk = row['risks'].get(rid)
        if risk:
            if risk['finding'] != finding:
                raise ValueError('MANAGEMENT_REQUEST_REUSED')
        else:
            risk = dict(id=rid, finding=finding, decision=None, status='OPEN', disposition='ACTIVE',
                        observations=[], created_at=time.time(), sources=['MANUAL'])
            row['risks'][rid] = risk
            store._put(db, 'manual', row)
    return dict(saved=True, id=':'.join((data['anchor_id'].split(':')[0], wd.name, 'manual', rid)), revision=revision(risk))
