"""Optional product outcome metadata. Never a business authority or source reader."""
from __future__ import annotations

import os
import time
import hashlib
import json
import re
from collections import Counter
from collections import OrderedDict
from contextvars import ContextVar
from functools import wraps
from itertools import islice

_INPUT = ContextVar('monitor_scan_input', default=None)
MAX_ITEMS = 64
VERDICTS = {'CONFIRMED', 'LIKELY', 'NEEDS_REVIEW', 'UNLIKELY', 'FALSE_POSITIVE', 'UNKNOWN'}
OUTCOMES = {'OPEN', 'SCANNER_VERIFIED_RESOLVED', 'CODE_REVIEWED_RESOLVED', 'STILL_PRESENT', 'INCONCLUSIVE'}
_TASK_VIEWS = OrderedDict()


def enabled():
    if os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR') == '0' or os.getenv('SECURITY_RUNTIME_CONTEXT_MODE') == 'off':
        return None
    from .context_cost_worker import get_worker
    worker = get_worker()
    return worker if worker is not None and worker.snapshot_settings().get('mode') in {'basic', 'debug'} else None


def publish(fact, *, workspace=None):
    worker = enabled()
    if worker is None:
        return
    from .observation import current_facts
    context = current_facts()
    setting = worker.snapshot_settings()
    return worker.offer(envelope(fact, workspace=workspace or context.get('workspace'),
        owner=context.get('owner'), correlation=context.get('correlation', {}),
        run='unobserved-start-setting' if setting.get('source') == 'startup' else setting.get('run', 'default')))


def envelope(fact, *, workspace=None, owner=None, correlation=None, run='default'):
    now = time.time()
    return dict(tool='product_outcome', transport='workspace', succeeded=True,
        started_at=now, finished_at=now, elapsed_ms=0, workspace=workspace,
        chat_owner=owner, correlation=correlation or {}, run_label=run,
        measurements={}, observations={}, product_fact=fact)


def observe_scan(call):
    @wraps(call)
    def wrapped(*args, **kwargs):
        token = None
        try:
            if enabled() is not None:
                token = _INPUT.set(dict(files={}, bytes=0, limited=False))
        except Exception:
            pass
        try:
            return call(*args, **kwargs)
        finally:
            if token is not None:
                _INPUT.reset(token)
    return wrapped


def observe_input(name, role, raw):
    state = _INPUT.get()
    if state is None or role != 'TARGET':
        return
    if len(state['files']) >= 10000 or len(raw) > 4*1024*1024 or state['bytes'] + len(raw) > 64*1024*1024:
        state['limited'] = True
        return
    state['bytes'] += len(raw)
    # Physical lines, including comments/blanks; CRLF is one separator.
    count = None if b'\0' in raw else raw.count(b'\n') + raw.count(b'\r') - raw.count(b'\r\n') + int(bool(raw) and raw[-1:] not in (b'\r', b'\n'))
    state['files'][name] = count


def finding_item(value):
    def get(key, default=None):
        return value.get(key, default) if isinstance(value, dict) else getattr(value, key, default)
    category = get('category')
    category = {'secret':'secret', 'dependency':'dependency', 'configuration':'configuration'}.get(category, 'code')
    severity = str(get('severity', 'UNKNOWN')).upper()
    item = dict(id=get('id'), category=category,
        severity=severity if severity in {'CRITICAL','HIGH','MEDIUM','LOW','INFO'} else 'UNKNOWN')
    # Only reuse an existing producer identity. A common source location does
    # not prove that independent host findings describe the same risk. Missing
    # fingerprints stay unlinked; their scoped occurrence IDs remain distinct.
    fingerprint = get('fingerprint')
    if isinstance(fingerprint, str) and re.fullmatch(r'[a-fA-F0-9]{24,64}', fingerprint):
        item['risk_key'] = hashlib.sha256(('fingerprint:'+fingerprint.lower()).encode()).hexdigest()
    return item


def scan_fact(scan, plans=None):
    from .monitor_checks import scan_check
    get = scan.get if isinstance(scan, dict) else lambda name, default=None: getattr(scan, name, default)
    findings = get('findings', [])
    state = _INPUT.get() if plans is not None else None
    lines = dict(target_lines=None, confirmed_file_lines=None, target_files=None,
                 confirmed_files=None, unknown_files=None, status='UNKNOWN')
    if state is not None and state['files']:
        files = state['files']
        confirmed = set()
        for plan in plans.values():
            if not plan.unscoped_error:
                confirmed.update(plan.scanned_files - plan.errored_files - set(plan.skipped_files))
        known = {name: count for name, count in files.items() if count is not None}
        confirmed &= known.keys()
        lines = dict(target_lines=sum(known.values()), confirmed_file_lines=sum(known[name] for name in confirmed),
            target_files=len(files), confirmed_files=len(confirmed), unknown_files=sum(v is None for v in files.values()),
            status='PARTIAL' if state['limited'] or len(known) != len(files) or len(confirmed) != len(files) else 'OBSERVED')
    return dict(kind='SCAN', reference=get('scan_id'), source='LIVE' if plans is not None else 'HISTORY',
        total=len(findings), omitted=max(0, len(findings)-MAX_ITEMS),
        items=[finding_item(item) for item in findings[:MAX_ITEMS]], lines=lines, check=scan_check(scan))


def scan_completed(result, plans):
    if enabled() is not None:
        publish(scan_fact(result, plans), workspace=result.target_profile.path)


def assessment(record):
    get = record.get if isinstance(record, dict) else lambda name, default=None: getattr(record, name, default)
    status = get('status')
    verdict = str(get('verdict')) if status == 'VALID' else 'UNKNOWN'
    return dict(kind='ASSESSMENT', reference=get('scan_id'), source='LIVE', total=1, omitted=0,
        items=[dict(id=get('finding_id'), verdict=verdict if verdict in VERDICTS else 'UNKNOWN')])


def triage_saved(record):
    publish(assessment(record))


def ledger_saved(rows, workspace):
    # Bound optional work. Group by origin without traversing unrelated history.
    groups = {}
    selected = list(islice(rows, MAX_ITEMS+1))
    for row in selected[:MAX_ITEMS]:
        scope = row.get('origin_scan_id') if row.get('source') == 'SCANNER' else row['origin_task_ref']
        status = row.get('status', 'INCONCLUSIVE')
        groups.setdefault(scope, []).append(dict(id=row['finding_id'], outcome=status if status in OUTCOMES else 'INCONCLUSIVE'))
    for index,(reference, items) in enumerate(groups.items()):
        omitted = int(index == 0 and len(selected) > MAX_ITEMS)
        publish(dict(kind='VERIFICATION', reference=reference, source='LIVE', total=len(items)+omitted,
            omitted=omitted, items=items), workspace=str(workspace))


def feedback_saved(reference, finding_id, verdict, workspace):
    publish(dict(kind='ASSESSMENT', reference=reference, source='LIVE', total=1, omitted=0,
        items=[dict(id=finding_id, verdict=verdict)]), workspace=str(workspace))


def proposals_saved(reference, findings, workspace):
    publish(dict(kind='PROPOSAL', reference=reference, source='LIVE', total=len(findings),
        omitted=max(0, len(findings)-MAX_ITEMS), items=[finding_item(item) for item in findings[:MAX_ITEMS]]),
        workspace=str(workspace))


def handling_observed(rows, workspace):
    """Already-computed product view only; no lookup and no implicit repair."""
    if enabled() is None:
        return
    from .monitor_risks import HANDLING_STATES
    selected = list(islice(rows, MAX_ITEMS+1))
    groups = {}
    for row in selected[:MAX_ITEMS]:
        reference = row.get('origin_scan_id') if row.get('source') == 'SCANNER' else row.get('origin_task_ref')
        handling = row.get('handling_status')
        if handling == 'PENDING':
            handling = 'OPEN'
        # Existing freshness projection has already checked source changes.
        if row.get('status') in {'NEEDS_RECHECK','INCONCLUSIVE'}:
            handling = 'UNKNOWN'
        groups.setdefault(reference, []).append(dict(id=row['finding_id'],
            handling=handling if handling in HANDLING_STATES else 'UNKNOWN'))
    for index, (reference, items) in enumerate(groups.items()):
        omitted = int(index == 0 and len(selected) > MAX_ITEMS)
        publish(dict(kind='HANDLING', reference=reference, source='LIVE', total=len(items)+omitted,
            omitted=omitted, items=items), workspace=str(workspace))


def task_record_observed(record):
    """Post-commit metadata only, including review paths that return packets."""
    if enabled() is None:
        return
    progress = record.get('review_completion')
    plan = record.get('review_plan') or {}
    if not progress and isinstance(plan.get('units'),list):
        units = plan['units']
        progress = dict(unit_count=len(units), reviewed_unit_count=(
            sum(unit.get('status')=='REVIEWED' for unit in units) if len(units)<=MAX_ITEMS else None))
    view = dict(task_ref=record['task_ref'],status=('CAPACITY_REQUIRED' if record.get('review_capacity')
            and record['phase'] not in {'COMPLETE','INCOMPLETE','NO_CHANGES'} else record['phase']),
        changed_file_count=len(record.get('changes',())), unverified_file_count=len(record.get('unverified_paths',())),
        limitations=record.get('limitations') or (record.get('baseline') or {}).get('limitations') or [],
        static=record.get('static'),host_review=record.get('review'),review_progress=progress,
        context_read_coverage=dict(gaps=record.get('context_gaps') or []))
    task_observed(view,record['workspace'],record.get('generation',0),projection_rank=0)


def task_observed(view, workspace, revision=0, *, handling=(), projection_rank=1):
    """Report a task which may never reach a scanner; repeated polls are views."""
    if enabled() is None:
        return
    # These are the task view's existing, already-computed handling results.
    # Missing entries remain unknown; never fill them by querying a ledger.
    for reference, feedback in islice(handling, 2):
        if reference:
            handling_observed((dict(source='SCANNER',origin_scan_id=reference,finding_id=identity,
                handling_status=value.get('handling_status','UNKNOWN'),status=value.get('status'))
                for identity,value in islice(feedback.items(),MAX_ITEMS+1)),workspace)
    from .monitor_checks import task_check
    check = task_check(view)
    revision = revision if type(revision) is int and 0 <= revision <= 10**9 else 0
    identity = hashlib.sha256((str(workspace)+'\0'+view['task_ref']).encode()).hexdigest()
    signature = hashlib.sha256(json.dumps([revision,projection_rank,check],sort_keys=True).encode()).hexdigest()
    if _TASK_VIEWS.get(identity) == signature:
        return
    if publish(dict(kind='CHECK', reference=view['task_ref'], source='LIVE', total=0,
            omitted=0, items=[], check=check, revision=revision,projection_rank=projection_rank), workspace=str(workspace)):
        _TASK_VIEWS[identity] = signature
        _TASK_VIEWS.move_to_end(identity)
        if len(_TASK_VIEWS)>256:
            _TASK_VIEWS.popitem(last=False)


def validate_fact(value):
    from .context_cost_worker import _mapping, _text, _number, _CALL_ID
    value = _mapping(value, {'kind','reference','source','total','omitted','items','lines','check','revision','projection_rank'})
    if value.get('kind') not in {'SCAN','ASSESSMENT','VERIFICATION','PROPOSAL','HANDLING','CHECK'} or value.get('source') not in {'LIVE','HISTORY'}:
        raise ValueError('INVALID_PRODUCT_FACT')
    reference = _text(value['reference'], 256)
    if not reference or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:' for c in reference):
        raise ValueError('INVALID_PRODUCT_REFERENCE')
    items = value['items']
    if type(items) is not list or len(items) > MAX_ITEMS:
        raise ValueError('INVALID_PRODUCT_ITEMS')
    out = dict(kind=value['kind'], reference=reference, source=value['source'],
        total=_number(value['total'], 10**8), omitted=_number(value['omitted'], 10**8), items=[])
    for item in items:
        fields = ({'id','category','severity','risk_key'} if value['kind'] in {'SCAN','PROPOSAL'}
            else {'id','verdict'} if value['kind'] == 'ASSESSMENT'
            else {'id','handling'} if value['kind'] == 'HANDLING' else {'id','outcome'})
        item = _mapping(item, fields)
        identity = _text(item['id'], 128)
        if not identity or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:' for c in identity):
            raise ValueError('INVALID_FINDING_REFERENCE')
        clean = dict(id=identity)
        if 'risk_key' in item:
            risk_key = _text(item['risk_key'], 64)
            if not re.fullmatch(r'[a-f0-9]{64}', risk_key):
                raise ValueError('INVALID_RISK_IDENTITY')
            clean['risk_key'] = risk_key
        if 'handling' in fields:
            from .monitor_risks import HANDLING_STATES
            if item.get('handling') not in HANDLING_STATES:
                raise ValueError('INVALID_HANDLING_STATE')
            clean['handling'] = item['handling']
        for key, allowed in (('category', {'code','secret','dependency','configuration'}),
            ('severity', {'CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'}), ('verdict',VERDICTS), ('outcome',OUTCOMES)):
            if key in fields:
                if item.get(key) not in allowed:
                    raise ValueError('INVALID_PRODUCT_ENUM')
                clean[key] = item[key]
        out['items'].append(clean)
    if out['total'] != len(items) + out['omitted']:
        raise ValueError('INVALID_PRODUCT_TOTAL')
    if value['kind'] == 'CHECK':
        if items or out['total']:
            raise ValueError('INVALID_CHECK_TOTAL')
        from .monitor_checks import validate_check
        out['check'] = validate_check(value['check'])
        out['revision'] = _number(value.get('revision',0),10**9)
        out['projection_rank'] = _number(value.get('projection_rank',0),1)
    if value['kind'] == 'SCAN':
        lines = _mapping(value['lines'], {'target_lines','confirmed_file_lines','target_files','confirmed_files','unknown_files','status'})
        if lines['status'] not in {'UNKNOWN','PARTIAL','OBSERVED'}:
            raise ValueError('INVALID_LINE_STATUS')
        out['lines'] = {k: None if v is None else _number(v, 10**9) for k,v in lines.items() if k != 'status'}
        out['lines']['status'] = lines['status']
        if 'check' in value:
            from .monitor_checks import validate_check
            out['check'] = validate_check(value['check'])
    return out


def report(facts):
    from .monitor_checks import scan_check
    from .monitor_risks import current_risks
    scans, proposals, decisions, verifications, decision_sources, observed_at, tasks = {}, {}, {}, {}, {}, {}, {}
    for event in sorted(facts, key=lambda item: item.get('finished_at') or 0):
        fact = event['product_fact']
        scope = (event.get('workspace_hash'), fact['reference'])
        if fact['kind'] == 'SCAN':
            # A history import cannot replace observed physical line evidence.
            if scope not in scans or fact['source'] == 'LIVE':
                scans[scope] = fact
                observed_at.setdefault(scope, event.get('finished_at'))
        elif fact['kind'] == 'PROPOSAL':
            proposals[scope] = fact
        elif fact['kind'] == 'CHECK':
            priority = (fact.get('revision',0),fact.get('projection_rank',0))
            if scope not in tasks or priority > (tasks[scope][0].get('revision',0),tasks[scope][0].get('projection_rank',0)):
                tasks[scope] = (fact,event.get('finished_at'))
        for item in fact['items']:
            key = (*scope, item['id'])
            if fact['kind'] == 'ASSESSMENT':
                # Historical snapshots have no proven ordering against live events.
                if key not in decisions or fact['source'] == 'LIVE' or decision_sources[key] != 'LIVE':
                    decisions[key] = item['verdict']
                    decision_sources[key] = fact['source']
            elif fact['kind'] == 'VERIFICATION':
                verifications[key] = item['outcome']
    finding_keys = {(*scope, item['id']) for scope,fact in {**scans, **proposals}.items() for item in fact['items']}
    verdicts = Counter(decisions.get(key, 'UNKNOWN') for key in finding_keys | decisions.keys())
    outcomes = Counter(verifications.values())
    rows = []
    for index,(scope,fact) in enumerate(scans.items(), 1):
        rows.append(dict(scan=f'scan-{index}', source=fact['source'], findings=fact['total'],
            omitted_findings=fact['omitted'], categories=dict(Counter(i['category'] for i in fact['items'])),
            severities=dict(Counter(i['severity'] for i in fact['items'])), lines=fact['lines'],
            check=fact.get('check') or scan_check({}), observed_at=observed_at.get(scope)))
    checks = [dict(subject=row['scan'],kind='SCAN',source=row['source'],check=row['check'],
                   observed_at=row['observed_at']) for row in rows]
    checks += [dict(subject=f'task-{index}',kind='TASK',source=fact['source'],check=fact['check'],
                    observed_at=at) for index,(fact,at) in enumerate(tasks.values(),1)]
    live = [row for row in checks if row['source']=='LIVE']
    latest = max(live or checks, key=lambda row: row.get('observed_at') or 0) if checks else None
    return dict(scope='RETAINED_OBSERVATIONS; HISTORICAL_OUTCOMES_NOT_CURRENT_SAFETY', scans=len(scans),
        findings=sum(v['total'] for v in scans.values()), finding_occurrences=len(finding_keys),
        cumulative_finding_occurrences=sum(v['total'] for v in scans.values()),
        current_risks=current_risks(facts),
        checks=checks,
        check_summary=dict(observed_checks=len(checks),scan_checks=len(rows),task_checks=len(tasks),
            status_counts=dict(Counter(row['check']['status'] for row in checks)),
            latest=dict(latest['check'], scan=latest['subject'], kind=latest['kind'],source=latest['source'],
                        observed_at=latest['observed_at']) if latest else None),
        known_finding_identities=len({(key[0],key[2]) for key in finding_keys}),
        host_proposals=sum(v['total'] for v in proposals.values()),
        omitted_findings=sum(v['omitted'] for v in [*scans.values(), *proposals.values()]),
        known_target_lines=sum(v['lines']['target_lines'] or 0 for v in scans.values()),
        known_confirmed_file_lines=sum(v['lines']['confirmed_file_lines'] or 0 for v in scans.values()),
        scans_without_line_evidence=sum(v['lines']['status']=='UNKNOWN' for v in scans.values()),
        ai_confirmed=verdicts['CONFIRMED'], ai_likely=verdicts['LIKELY'], ai_unknown=verdicts['UNKNOWN']+verdicts['NEEDS_REVIEW'],
        ai_false_positive=verdicts['FALSE_POSITIVE'], ai_unlikely=verdicts['UNLIKELY'],
        scanner_verified_resolved=outcomes['SCANNER_VERIFIED_RESOLVED'],
        code_reviewed_resolved=outcomes['CODE_REVIEWED_RESOLVED'], verification_outcomes=dict(outcomes),
        verification_records_limited=any(e['product_fact']['omitted'] for e in facts if e['product_fact']['kind']=='VERIFICATION'),
        rows=rows, acceptance_scope='EXPLICIT_VALIDATED_VERDICT; NOT_SCHEMA_ACCEPTED_OR_AUTOMATIC_FIX',
        lines_scope='PHYSICAL_TARGET_FILE_LINES_INCLUDING_BLANKS_COMMENTS; NOT_RULE_OR_BRANCH_COVERAGE')
