"""Owner-authorized child audit capability and durable result reception.

No model, scanner, worker or polling. Tokens never enter persisted payloads.
"""
import hashlib
import hmac
import secrets
import time

from . import incremental_audit as state
from .development_risks import BusinessReview, Observation, require, safe
from .scan_request import relative_path


def authenticate(check, token, agent_ref=None):
    grant = check.get('audit_delegate') or {}
    require(isinstance(token, str) and 20 <= len(token) <= 200, 'AUDIT_CAPABILITY_INVALID')
    require(not grant.get('revoked') and grant.get('token_hash') and
            hmac.compare_digest(grant['token_hash'], hashlib.sha256(token.encode()).hexdigest()),
            'AUDIT_CAPABILITY_INVALID')
    require(grant.get('agent_ref') and (agent_ref is None or grant['agent_ref'] == agent_ref),
            'AUDIT_EXECUTOR_NOT_BOUND')
    require(grant.get('round_id') == state.progress(check).get('round_id'), 'AUDIT_ROUND_CHANGED')
    from .user_config import batch_config
    require(batch_config(check)['agent']['audit_business_logic'], 'BUSINESS_AUDIT_DISABLED')
    return grant


def manage(risks, action, *, agent_ref=None, related_paths=(), audit_token=None):
    from .user_config import batch_config
    token = None
    if action == 'status':
        check = risks.current_check()
        grant = check.get('audit_delegate') or {}
        return _status(check, grant)
    with risks.checks.transaction() as db:
        check = risks.checks._get(db, risks.ref)
        require(batch_config(check)['agent']['audit_business_logic'], 'BUSINESS_AUDIT_DISABLED')
        grant = check.get('audit_delegate') or {}
        if action in {'prepare', 'rotate'}:
            state.record_changes(check, check.get('observed_paths', []) if not check.get('audit_stream') else [])
            round_id = state.progress(check).get('round_id')
            if not grant or grant.get('revoked') or grant.get('round_id') != round_id or action == 'rotate':
                for batch in (check.get('audit_stream') or {}).get('batches', {}).values():
                    if batch.get('status') not in {'COMPLETE', 'CANCELLED'}:
                        state.cancel(check, batch['batch_id'])
                token = 'ad1-' + secrets.token_hex(32)
                grant = dict(token_hash=hashlib.sha256(token.encode()).hexdigest(), revoked=False,
                             round_id=round_id,
                             related_paths=[relative_path(p) for p in related_paths], created_at=time.time())
                check['audit_delegate'] = grant
        elif action == 'started':
            require(grant and not grant.get('revoked'), 'AUDIT_CAPABILITY_INVALID')
            require(grant.get('round_id') == state.progress(check).get('round_id'), 'AUDIT_ROUND_CHANGED')
            require(isinstance(agent_ref, str) and 1 <= len(agent_ref) <= 200, 'BUSINESS_AUDIT_AGENT_REQUIRED')
            require(not grant.get('agent_ref') or grant['agent_ref'] == agent_ref, 'BUSINESS_AUDIT_ALREADY_CLAIMED')
            if audit_token is not None:
                require(isinstance(audit_token, str) and hmac.compare_digest(grant['token_hash'],
                    hashlib.sha256(audit_token.encode()).hexdigest()), 'AUDIT_CAPABILITY_INVALID')
            grant.update(agent_ref=agent_ref, started_at=grant.get('started_at', time.time()))
            grant.pop('failure', None)
            token = audit_token
        elif action == 'failed':
            require(grant and grant.get('agent_ref') == agent_ref and agent_ref,
                    'AUDIT_EXECUTOR_NOT_BOUND')
            grant['failure'] = 'HOST_AUDIT_FAILED'
        elif action == 'authorize_paths':
            require(grant and not grant.get('revoked'), 'AUDIT_CAPABILITY_INVALID')
            require(len(related_paths) <= 50, 'AUDIT_RELATED_LIMIT')
            names = sorted(set(grant.get('related_paths', [])) | {relative_path(p) for p in related_paths})
            require(len(names) <= 200, 'AUDIT_RELATED_LIMIT')
            grant['related_paths'] = names
        elif action == 'cancel':
            grant['revoked'] = True
            check['audit_delegate'] = grant
            for batch in (check.get('audit_stream') or {}).get('batches', {}).values():
                if batch.get('status') not in {'COMPLETE', 'CANCELLED'}:
                    state.cancel(check, batch['batch_id'])
        else:
            require(action == 'status', 'AUDIT_ACTION_INVALID')
        risks.checks._put(db, risks.ref, check)
        result = _status(check, grant)
    if token:
        result['audit_token'] = token
        if action == 'started':
            result['child_call'] = dict(tool='development_review', operation='process_development_audit',
                arguments=dict(workspace_path=str(risks.root), check_ref=risks.ref,
                               agent_ref=agent_ref, audit_token=token, action='claim'))
        else:
            result['registration'] = dict(action='stream_started', check_ref=risks.ref,
                workspace_path=str(risks.root), audit_token=token)
            result['handoff_instruction'] = ('实际创建只读子 Agent 后，将其真实 agent_ref 与当前父会话 session_ref '
                '加入 registration 调用 manage_development_audit；只把返回的完整 child_call 交给子 Agent 执行。'
                '不要提前让子 Agent 猜参数领取；子任务不接收父会话 session_ref。')
    return result


def _batch(check, batch_id, token, agent_ref):
    authenticate(check, token, agent_ref)
    return state.authenticate(check, batch_id, token, agent_ref)


def _public_batch(batch):
    return {k: v for k, v in batch.items() if k not in {'token', 'token_hash', 'receipts'}}


def process(risks, action, *, audit_token, agent_ref, batch_id=None, request_id=None,
            windows=None, observations=(), business_reviews=()):
    authenticate(risks.current_check(), audit_token, agent_ref)
    if action == 'claim':
        with risks.checks.transaction() as db:
            check = risks.checks._get(db, risks.ref)
            authenticate(check, audit_token, agent_ref)
            batch = state.claim(check, agent_ref, token=audit_token, round_id=check['audit_delegate']['round_id'])
            grant = check['audit_delegate']
            grant['claimed_at'] = grant.get('claimed_at', time.time())
            grant.pop('failure', None)
            if not batch.get('batch_id') and state.progress(check)['status'] == 'COMPLETE':
                grant['closed'] = True
            risks.checks._put(db, risks.ref, check)
        result = dict(batch=_public_batch(batch) if batch else None, progress=state.progress(check), scanner_run=False)
        if batch.get('batch_id'):
            result['context'] = process(risks, 'read', audit_token=audit_token, agent_ref=agent_ref,
                batch_id=batch['batch_id'], windows=[dict(file_path=p, start_line=1, end_line=80)
                    for p in list(batch['versions'])[:8]])
            result['submission_contract'] = dict(
                observation_required=[name for name, field in Observation.model_fields.items() if field.is_required()],
                observation_extra_fields_allowed=False,
                instruction='发现项使用 observations 的完整字段，report_content 不能代替必填的 description、impact、fix_advice；不传 kind。'
                            '没有发现则 observations=[]，仍提交已审路径的 business_reviews。原样保留身份、batch_id 和稳定 request_id。')
        return result
    if action == 'recover' and request_id:
        check = risks.current_check()
        receipt = (check.get('audit_stream') or {}).get('receipts', {}).get(request_id)
        require(receipt is not None, 'BUSINESS_AUDIT_RECEIPT_UNKNOWN')
        return process(risks, 'submit', audit_token=audit_token, agent_ref=agent_ref,
            batch_id=receipt['batch_id'], request_id=request_id, **receipt['payload'])
    if action in {'recover', 'heartbeat'}:
        with risks.checks.transaction() as db:
            check = risks.checks._get(db, risks.ref)
            authenticate(check, audit_token, agent_ref)
            if batch_id:
                batch = _batch(check, batch_id, audit_token, agent_ref)
                if action == 'heartbeat':
                    require(batch.get('status') != 'CANCELLED', 'AUDIT_BATCH_CANCELLED')
                    batch['lease_until'] = time.time() + 300
            if action == 'heartbeat':
                risks.checks._put(db, risks.ref, check)
        return dict(progress=state.progress(check),
            pending_request_ids=[r['request_id'] for r in check.get('audit_stream', {}).get('receipts', {}).values()
                                 if r['status']=='RECEIVED'][:20], scanner_run=False)
    if action == 'read':
        check = risks.current_check()
        batch = _batch(check, batch_id, audit_token, agent_ref)
        require(windows and len(windows) <= 20, 'AUDIT_WINDOWS_INVALID')
        allowed = set(batch['versions']) | set(check['audit_delegate'].get('related_paths', []))
        requested = [relative_path(w['file_path']) for w in windows]
        missing = sorted(set(requested) - allowed)
        if missing:
            return dict(error='AUDIT_RELATED_AUTHORIZATION_REQUIRED', requested_related_paths=missing,
                        parent_action='stream_authorize_paths', scanner_run=False)
        from .development_views import read_contexts, EvidenceWindow
        result = read_contexts(risks, [EvidenceWindow(**dict(w, related=True)) for w in windows])
        for error in list(result.get('errors', [])):
            try:
                item = absence_evidence(risks, error['file_path'])
            except (ValueError, OSError):
                continue
            result['evidence'].append(item)
            result['errors'].remove(error)
        with risks.checks.transaction() as db:
            check = risks.checks._get(db, risks.ref)
            batch = _batch(check, batch_id, audit_token, agent_ref)
            batch['issued_evidence'] = sorted(set(batch.get('issued_evidence', [])) |
                {e['evidence_ref'] for e in result.get('evidence', [])})
            risks.checks._put(db, risks.ref, check)
        return result
    require(action == 'submit', 'AUDIT_ACTION_INVALID')
    require(len(observations) <= 50 and len(business_reviews) <= 50, 'DEVELOPMENT_RISK_LIMIT')
    values = [Observation.model_validate(v).model_dump() for v in observations]
    reviews = [BusinessReview.model_validate(v).model_dump() for v in business_reviews]
    require(all(not v.get('same_issue_as') and not v.get('scan_id') and not v.get('duplicate_of') for v in values),
            'AUDIT_SCANNER_AUTHORITY_FORBIDDEN')
    # redact explanatory text before the durable inbox, including stale results
    for v in [*values, *reviews]:
        for key, value in list(v.items()):
            if key not in {'file_path', 'issue_key', 'decision', 'severity', 'category', 'evidence_refs'}:
                v[key] = _scrub(value)
    payload = dict(observations=values, business_reviews=reviews)
    with risks.checks.transaction() as db:
        check = risks.checks._get(db, risks.ref)
        batch = _batch(check, batch_id, audit_token, agent_ref)
        require(all(v['file_path'] in batch['versions'] for v in [*values, *reviews]), 'AUDIT_PATH_NOT_CLAIMED')
        receipt = state.receive(check, batch_id, audit_token, request_id, payload)
        risks.checks._put(db, risks.ref, check)
    if receipt.get('status') != 'RECEIVED':
        return dict(receipt={k:receipt[k] for k in ('request_id','status','applied_paths')},
                    received=True, repeated=True, scanner_run=False)
    # The inbox is committed before validation or publication. Failed publication
    # therefore leaves a recoverable result rather than losing the child's work.
    ledger = risks.load()
    check = risks.current_check()
    batch = _batch(check, batch_id, audit_token, agent_ref)
    current = next(r for r in check['audit_stream']['rounds'] if r['round_id'] == batch['round_id'])
    dependencies, valid_reviews_list, valid_values = {}, [], []
    issued = set(batch.get('issued_evidence', []))
    for review in reviews:
        refs = review['evidence_refs']
        require(set(refs) <= issued, 'AUDIT_EVIDENCE_NOT_ISSUED')
        try:
            require(current['required'].get(review['file_path']) == batch['versions'][review['file_path']],
                    'BUSINESS_AUDIT_INPUT_CHANGED')
            evidence = risks.evidence(ledger, refs)
            require(any(e['file_path'] == review['file_path'] for e in evidence), 'DEVELOPMENT_RISK_LOCATION_UNREAD')
            dependencies[review['file_path']] = [e['file_path'] for e in evidence]
            valid_reviews_list.append(review)
        except (ValueError, OSError):
            pass  # Retained in inbox; not accepted as current coverage.
    valid = {v['file_path'] for v in valid_reviews_list}
    for value in values:
        require(set(value['evidence_refs']) <= issued, 'AUDIT_EVIDENCE_NOT_ISSUED')
        try:
            require(value['file_path'] in valid, 'AUDIT_FINDING_WITHOUT_COVERAGE')
            risks.evidence(ledger, value['evidence_refs'])
            valid_values.append(value)
        except (ValueError, OSError):
            # A failed finding must keep its file pending, never publish a clean review.
            valid.discard(value['file_path'])
    valid_reviews_list = [v for v in valid_reviews_list if v['file_path'] in valid]
    valid_values = [v for v in valid_values if v['file_path'] in valid]
    commit = dict(batch_id=batch_id, request_id=request_id, token=audit_token, agent_ref=agent_ref,
                  valid_paths=sorted(valid), dependencies=dependencies,
                  evidence_refs=sorted({r for v in [*valid_reviews_list, *valid_values] for r in v['evidence_refs']}))
    try:
        if valid:
            result = risks._submit(valid_values, check['dirty_seq'], business_reviews=valid_reviews_list,
                return_risks=False, scan_id=None, audit_id=None, stream_commit=commit)
        else:
            with risks.checks.transaction() as db:
                check = risks.checks._get(db, risks.ref)
                _batch(check, batch_id, audit_token, agent_ref)
                state.complete(check, batch_id, request_id, [])
                risks.checks._put(db, risks.ref, check)
            result = {}
    except (ValueError, OSError):
        return dict(received=True, applied=False, error='AUDIT_PUBLICATION_PENDING',
                    recovery='recover', request_id=request_id, scanner_run=False)
    next_batch = process(risks, 'claim', audit_token=audit_token, agent_ref=agent_ref)
    return dict(received=True, applied=bool(valid), review_saved=bool(valid),
                applied_paths=sorted(valid), pending_paths=sorted(set(batch['versions'])-valid),
                next_batch=next_batch, scanner_run=False)


def validate_commit(check, commit):
    batch = _batch(check, commit['batch_id'], commit['token'], commit['agent_ref'])
    require(set(commit['evidence_refs']) <= set(batch.get('issued_evidence', [])), 'AUDIT_EVIDENCE_NOT_ISSUED')
    stream = check['audit_stream']
    current = next(r for r in stream['rounds'] if r['round_id'] == batch['round_id'])
    require(all(current['required'].get(p) == batch['versions'][p] and p not in current.get('superseded', {})
                for p in commit['valid_paths']),
            'BUSINESS_AUDIT_INPUT_CHANGED')


def valid_reviews(check):
    stream = check.get('audit_stream') or {}
    if not state.enabled(check):
        return {}
    latest, accepted = stream.get('latest_versions', {}), stream.get('accepted_current', {})
    result = {}
    for name, record in accepted.items():
        if record['seq'] != latest.get(name):
            continue
        receipt = stream['receipts'][record['request_id']]
        if name not in receipt.get('applied_paths', []):
            continue
        for review in receipt['payload'].get('business_reviews', []):
            if review['file_path'] == name:
                result[name] = review
    return result


def assessment_current(check, assessment, file_path=None):
    batch_id = assessment.get('stream_batch_id')
    if not batch_id:
        return False
    batch = (check.get('audit_stream') or {}).get('batches', {}).get(batch_id)
    if not batch or batch.get('status') != 'COMPLETE':
        return False
    name = file_path or assessment.get('finding', {}).get('file_path')
    if name not in valid_reviews(check):
        return False
    latest = check['audit_stream'].get('accepted_current', {})
    return latest.get(name, {}).get('request_id') == batch.get('request_id')


def _status(check, grant):
    progress = state.progress(check) if state.enabled(check) else dict(status='DISABLED',pending_paths=[])
    current = grant.get('round_id') == progress.get('round_id') and not grant.get('closed')
    bound = current and bool(grant.get('agent_ref')) and not grant.get('revoked')
    ready = current and bool(grant.get('token_hash')) and not grant.get('revoked')
    if current and grant.get('failure') and progress['pending_paths']:
        progress.update(status='FAILED', reason_code=grant['failure'])
    return dict(progress, scanner_run=False, executor_bound=bound,
        executor_stage=('FAILED' if current and grant.get('failure') else 'CLAIMED' if bound and grant.get('claimed_at') else
                        'DISPATCHED' if bound else 'NOT_DISPATCHED'),
        agent_ref=grant.get('agent_ref') if bound else None, delegation_ready=ready,
        delegation_revoked=bool(grant.get('revoked')),
        pending_received_count=sum(r['status']=='RECEIVED' for r in (check.get('audit_stream') or {}).get('receipts',{}).values()),
        host_next_action='FOLLOWUP_EXISTING_EXECUTOR' if bound else 'SPAWN_THEN_REGISTER_STARTED' if ready else 'stream_prepare')


def revalidate(risks, check, row):
    """Validate only accepted evidence at existing scan publication, never poll."""
    from .local_evidence import WorkspaceReader
    hashes = {}
    invalid = set()
    for name, review in valid_reviews(check).items():
        for ref in review['evidence_refs']:
            evidence = row.get('evidence', {}).get(ref)
            if not evidence:
                invalid.add(name)
                break
            path = evidence['file_path']
            if evidence.get('kind') == 'ABSENCE':
                try:
                    if not absent(risks.root, path): invalid.add(name)
                except (ValueError, OSError):
                    invalid.add(name)
                continue
            if path not in hashes:
                try:
                    raw, _ = WorkspaceReader(risks.root).read(path)
                    hashes[path] = hashlib.sha256(raw).hexdigest()
                except (ValueError, OSError):
                    hashes[path] = None
            if hashes[path] != evidence['sha256']:
                invalid.add(name)
                break
    for name in invalid:
        check['audit_stream'].get('accepted_current', {}).pop(name, None)
    for current in (check.get('audit_stream') or {}).get('rounds', []):
        for name in invalid & set(current['accepted']):
            current['accepted'].pop(name)
            current['pending'][name] = current['required'][name]
    return sorted(invalid)


def absent(root, name):
    from .hook_state import no_links
    path = root / relative_path(name)
    no_links(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def absence_evidence(risks, name):
    from .development_risks import digest
    name = relative_path(name)
    require(absent(risks.root, name), 'AUDIT_PATH_PRESENT')
    check = risks.current_check()
    evidence = dict(file_path=name, line_start=1, line_end=1, sha256='ABSENT',
                    dirty_seq=check['dirty_seq'], kind='ABSENCE')
    ref = 'dre1-' + digest([risks.ref, evidence])[:32]
    with risks.store.transaction() as db:
        row = risks.load(db)
        require(ref in row['evidence'] or len(row['evidence']) < 256, 'DEVELOPMENT_RISK_EVIDENCE_LIMIT')
        row['evidence'][ref] = evidence
        risks.store._put(db, risks.ref, row)
    return dict(evidence_ref=ref, **evidence, content='此路径当前不存在；须结合已授权关联证据判断删除或重命名影响，不能由不存在推断无漏洞。', scanner_run=False)


def _scrub(value):
    if isinstance(value, str):
        return safe(value)
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, dict):
        return {k:_scrub(v) for k,v in value.items()}
    return value
