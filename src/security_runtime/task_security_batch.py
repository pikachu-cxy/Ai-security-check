"""Opt-in immutable, bounded review batches; Runtime never starts a model.

The developing task remains ACTIVE. A host may dispatch one read-only worker
and continue editing; historical results are retained without claiming that
their source version is the final version. Existing closeout stays available.
"""
from __future__ import annotations

import difflib
import json
from pathlib import Path
import uuid

from .local_evidence import _relative, EvidenceUnavailable, MAX_LINE_CHARS
from .task_security import (capture, task_changes, digest_value, method as task_method, _clean,
    finding_view, _environment, _supported, MAX_CHANGED, MAX_RELATED, MAX_CONTEXT,
    MAX_CONTEXT_READS, MAX_CONTEXT_WINDOW_LINES, REVIEW_TTL, TaskContextError)

CONTRACT = 'task-security-batches-v1'
REVIEW_SCHEMA_VERSION = 'batch-review-candidates-v1'
MAX_BATCHES = 8
MAX_SNAPSHOT_BYTES = 1_000_000
MAX_SNAPSHOT_TEXT_BYTES = 128_000
MAX_BATCH_CONTEXT_BYTES = MAX_CONTEXT - 16_000
MAX_BATCH_CONTEXT_READS = MAX_CONTEXT_READS - 10


def method():
    """Compact worker method bound to the complete parent review policy.

    A batch does not need another copy of task-closeout orchestration. The
    final reviewer still receives that full method; its hash remains part of
    this method's identity so a policy change invalidates historical batches.
    """
    from .batch_reviewer import REVIEWER_INSTRUCTIONS
    content = REVIEWER_INSTRUCTIONS + '''
Review this coherent behavior change from base to frozen snapshot. Read issued
source evidence for every scoped file, including a zero-finding review. Inspect
relevant unchanged callers, authorization, ownership checks and configuration;
trace input, controls and sensitive operations across files. Diffs navigate the
change and never replace issued evidence. Examine the strongest counterevidence
and current protections before keeping a candidate. For each remaining risk,
state trigger conditions, concrete impact, protections, uncertainties and a
bounded fix. Distinguish TASK_CHANGED from conditional RELATED_EXISTING risk.
Do not treat historical static rows as proof about this snapshot. Report only
code-supported candidates, never runtime exploitability or a safety guarantee.
Use PARTIAL for missing/truncated snapshot text, unread requested ranges or
exhausted shared budget. Later source edits cannot change this snapshot; the
parent revalidates dependencies, all final changes and cross-batch interactions.
A zero-finding batch does not close an earlier risk or complete final review.
'''
    parent = task_method()
    policy = dict(content=content, schema_version=REVIEW_SCHEMA_VERSION,
                  parent_method_sha256=parent['sha256'])
    return dict(version='batch-review-method-v1', sha256=digest_value(policy), **policy)


def source_manifest(snapshot):
    """Only source facts determine the version, never state-store generation."""
    return {key: snapshot.get(key) for key in
            ('hashes', 'inventory', 'inventory_complete', 'limitations')}


def snapshot_id(snapshot):
    return 'bs1-' + digest_value(source_manifest(snapshot))[:32]


def budget_usage(record):
    state = record.get('batch_state') or {}
    budget = state.get('budget') or {}
    return dict(context_bytes=budget.get('context_bytes', 0),
                context_reads=budget.get('context_reads', 0),
                changed_files=list(budget.get('changed_files', [])),
                related_files=list(budget.get('related_files', [])))


def _bytes(value):
    return len(json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode())


def _public_history(value, sessions):
    """History navigation never exports launch/session credentials, even echoes."""
    if isinstance(value, dict):
        return {key: _public_history(item, sessions) for key, item in value.items()}
    if isinstance(value, list):
        return [_public_history(item, sessions) for item in value]
    if isinstance(value, str):
        for session in sessions:
            value = value.replace(session, '[REDACTED_REVIEW_SESSION]')
    return value


def _new_state():
    return dict(contract=CONTRACT, batches=[], pending=None,
                budget=dict(context_bytes=0, context_reads=0,
                            changed_files=[], related_files=[]))


def _state(record, *, create=False):
    state = record.get('batch_state')
    if state is None:
        if not create:
            return _new_state()
        state = record['batch_state'] = _new_state()
    if state.get('contract') != CONTRACT:
        raise ValueError('Unsupported batch state contract')
    return state


def _snapshot(snapshot, priority):
    """Keep only sanitized capture lines. Missing text is never live-read."""
    result = {key: snapshot[key] for key in
              ('hashes', 'inventory', 'inventory_complete', 'limitations')}
    result.update(texts={}, text_truncations=snapshot.get('text_truncations', {}))
    candidates = sorted(snapshot.get('texts', {}), key=lambda name: (
        name not in priority,
        not any(word in name.lower() for word in ('auth', 'permission', 'route', 'middleware')),
        name))
    used = 0
    for name in candidates:
        lines = snapshot['texts'][name]
        cost = _bytes(lines)
        if used + cost <= MAX_SNAPSHOT_TEXT_BYTES:
            result['texts'][name] = lines
            used += cost
    return result


def _before(snapshot, changes):
    names = {change['path'] for change in changes}
    return {key: {name: value for name, value in snapshot.get(key, {}).items() if name in names}
            for key in ('hashes', 'texts', 'text_truncations')}


def _snapshot_cost(state, extra=None):
    items = [*state['batches']]
    if state.get('pending'):
        items.append(state['pending'])
    if extra:
        items.append(extra)
    return sum(_bytes(item['snapshot']) + _bytes(item['before']) for item in items)


def _fingerprint(snapshot, path):
    if path in snapshot['hashes']:
        return snapshot['hashes'][path]
    if snapshot.get('inventory_complete') and path not in snapshot['inventory']:
        return 'ABSENT'
    return None


def _validity(batch, current):
    if batch.get('review') is None:
        return 'UNREVIEWED', []
    if (batch.get('method_sha256') != method()['sha256']
            or batch.get('review_schema_version') != REVIEW_SCHEMA_VERSION):
        return 'STALE', sorted(batch['scope_files'])
    dependencies = set(batch['scope_files']) | {e['path'] for e in batch['evidence'].values()}
    stale = [name for name in sorted(dependencies)
             if (_fingerprint(batch['snapshot'], name) is None
                 or _fingerprint(batch['snapshot'], name) != _fingerprint(current, name))]
    if stale:
        return 'STALE', stale
    if snapshot_id(batch['snapshot']) != snapshot_id(current):
        return 'INTEGRATION_RECHECK', []
    return 'CURRENT_REUSABLE', []


class TaskSecurityBatchService:
    def __init__(self, task_service, *, scan_reader=None):
        if scan_reader is not None and not callable(scan_reader):
            raise ValueError('Batch scan reader must be a trusted read-only callback')
        self.tasks = task_service
        self.hooks = task_service.hooks
        self.now = task_service.now
        self.scan_reader = scan_reader

    def _save(self, root, record):
        return self.tasks.store(root).save(record)

    def _expire(self, state):
        for batch in state['batches']:
            if batch['status'] == 'RUNNING' and self.now() > batch['review_deadline']:
                batch['status'] = 'EXPIRED'

    @staticmethod
    def _running(state):
        return next((b for b in state['batches'] if b['status'] == 'RUNNING'), None)

    def _current(self, root, record):
        return capture(root, known_paths=record['baseline'].get('inventory',
                       record['baseline']['hashes']), include_text=False)

    def _budget(self, record):
        return dict(**budget_usage(record), max_context_bytes=MAX_BATCH_CONTEXT_BYTES,
            max_context_reads=MAX_BATCH_CONTEXT_READS, max_changed_files=MAX_CHANGED,
            max_related_files=MAX_RELATED, final_reserved_bytes=16_000,
            final_reserved_reads=10, max_snapshot_bytes=MAX_SNAPSHOT_BYTES)

    def _view(self, record, batch, current=None):
        validity, stale = _validity(batch, current) if current else ('UNREVIEWED', [])
        status = 'EXPIRED' if batch['status']=='RUNNING' and self.now()>batch['review_deadline'] else batch['status']
        return dict(batch_ref=batch['batch_ref'], status=status,
            snapshot_id=batch['snapshot_id'], base_snapshot_id=batch['base_snapshot_id'],
            method_sha256=batch.get('method_sha256'), method_version=batch.get('method_version'),
            review_schema_version=batch.get('review_schema_version'),
            scope_files=batch['scope_files'], changes=batch['changes'],
            validity=validity, stale_paths=stale,
            coverage=(batch.get('review') or {}).get('coverage'),
            review_scope=(batch.get('review') or {}).get('review_scope', []),
            findings=(batch.get('review') or {}).get('findings', []),
            limitations=[*batch['limitations'], *(batch.get('review') or {}).get('limitations', [])],
            scanner_run=False, repair_authorized=False)

    def prepare(self, workspace, ref, checkpoint_key):
        if (not isinstance(checkpoint_key, str) or not 1 <= len(checkpoint_key) <= 100
                or any(ord(c) < 32 for c in checkpoint_key)):
            raise ValueError('Use a short checkpoint identifier, not source or a prompt')
        root = self.tasks.root(workspace)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return dict(status='BUSY', task_ref=ref, scanner_run=False)
            record = self.tasks.load(root, ref)
            if record['phase'] != 'ACTIVE':
                return dict(status='BATCH_TASK_NOT_ACTIVE', task_ref=ref,
                            scanner_run=False, dispatch_required=False)
            state = _state(record, create=True)
            self._expire(state)
            key = digest_value(checkpoint_key)
            existing = next((b for b in state['batches'] if key in b['checkpoint_keys']), None)
            if existing:
                if existing['status'] == 'RUNNING':
                    return dict(existing['packet'], review_session=existing['review_session'])
                result = self._view(record, existing, self._current(root, record))
                result.update(batch_status=result['status'],
                    status='BATCH_ALREADY_REVIEWED' if existing.get('review') else 'BATCH_EXPIRED',
                    task_ref=ref, dispatch_required=False)
                return result
            if len(state['batches']) >= MAX_BATCHES:
                return dict(status='BATCH_BUDGET_EXCEEDED', task_ref=ref,
                            reason='BATCH_COUNT_BUDGET', dispatch_required=False, scanner_run=False)
            pending = state.get('pending')
            if pending and key in pending['checkpoint_keys'] and not self._running(state):
                state['pending'] = None
                return self._dispatch(root, record, pending)
            base = state['batches'][-1]['snapshot'] if state['batches'] else record['baseline']
            current = capture(root, known_paths=base.get('inventory', base['hashes']))
            verified = capture(root, known_paths=base.get('inventory', base['hashes']), include_text=False)
            if source_manifest(current) != source_manifest(verified):
                return dict(status='SNAPSHOT_UNSTABLE', task_ref=ref,
                    reason='SOURCE_CHANGED_DURING_BATCH_CAPTURE', dispatch_required=False,
                    scanner_run=False, repair_authorized=False)
            changes, unknown = task_changes(root, base, current)
            if not changes:
                return dict(status='NO_BATCH_CHANGES', task_ref=ref, unverified_paths=unknown,
                            dispatch_required=False, scanner_run=False)
            eligible = [c['path'] for c in changes if not _environment(c['path'])]
            budget = state['budget']
            available = MAX_CHANGED - len(budget['changed_files'])
            old_names = set(budget['changed_files'])
            selected = [name for name in eligible if name in old_names]
            selected.extend([name for name in eligible if name not in old_names][:available])
            limitations = [*base.get('limitations', []), *current['limitations']]
            if unknown:
                limitations.append(dict(reason='BATCH_CHANGE_COMPARISON_UNAVAILABLE', paths=unknown))
            excluded = [name for name in eligible if name not in selected]
            if excluded:
                limitations.append(dict(reason='BATCH_CHANGED_FILE_BUDGET', paths=excluded))
            if any(_environment(c['path']) for c in changes):
                limitations.append(dict(reason='BATCH_ENVIRONMENT_CONTEXT_EXCLUDED'))
            guide = method()
            item = dict(batch_ref='tb1-'+uuid.uuid4().hex,
                checkpoint_keys=[key], snapshot=_snapshot(current, selected),
                before=_before(base, changes), base_snapshot_id=snapshot_id(base),
                snapshot_id=snapshot_id(current), changes=changes, scope_files=sorted(selected),
                limitations=limitations, created_at=self.now(), evidence={},
                context_requests={}, context_gaps=[], review=None,
                review_method=guide, method_sha256=guide['sha256'], method_version=guide['version'],
                review_schema_version=REVIEW_SCHEMA_VERSION,
                mutation_seq=record.get('ai_mutation_seq', 0))
            # Old cached lines are never evicted out from under an active worker.
            # Drop only this new snapshot's optional cache if aggregate storage is full.
            previous_pending = state.get('pending')
            state['pending'] = None
            while _snapshot_cost(state, item) > MAX_SNAPSHOT_BYTES and item['snapshot']['texts']:
                item['snapshot']['texts'].pop(next(reversed(item['snapshot']['texts'])))
            if _snapshot_cost(state, item) > MAX_SNAPSHOT_BYTES:
                state['pending'] = previous_pending
                return dict(status='BATCH_BUDGET_EXCEEDED', task_ref=ref,
                    reason='BATCH_SNAPSHOT_STORAGE_BUDGET', dispatch_required=False, scanner_run=False)
            if self._running(state):
                if previous_pending:
                    item['checkpoint_keys'] = [*previous_pending['checkpoint_keys'], key][-MAX_BATCHES*8:]
                state['pending'] = item
                self._save(root, record)
                return dict(status='BATCH_QUEUED', task_ref=ref, batch_ref=item['batch_ref'],
                    snapshot_id=item['snapshot_id'], running_batch_ref=self._running(state)['batch_ref'],
                    pending_batch_ref=item['batch_ref'], dispatch_required=False,
                    scanner_run=False, budget=self._budget(record))
            return self._dispatch(root, record, item)

    def _static_history(self, root, record, batch):
        """Read bounded stored scanner clues; never attest this snapshot or scan."""
        static = dict(source='SYNCHRONOUS_HOOK_HISTORY_NOT_CURRENT_PROOF',
            hook_checks=record.get('hook_checks', [])[-8:],
            pending_scope_files=record.get('hook_pending_scope_files', []),
            scanner_run=False, new_scanner_invocation=False,
            exact_version_verified=False, findings=[], scanner_runs=[], history_read_results=[],
            coverage_gap='Hook history has no per-file snapshot proof; retain the final synchronous static check.')
        if self.scan_reader is None:
            static['history_read_status'] = 'UNKNOWN_SCAN_STORE_READER_UNAVAILABLE'
            return static
        refs = []
        for row in reversed(static['hook_checks']):
            scan_id = row.get('scan_id')
            if isinstance(scan_id,str) and 1<=len(scan_id)<=100 and scan_id not in refs:
                refs.append(scan_id)
                if len(refs)>=3:
                    break
        static['history_read_status'] = 'UNKNOWN_NO_HOOK_SCAN_REFERENCES' if not refs else 'READ_ONLY_HISTORY'
        seen = set()
        for scan_id in refs:
            try:
                scan = self.scan_reader(scan_id)
                if not isinstance(scan,dict):
                    raise ValueError('Stored scan unavailable')
                if Path(scan['target_profile']['path']).resolve() != root.resolve():
                    static['history_read_results'].append(dict(scan_id=scan_id,status='REJECTED_WORKSPACE'))
                    continue
                static['history_read_results'].append(dict(scan_id=scan_id,status='READ'))
                for finding in scan.get('findings', []):
                    if len(static['findings'])>=10:
                        break
                    if not isinstance(finding,dict):
                        continue
                    try:
                        name = _relative(finding['file_path'])
                    except (KeyError,ValueError,EvidenceUnavailable):
                        continue
                    key = finding.get('id')
                    if name not in batch['scope_files'] or not isinstance(key,str) or key in seen:
                        continue
                    seen.add(key)
                    static['findings'].append(dict(finding_view(dict(finding,file_path=name)),
                        origin_scan_id=scan_id,source='HISTORICAL_STATIC_FINDING'))
                for run in scan.get('scanner_runs', [])[:4]:
                    if isinstance(run,dict):
                        static['scanner_runs'].append(dict(scan_id=scan_id, **{
                            key: str(run.get(key,''))[:100] for key in ('scanner','version','status')}))
            except Exception:
                static['history_read_results'].append(dict(scan_id=scan_id,status='UNKNOWN_UNREADABLE'))
        if refs and not any(item['status']=='READ' for item in static['history_read_results']):
            static['history_read_status']='UNKNOWN_NO_ADMITTED_SCAN_RECORDS'
        return static

    def _dispatch(self, root, record, batch):
        state = _state(record)
        review_session = 'br1-'+uuid.uuid4().hex
        from .batch_reviewer import reviewer_handoff
        diffs = []
        for change in batch['changes']:
            name = change['path']
            if name not in batch['scope_files']:
                continue
            old = [] if change['change'] == 'ADDED' else batch['before']['texts'].get(name)
            new = [] if change['change'] == 'DELETED' else batch['snapshot']['texts'].get(name)
            if old is None or new is None:
                diffs.append(dict(path=name, change=change['change'], availability='SNAPSHOT_TEXT_UNAVAILABLE'))
                batch['limitations'].append(dict(reason='BATCH_PREIMAGE_OR_TEXT_UNAVAILABLE', path=name))
                continue
            lines = list(difflib.unified_diff(old, new, fromfile='before/'+name,
                         tofile='snapshot/'+name, lineterm=''))
            if sum(len(d.get('diff', '')) for d in diffs) + len('\n'.join(lines)) > 12_000:
                diffs.append(dict(path=name, change=change['change'], availability='ON_DEMAND'))
            else:
                diffs.append(dict(path=name, change=change['change'], diff='\n'.join(lines)))
        static = self._static_history(root,record,batch)
        if set(batch['scope_files']) & set(static['pending_scope_files']):
            batch['limitations'].append(dict(reason='BATCH_STATIC_SCOPE_PENDING'))
        packet = dict(status='REVIEW_REQUIRED', task_ref=record['task_ref'],
            batch_ref=batch['batch_ref'], review_required=True, dispatch_required=True,
            snapshot_id=batch['snapshot_id'], base_snapshot_id=batch['base_snapshot_id'],
            changes=batch['changes'], review_scope=batch['scope_files'], diffs=diffs,
            static=static, quick_skill=batch['review_method'], limitations=batch['limitations'],
            related_candidates=[name for name in batch['snapshot']['texts']
                                if name not in batch['scope_files']][:30],
            trust='UNTRUSTED_CODE_AND_SCANNER_DATA', scanner_run=False, repair_authorized=False,
            review_handoff=reviewer_handoff(root, record['task_ref'], batch['batch_ref'],
                review_session, hooks_directory=self.hooks.directory),
            submission_contract=dict(findings='Existing task candidate schema; issued batch evidence only.',
                coverage='REVIEWED or PARTIAL', review_scope='Every batch scope path requires issued source evidence, including zero-finding reviews.',
                historical_results='Accepted as history; current coverage is revalidated separately.'),
            budget=self._budget(record))
        cost = _bytes(packet)
        budget = state['budget']
        if budget['context_bytes'] + cost > MAX_BATCH_CONTEXT_BYTES:
            packet['diffs'] = []
            packet['related_candidates'] = packet['related_candidates'][:10]
            cost = _bytes(packet)
        if budget['context_bytes'] + cost > MAX_BATCH_CONTEXT_BYTES:
            state['pending'] = batch
            self._save(root, record)
            return dict(status='BATCH_BUDGET_EXCEEDED', task_ref=record['task_ref'],
                reason='BATCH_CONTEXT_BYTE_BUDGET', dispatch_required=False, scanner_run=False)
        batch.update(status='RUNNING', review_session=review_session,
                     review_deadline=self.now()+REVIEW_TTL, packet=packet)
        budget['context_bytes'] += cost
        budget['changed_files'] = sorted(set(budget['changed_files']) | set(batch['scope_files']))
        state['batches'].append(batch)
        self._save(root, record)
        return dict(packet, review_session=batch['review_session'])

    def _session(self, record, batch_ref, session, *, allow_complete=False):
        state = _state(record)
        if record['phase'] in {'COMPLETE','NO_CHANGES','INCOMPLETE'}:
            raise ValueError('Development task is terminal; batch reads and submissions are closed')
        if state.get('finalizing'):
            raise ValueError('Batch inputs are closed for final version review; no late reads or submissions')
        batch = next((b for b in state['batches'] if b['batch_ref'] == batch_ref), None)
        if (not batch or batch.get('review_session') != session
                or (batch['status'] != 'RUNNING' and not (allow_complete and batch['status'] == 'COMPLETE'))
                or (batch['status']!='COMPLETE' and self.now() > batch['review_deadline'])):
            raise ValueError('Batch review session unavailable or expired; no automatic restart')
        return batch

    def _gap(self, root, record, batch, reason, path):
        gap = dict(reason=reason, path=path)
        if gap not in batch['context_gaps'] and len(batch['context_gaps']) < MAX_CONTEXT_READS:
            batch['context_gaps'].append(gap)
        self._save(root, record)
        raise TaskContextError(reason, 'Immutable batch context unavailable', recoverable=False,
            guidance='Keep the same task and batch. Submit PARTIAL with the missing range; never substitute current workspace code or restart budgets.')

    def read(self, workspace, ref, batch_ref, review_session, path,
             start_line=1, end_line=80, source_version='SNAPSHOT'):
        root = self.tasks.root(workspace)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return dict(status='BUSY', scanner_run=False)
            record = self.tasks.load(root, ref)
            batch = self._session(record, batch_ref, review_session)
            try:
                name = _relative(path)
            except (ValueError, EvidenceUnavailable):
                raise ValueError('Batch source path rejected') from None
            if (not _supported(name) or _environment(name)
                    or name not in set(batch['snapshot']['inventory']) | set(batch['before']['hashes'])):
                raise ValueError('Batch context path excluded')
            if source_version not in {'SNAPSHOT', 'BEFORE_BATCH'}:
                raise ValueError('Invalid batch source version')
            if (type(start_line) is not int or type(end_line) is not int
                    or not 1 <= start_line <= end_line <= 2_147_483_647):
                raise ValueError('Invalid batch source range')
            before = source_version == 'BEFORE_BATCH' or any(
                c['path'] == name and c['change'] == 'DELETED' for c in batch['changes'])
            source = batch['before'] if before else batch['snapshot']
            lines = source['texts'].get(name)
            if lines is None or name not in source['hashes']:
                self._gap(root, record, batch, 'BATCH_SNAPSHOT_TEXT_UNAVAILABLE', name)
            if start_line > len(lines):
                raise ValueError('Batch source range unavailable')
            budget = _state(record)['budget']
            related = name not in batch['scope_files']
            if related and name not in budget['related_files'] and len(budget['related_files']) >= MAX_RELATED:
                self._gap(root, record, batch, 'BATCH_RELATED_FILE_BUDGET', name)
            requested_high = min(end_line, len(lines))
            high = min(requested_high, start_line+MAX_CONTEXT_WINDOW_LINES-1)
            version = 'BEFORE_DELETION' if before and source_version == 'SNAPSHOT' else 'BEFORE_BATCH' if before else 'BATCH_SNAPSHOT'
            file_hash = source['hashes'][name]
            eid = 'be1-'+digest_value([ref, batch_ref, review_session, batch['snapshot_id'],
                                      name, file_hash, start_line, high, version])[:32]
            truncation = source.get('text_truncations', {}).get(name)
            packet = dict(evidence_id=eid, task_ref=ref, batch_ref=batch_ref,
                snapshot_id=batch['snapshot_id'], path=name, file_sha256=file_hash,
                location_version=version, start_line=start_line, end_line=high,
                total_lines=len(lines), has_more=high<requested_high,
                requested_range=dict(start_line=start_line, end_line=end_line),
                returned_range=dict(start_line=start_line, end_line=high),
                next_read=(dict(task_ref=ref, batch_ref=batch_ref, review_session=review_session,
                    file_path=name, start_line=high+1, end_line=requested_high, source_version=source_version,
                    workspace_path=str(root)) if high<requested_high else None),
                numbered_lines=[f'{i}: {lines[i-1]}' for i in range(start_line, high+1)],
                line_truncation=dict(max_line_chars=MAX_LINE_CHARS,
                    complete_line_text=not truncation,
                    known_truncated_lines=[i for i in (truncation or {}).get('lines', []) if start_line<=i<=high]),
                trust='UNTRUSTED_SNAPSHOT_CODE', scanner_run=False, repair_authorized=False)
            if eid not in batch['evidence']:
                if budget['context_reads'] >= MAX_BATCH_CONTEXT_READS:
                    self._gap(root, record, batch, 'BATCH_CONTEXT_READ_BUDGET', name)
                cost = _bytes(packet)
                if budget['context_bytes'] + cost > MAX_BATCH_CONTEXT_BYTES:
                    self._gap(root, record, batch, 'BATCH_CONTEXT_BYTE_BUDGET', name)
                batch['evidence'][eid] = {key: packet[key] for key in
                    ('path', 'file_sha256', 'location_version', 'start_line', 'end_line', 'snapshot_id')}
                budget['context_bytes'] += cost
                budget['context_reads'] += 1
                if related:
                    budget['related_files'] = sorted(set(budget['related_files']) | {name})
            request_key = digest_value([name, file_hash, version])
            request = batch['context_requests'].setdefault(request_key,
                dict(path=name, file_sha256=file_hash, location_version=version, spans=[]))
            from .task_security import _merge_spans
            request['spans'] = _merge_spans([*request['spans'], [start_line, requested_high]])
            if truncation:
                gap = dict(reason='SOURCE_LINE_CHAR_BUDGET', path=name)
                if gap not in batch['context_gaps']:
                    batch['context_gaps'].append(gap)
            self._save(root, record)
            return packet

    def _findings(self, ref, batch, findings):
        if not isinstance(findings, list) or len(findings) > 10:
            raise ValueError('Invalid bounded batch candidates')
        required = {'title','category','severity','primary_evidence','evidence_refs','impact',
                    'preconditions','unknowns','counterevidence','fix_advice'}
        optional = {'risk_scope','task_evidence','current_protections'}
        accepted = []
        for candidate in findings:
            if not isinstance(candidate, dict) or not required <= set(candidate) or set(candidate)-required-optional:
                raise ValueError('Use batch candidate schema; scanner proof and authority fields are forbidden')
            refs, primary = candidate['evidence_refs'], candidate['primary_evidence']
            if (not isinstance(refs, list) or not 1 <= len(refs) <= 10
                    or any(not isinstance(e, str) or e not in batch['evidence'] for e in refs)
                    or not isinstance(primary, str) or primary not in refs):
                raise ValueError('Every candidate needs Runtime-issued batch evidence')
            location = batch['evidence'][primary]
            scope = candidate.get('risk_scope', 'TASK_CHANGED')
            task_evidence = candidate.get('task_evidence', primary)
            if (scope not in {'TASK_CHANGED','RELATED_EXISTING'}
                    or not isinstance(task_evidence, str) or task_evidence not in refs
                    or batch['evidence'][task_evidence]['path'] not in batch['scope_files']):
                raise ValueError('Every candidate needs batch-changed evidence')
            if location['location_version'] == 'BEFORE_BATCH':
                raise ValueError('Historical preimage cannot locate a current candidate')
            if scope == 'TASK_CHANGED' and location['path'] not in batch['scope_files']:
                raise ValueError('Primary evidence must locate a batch-changed file')
            if scope == 'RELATED_EXISTING' and (location['path'] in batch['scope_files']
                    or location['location_version'] != 'BATCH_SNAPSHOT'
                    or not candidate['preconditions'] or not candidate['unknowns']
                    or 'current_protections' not in candidate):
                raise ValueError('Related risk requires current related evidence, conditions and protections')
            if candidate['severity'] not in {'LOW','MEDIUM','HIGH','CRITICAL'}:
                raise ValueError('Invalid batch candidate severity')
            item = {key: _clean(candidate[key],1200) for key in ('title','category','impact','fix_advice')}
            for field in ('preconditions','unknowns','counterevidence','current_protections'):
                values = candidate.get(field, candidate['counterevidence'])
                if not isinstance(values,list) or len(values)>10:
                    raise ValueError('Invalid candidate conditions or protections')
                item[field] = [_clean(v,500) for v in values]
            item.update(id='bc1-'+digest_value([ref,batch['batch_ref'],candidate])[:32],
                severity=candidate['severity'], risk_scope=scope, task_evidence=task_evidence,
                evidence_refs=list(dict.fromkeys(refs)),
                evidence_locations=[dict(evidence_ref=e, **batch['evidence'][e]) for e in dict.fromkeys(refs)],
                file_path=location['path'], line_start=location['start_line'], line_end=location['end_line'],
                location_version=location['location_version'], batch_ref=batch['batch_ref'],
                snapshot_id=batch['snapshot_id'], source='HOST_BATCH_REVIEW',
                validation='STRUCTURE_AND_SNAPSHOT_VERSION_ONLY',
                verdict='CANDIDATE_REQUIRES_REVIEW', scanner_sources=[])
            accepted.append(item)
        return accepted

    def submit(self, workspace, ref, batch_ref, review_session, findings, coverage, limitations):
        root = self.tasks.root(workspace)
        with self.hooks.lock(root) as acquired:
            if not acquired:
                return dict(status='BUSY', scanner_run=False)
            record = self.tasks.load(root, ref)
            batch = self._session(record, batch_ref, review_session, allow_complete=True)
            current = self._current(root, record)
            if batch['status'] == 'COMPLETE':
                return dict(task_ref=ref, pending_ready=bool(_state(record).get('pending')),
                            **self._view(record,batch,current))
            if (coverage not in {'REVIEWED','PARTIAL'} or not isinstance(limitations,list)
                    or len(limitations)>30):
                raise ValueError('Invalid batch review coverage or limitations')
            clean = [_clean(value,500) for value in limitations]
            if coverage == 'PARTIAL' and not clean:
                raise ValueError('Partial review must identify a limitation')
            accepted = self._findings(ref,batch,findings)
            reviewed = {e['path'] for e in batch['evidence'].values()
                        if e['location_version'] in {'BATCH_SNAPSHOT','BEFORE_DELETION'}}
            missing = sorted(set(batch['scope_files'])-reviewed)
            from .task_security import _unread_context
            unread = _unread_context(batch)
            if missing:
                clean.append('批次范围尚未读取源码证据：'+'、'.join(missing[:20]))
            if unread:
                clean.append('已请求的批次源码范围尚未读完。')
            if len(batch['scope_files'])>1 and not reviewed-set(batch['scope_files']):
                clean.append('未读取未改动关联文件，跨文件控制仍需核查。')
            if missing or unread or batch['limitations'] or batch['context_gaps']:
                coverage = 'PARTIAL'
                if batch['limitations'] or batch['context_gaps']:
                    clean.append('批次快照、静态记录或上下文存在已记录的覆盖限制。')
            if len(batch['scope_files'])>1 and not reviewed-set(batch['scope_files']):
                coverage = 'PARTIAL'
            batch.update(status='COMPLETE',review=dict(coverage=coverage,findings=accepted,
                limitations=clean,review_scope=[dict(path=name,
                    evidence_refs=[eid for eid,e in batch['evidence'].items() if e['path']==name],
                    snapshot_file_sha256=_fingerprint(batch['snapshot'],name)) for name in batch['scope_files']],
                submitted_at=self.now(), model_invocation='HOST_ONLY_NOT_OBSERVED_BY_RUNTIME'))
            # The result acknowledges only its exact version. Newer changes stay dirty.
            dirty = record.get('ai_dirty_versions')
            if isinstance(dirty,dict) and coverage=='REVIEWED':
                for name in batch['scope_files']:
                    if dirty.get(name) == _fingerprint(batch['snapshot'],name):
                        dirty.pop(name,None)
            self._save(root,record)
            return dict(task_ref=ref,pending_ready=bool(_state(record).get('pending')),
                        **self._view(record,batch,current))

    def get(self, workspace, ref):
        root = self.tasks.root(workspace)
        record = self.tasks.load(root,ref)
        state = _state(record)
        current = self._current(root,record)
        running = self._running(state)
        result = dict(status='BATCH_STATUS',task_ref=ref,
            batches=[self._view(record,b,current) for b in state['batches']],
            running_batch_ref=running['batch_ref'] if running and self.now()<=running['review_deadline'] else None,
            pending_batch_ref=(state.get('pending') or {}).get('batch_ref'),
            budget=self._budget(record),scanner_run=False,repair_authorized=False)
        return _public_history(result, [batch['review_session'] for batch in state['batches']
                                       if batch.get('review_session')])

    def final_coverage(self, root, record, snapshot=None):
        """Candidates require final integration review; this never closes a task."""
        current = snapshot or record.get('end') or self._current(root,record)
        state = _state(record)
        changes, unknown = task_changes(root,record['baseline'],current)
        scope = sorted({c['path'] for c in changes} |
                       set(record.get('hook_final_recheck_files', [])))
        coverage, candidates = [], []
        stale_paths, unreviewed = set(), set(unknown)
        for name in scope:
            matching, stale, changed_paths = [], [], set()
            for batch in state['batches']:
                if name not in batch['scope_files']:
                    continue
                validity, changed_dependencies = _validity(batch,current)
                if validity=='STALE':
                    stale.append(batch['batch_ref'])
                    changed_paths.update(changed_dependencies)
                elif batch.get('review') and batch['review']['coverage']=='REVIEWED':
                    matching.append((batch,validity))
            if matching:
                batch,validity = matching[-1]
                coverage.append(dict(path=name,status=validity,
                    batch_refs=[batch['batch_ref']],snapshot_file_sha256=_fingerprint(current,name)))
                if batch['batch_ref'] not in {b['batch_ref'] for b in candidates}:
                    candidates.append(dict(batch_ref=batch['batch_ref'],validity=validity,
                        snapshot_id=batch['snapshot_id'],review_scope=batch['review']['review_scope'],
                        findings=batch['review']['findings'],evidence=batch['evidence'],
                        coverage=batch['review']['coverage'],limitations=batch['review']['limitations']))
            else:
                stale_paths.update(changed_paths)
                status='STALE' if stale else 'PARTIAL' if any(
                    name in b['scope_files'] and b.get('review') for b in state['batches']) else 'UNREVIEWED'
                coverage.append(dict(path=name,status=status,batch_refs=stale))
                unreviewed.add(name)
        return dict(contract=CONTRACT,enabled=bool(record.get('batch_state')),
            snapshot_id=snapshot_id(current),review_scope=scope,path_coverage=coverage,
            reusable_candidates=candidates,stale_paths=sorted(stale_paths),
            unreviewed_paths=sorted(unreviewed),integration_required=True,
            integration_reason='Final task diff and cross-batch interactions require host analysis; matching file hashes alone never complete review.',
            budget=self._budget(record),scanner_run=False,repair_authorized=False)
