"""Signed per-finding outcomes; never edit authority or production safety."""
from __future__ import annotations
import hmac
import json
from pathlib import Path
from .closeout_state import digest
from .hook_state import atomic_bytes, no_links
from .private_authority import PrivateAuthority, AuthorityRows, revision
from .ledger_partitions import LedgerPartitions, LedgerCapacity
from .local_evidence import WorkspaceReader, EvidenceUnavailable

MAX_ROWS = 1000
MAX_BYTES = 2_000_000


def disposition_store(hooks, root, *, now=None):
    """Keep user decisions outside source-review and repair ledgers."""
    from .risk_disposition import RiskDispositionStore
    options = {} if now is None else {'now': now}
    return RiskDispositionStore(hooks.workspace_directory(root) / 'risk-dispositions.db', **options)


def finding_disposition_scope(root, finding):
    """A task-independent issue identity; source text never enters the ledger."""
    from .risk_disposition import issue_scope
    try:
        return issue_scope(root, finding['file_path'], finding.get('line_start', 1),
            finding.get('line_end', finding.get('line_start', 1)),
            category=finding.get('category', ''), rule_id='HOST_CONTEXT_REVIEW')
    except (OSError, ValueError, EvidenceUnavailable, UnicodeError):
        return {}


def finding_disposition_locations(root, finding, paths):
    locations = {}
    for location in finding.get('evidence_locations', []):
        locations.setdefault(location['path'], location)
    result = []
    for path in sorted(paths):
        location = dict(path=path, start_line=locations.get(path, {}).get('start_line', 1),
                        end_line=locations.get(path, {}).get('end_line', 1))
        scope = finding_disposition_scope(root, dict(file_path=path,
            line_start=location['start_line'], line_end=location['end_line'],
            category=finding.get('category', '')))
        location['scope_metadata'] = scope.get('metadata') or {}
        result.append(location)
    return result


def disposition_revision(root, row, *, with_precision=False):
    """Changes request reassessment; they do not cancel a user's decision."""
    from .risk_disposition import issue_scope, refresh_scope
    revisions, precise = {}, True
    locations = row.get('disposition_locations') or [dict(path=path, start_line=1, end_line=1)
                                                   for path in row['required_source_paths']]
    for location in locations:
        path = location['path']
        try:
            try:
                scope = refresh_scope(root, location['scope_metadata'])
            except (KeyError, OSError, ValueError, EvidenceUnavailable, UnicodeError):
                scope = issue_scope(root, path, location['start_line'], location['end_line'],
                                    category=row.get('category', ''), rule_id='HOST_CONTEXT_REVIEW')
        except (OSError, ValueError, EvidenceUnavailable, UnicodeError):
            return (None, False) if with_precision else None
        revision = scope.get('evidence_revision')
        if revision is None:
            return (None, False) if with_precision else None
        revisions[path+':'+scope['metadata']['symbol']] = revision
        precise = precise and scope['metadata'].get('material_change_confirmable') is True
    revision = digest(b'task-risk-disposition-revision-v1', revisions)
    return (revision, precise) if with_precision else revision

def current_hashes(root, paths):
    import hashlib
    values = {}
    for path in sorted(set(paths)):
        try:
            raw, _ = WorkspaceReader(root).read(path)
            values[path] = hashlib.sha256(raw).hexdigest()
        except (OSError, ValueError, EvidenceUnavailable, UnicodeError):
            values[path] = None
    return values

class TaskRiskLedger:
    def __init__(self, hooks, root):
        self.hooks, self.root = hooks, Path(root)
        self.authority = PrivateAuthority(hooks, self.root, legacy_name='task-risk-ledger.json',
            name='task-risk-ledger-v2.state', contract='task-risk-authority-v2',
            initial=dict(rows={}, outbox={}, inbox={}), legacy=self._legacy)
        self.path = self.authority.path
        self.partitions = LedgerPartitions(self.authority)

    def _legacy(self, raw, key):
        data = json.loads(raw)
        if (not isinstance(data, dict) or data.get('contract') != 'task-risk-ledger-v1'
                or not isinstance(data.get('rows'), dict) or len(data['rows']) > MAX_ROWS
                or data.get('workspace') != str(self.root) or not isinstance(data.get('mac'), str)
                or not hmac.compare_digest(data['mac'], digest(key, data['rows']))):
            raise ValueError('Risk ledger cannot be verified')
        return dict(rows=data['rows'], outbox={}, inbox={})

    def _stored(self):
        value = self.authority.read()
        if (not isinstance(value, dict) or set(value) not in (
                {'rows', 'outbox', 'inbox'}, {'partitions', 'outbox', 'inbox'})
                or any(not isinstance(value[key], dict) for key in value)
                ):
            raise ValueError('Risk authority cannot be verified')
        return value

    def _state(self):
        value = self._stored()
        return dict(rows=self.partitions.read(value), outbox=value['outbox'], inbox=value['inbox'])

    def read(self, task_ref=None):
        value = self._stored()
        return AuthorityRows(self.partitions.read(value, task_ref), revision=revision(value), scope=task_ref)

    def read_origins(self, origins):
        value = self._stored()
        origins = tuple(sorted(set(origins)))
        return AuthorityRows(self.partitions.read_origins(value,origins), revision=revision(value),scope=origins)

    def read_scan(self, scan_id):
        value = self._stored()
        origins = tuple(self.partitions.origins_for_scan(value,scan_id))
        return AuthorityRows(self.partitions.read_origins(value,origins),revision=revision(value),scope=origins)

    def resume(self):
        """Mutation-only continuation of an already authenticated transition."""
        if not self.hooks.lock_held(self.root): raise ValueError('Risk ledger workspace lock required')
        if self.authority.journal.exists(): self.authority._ensure()

    def save(self, rows, *, effects=(), receipt=None):
        if not isinstance(rows, AuthorityRows) or rows.revision is None:
            raise ValueError('Risk ledger requires a current read snapshot')
        if not self.hooks.lock_held(self.root): raise ValueError('Risk ledger workspace lock required')
        if self.authority.journal.exists(): self.authority._ensure()
        value = self._stored()
        if revision(value) != rows.revision:
            raise ValueError('Risk ledger changed concurrently')
        for effect in effects:
            from .persistence_effects import validate_effect
            validate_effect(effect)
            old = value['outbox'].get(effect['event_id'])
            if old is not None and old != effect: raise ValueError('Risk effect identity conflict')
            value['outbox'][effect['event_id']] = effect
        if receipt is not None:
            event_id, fact = receipt
            old = value['inbox'].get(event_id)
            if old is not None and old != fact: raise ValueError('Risk target receipt conflict')
            if len(value['inbox']) >= 2000 and old is None:
                raise LedgerCapacity('RECEIPT', len(value['inbox'])+1, 2000)
            value['inbox'][event_id] = fact
        self.hooks.key(self.root)  # Writer-only; read paths never create keys.
        candidate = self.partitions.publish(value, dict(rows), rows.scope)
        from .closeout_state import encode
        size = len(encode(dict(content=dict(contract=self.authority.contract, workspace=str(self.root),
            value=candidate), mac='0'*64)))
        if size > MAX_BYTES: raise LedgerCapacity('BYTE',size,MAX_BYTES)
        self.authority.save(candidate, rows.revision)
        rows.revision = revision(candidate)
        self.partitions.collect(candidate)

    def pending_effects(self, limit=8):
        if type(limit) is not int or not 1 <= limit <= 32: raise ValueError('Invalid effect limit')
        return list(self._stored()['outbox'].values())[:limit]

    def acknowledge_effect(self, effect):
        value = self._stored()
        old = value['outbox'].get(effect['event_id'])
        if old is None: return
        if old != effect: raise ValueError('Risk effect acknowledgement conflict')
        before = revision(value)
        del value['outbox'][effect['event_id']]
        self.authority.save(value, before)

    def register(self, record):
        self.resume()
        previous = self.read(record['task_ref'])
        rows = self.registration_rows(record, previous)
        if rows != previous:
            self.save(rows)

    def registration_rows(self, record, rows):
        rows = AuthorityRows(rows, revision=getattr(rows, 'revision', None), scope=getattr(rows, 'scope', None))
        for finding in [*(record.get('static') or {}).get('findings', []),
                        *(record.get('review') or {}).get('findings', [])]:
            key = record['task_ref'] + ':' + finding['id']
            if key in rows:
                if (rows[key]['source'] == 'HOST_TASK_REVIEW'
                        and not rows[key].get('disposition_scope')):
                    rows[key] = dict(rows[key], disposition_scope=finding_disposition_scope(self.root, finding))
                if rows[key]['source'] == 'HOST_TASK_REVIEW' and not rows[key].get('disposition_locations'):
                    rows[key] = dict(rows[key], disposition_locations=finding_disposition_locations(
                        self.root, finding, rows[key]['required_source_paths']))
                continue
            source = finding.get('source', 'SCANNER')
            paths = {finding['file_path']}
            paths.update(e['path'] for e in finding.get('evidence_locations', []))
            if finding.get('category') == 'dependency':
                companion = str(Path(finding['file_path']).with_name('package.json')).replace('\\', '/')
                if companion in record['end']['hashes']:
                    paths.add(companion)
            rows[key] = dict(finding_id=finding['id'], origin_task_ref=record['task_ref'],
                origin_scan_id=(record.get('static') or {}).get('scan_id'),
                title=finding.get('plain_title') or finding['title'], category=finding['category'],
                file_path=finding['file_path'], source=source, status='OPEN',
                required_source_paths=sorted(paths),
                original_hashes={p:record['end']['hashes'].get(p) for p in paths},
                evidence_type='NONE', proof_hashes={}, repair_authorized=False)
            if source == 'HOST_TASK_REVIEW':
                rows[key]['disposition_scope'] = finding_disposition_scope(self.root, finding)
                rows[key]['disposition_locations'] = finding_disposition_locations(self.root, finding, paths)
        return rows

    def view(self, task_ref, offset=0, limit=30, origin_record=None):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 30:
            raise ValueError('Invalid ledger page')
        rows = self.read(task_ref)
        if origin_record and origin_record.get('end'):
            rows = self.registration_rows(origin_record, rows)
        selected = [dict(r) for r in rows.values() if r['origin_task_ref'] == task_ref]
        from .task_risk_feedback import project_feedback, project_disposition, _configuration_state
        configuration = (_configuration_state(self.root) if any(
            (row.get('feedback') or {}).get('status') == 'HOST_FALSE_POSITIVE'
            for row in selected) else None)
        counts, handling_counts = {}, {}
        for row in selected:
            row.pop('_task_projection', None)
            row.pop('_native_verification', None)
            events = row.pop('feedback_events', [])
            if events:
                row['feedback_audit_event_count'] = len(events)
                row['feedback_detail'] = dict(tool='get_task_risk_feedback',
                    task_ref=task_ref, finding_id=row['finding_id'], event_offset=0, event_limit=2)
            row['feedback'] = project_feedback(row, self.root, configuration=configuration)
            row.update(project_disposition(self.hooks, self.root, row, row['feedback']))
            row.pop('assessment_feedback', None)
            row['feedback']['folded'] = row['reminder_suppressed']
            row.pop('disposition_scope', None)
            row.pop('disposition_locations', None)
            proof = row.get('proof_hashes') or row['original_hashes']
            if current_hashes(self.root, proof) != proof:
                row['recorded_status'] = row['status']
                row['status'] = 'NEEDS_RECHECK'
            counts[row['status']] = counts.get(row['status'], 0) + 1
            handling_counts[row['handling_status']] = handling_counts.get(row['handling_status'], 0) + 1
        return dict(contract='task-risk-ledger-v1', task_ref=task_ref, total=len(selected),
            counts=counts, handling_counts=handling_counts, pending_count=handling_counts.get('OPEN', 0),
            items=selected[offset:offset+limit], has_more=offset+limit<len(selected),
            offset=offset, repair_authorized=False, production_safety_verified=False)

    def paths_for_scan(self, scan_id, ids):
        return {p for r in self.read_scan(scan_id).values() if r['origin_scan_id'] == scan_id and r['finding_id'] in ids
                for p in r['required_source_paths']}

    def record_native(self, scan_id, results, before):
        if not self.read_scan(scan_id):
            return dict(status='NOT_REGISTERED', recorded=0)
        with self.hooks.lock(self.root) as acquired:
            if not acquired:
                return dict(status='BUSY', recorded=0)
            rows = self.read_scan(scan_id)
            indexed = {r['finding_id']:r for r in results}
            count = 0
            unstable = 0
            for row in rows.values():
                if row['source'] != 'SCANNER' or row['origin_scan_id'] != scan_id or row['finding_id'] not in indexed:
                    continue
                result = indexed[row['finding_id']]
                hashes = {p:before.get(p) for p in row['required_source_paths']}
                stable = all(hashes.values()) and current_hashes(self.root, hashes) == hashes
                unstable += not stable
                row.update(status=result['verification_status'] if stable else 'INCONCLUSIVE',
                    evidence_type='ORIGINAL_SCANNER_RECHECK', proof_hashes=hashes if stable else {},
                    reason=result.get('reason', ''), verification_scope=result.get('verification_scope', 'ORIGINAL_RULE_FILE'),
                    dependency_verification=result.get('dependency_verification'),
                    scanner_runs=[{k:s.get(k) for k in ('scanner','status','version','coverage_contract')}
                                  for s in result.get('scanner_runs', [])],
                    production_safety_verified=False)
                row.pop('_native_verification', None)
                count += 1
            if count:
                self.save(rows)
            return dict(status='STALE' if unstable else 'RECORDED' if count else 'NOT_REGISTERED',
                        recorded=count, unverified_current=unstable)

    @staticmethod
    def _native_fingerprint(event):
        return revision({key:event[key] for key in ('event_id','scan_id','before','results','expected_rows')})

    def _native_rows(self, event, stored):
        """Read the selected rows from the same authenticated index snapshot."""
        origins = tuple(self.partitions.origins_for_scan(stored,event['scan_id']))
        rows = AuthorityRows(self.partitions.read_origins(stored,origins),
            revision=revision(stored), scope=origins)
        ids = {row['finding_id'] for row in event['results']}
        selected = {key:row for key,row in rows.items()
            if row['source'] == 'SCANNER' and row['origin_scan_id'] == event['scan_id']
            and row['finding_id'] in ids}
        return rows, selected

    def effect_current(self, event):
        """A pure target-watermark check, never execution or safety evidence.

        Old inbox records without row watermarks remain historical receipts.
        Unrelated rows and cache/outbox acknowledgements do not change this
        event's target watermark.
        """
        stored = self._stored()
        prior = stored['inbox'].get(event['event_id']+':ledger')
        if prior is None:
            return False
        if prior.get('payload_sha256') != self._native_fingerprint(event):
            raise ValueError('Risk verification receipt conflict')
        if prior.get('result',{}).get('status') not in {'RECORDED','NOT_REGISTERED'}:
            return False
        versions = prior.get('row_versions')
        if not isinstance(versions,dict):
            return False
        _, selected = self._native_rows(event,stored)
        return (set(selected) == set(versions) and all(
            self.row_version(row) == versions[key] for key,row in selected.items()))

    def apply_native_event(self, event):
        """Apply journaled scanner facts and inbox in one index publication."""
        if not self.hooks.lock_held(self.root): raise ValueError('Risk ledger workspace lock required')
        if self.authority.journal.exists(): self.authority._ensure()
        stored = self._stored()
        event_id = event['event_id']+':ledger'
        fingerprint = self._native_fingerprint(event)
        prior = stored['inbox'].get(event_id)
        if prior is not None:
            if prior['payload_sha256'] != fingerprint: raise ValueError('Risk verification receipt conflict')
            if (prior['result']['status'] in {'RECORDED','NOT_REGISTERED'}
                    and not self.effect_current(event)):
                return dict(status='SUPERSEDED',recorded=0,unverified_current=0,already_applied=True)
            return dict(prior['result'], already_applied=True)
        rows, selected = self._native_rows(event,stored)
        conflict = (set(selected) != set(event['expected_rows']) or any(
            self.row_version(row) != event['expected_rows'][key] for key,row in selected.items()))
        before = event['before']
        # No registered target rows means there is no ledger claim to mark
        # stale. Preserve the source's separate NOT_VERIFIED/no-attempt fact.
        stale = bool(selected) and (not all(before.values()) or current_hashes(self.root, before) != before)
        result = dict(status='SUPERSEDED' if conflict else 'STALE' if stale else
            'RECORDED' if selected else 'NOT_REGISTERED', recorded=0, unverified_current=int(stale))
        if not conflict and not stale:
            indexed = {r['finding_id']:r for r in event['results']}
            for row in selected.values():
                item = indexed[row['finding_id']]
                row.update(status=item['verification_status'], evidence_type='ORIGINAL_SCANNER_RECHECK',
                    proof_hashes={p:before.get(p) for p in row['required_source_paths']},
                    reason=item.get('reason',''), verification_scope=item.get('verification_scope','ORIGINAL_RULE_FILE'),
                    dependency_verification=item.get('dependency_verification'),
                    scanner_runs=[{k:s.get(k) for k in ('scanner','status','version','coverage_contract')}
                                  for s in item.get('scanner_runs',[])], production_safety_verified=False,
                    _native_verification=event['event_id'])
            result['recorded'] = len(selected)
        self.save(rows, receipt=(event_id, dict(payload_sha256=fingerprint, result=result,
            row_versions={key:self.row_version(row) for key,row in selected.items()})))
        return result

    def validate_host(self, record, resolutions, coverage):
        if not isinstance(resolutions, list) or len(resolutions) > 30:
            raise ValueError('Invalid risk resolutions')
        if any(not isinstance(item,dict) or not isinstance(item.get('original_task_ref'),str) for item in resolutions):
            raise ValueError('Use the risk resolution schema')
        rows = self.read_origins(item['original_task_ref'] for item in resolutions)
        updates = {}
        for item in resolutions:
            if not isinstance(item, dict) or set(item) != {'original_task_ref','finding_id','evidence_refs','outcome','rationale','tests'}:
                raise ValueError('Use the risk resolution schema')
            key = item['original_task_ref'] + ':' + item['finding_id']
            original = rows.get(key)
            if not original or original['source'] != 'HOST_TASK_REVIEW':
                raise ValueError('Only registered host candidates accept host resolution')
            if key in updates or item['outcome'] not in {'CODE_REVIEWED_RESOLVED','STILL_PRESENT','INCONCLUSIVE'}:
                raise ValueError('Invalid or duplicate resolution outcome')
            refs = item['evidence_refs']
            if not isinstance(refs, list) or not 1 <= len(refs) <= 10 or any(r not in record['evidence'] for r in refs):
                raise ValueError('Resolution requires issued evidence')
            evidence = [record['evidence'][r] for r in refs]
            paths = {e['path'] for e in evidence if e['location_version'] == 'CURRENT_TASK_END'}
            if not set(original['required_source_paths']) <= paths:
                raise ValueError('Resolution must re-read original risk and call/control paths')
            if not any(p in {v['path'] for v in record['changes']} for p in paths):
                raise ValueError('Resolution needs current task change evidence')
            for p in original['required_source_paths']:
                if record['end']['hashes'].get(p) != current_hashes(self.root, [p])[p]:
                    raise ValueError('Resolution source changed')
            for field in ('rationale', 'tests'):
                if not isinstance(item[field], str) or not item[field].strip() or len(item[field]) > 1200:
                    raise ValueError('Resolution needs bounded rationale and test report')
            from .task_security import _clean
            updates[key] = dict(status=item['outcome'] if coverage == 'REVIEWED' else 'INCONCLUSIVE',
                evidence_type='HOST_CODE_REVIEW_NOT_SCANNER_PROOF', review_task_ref=record['task_ref'],
                evidence_refs=refs, rationale=_clean(item['rationale'],1200), tests=_clean(item['tests'],1200),
                test_execution_trust='HOST_REPORTED_NOT_RUNTIME_OBSERVED',
                proof_hashes={p:record['end']['hashes'][p] for p in original['required_source_paths']},
                production_safety_verified=False)
        return updates

    @staticmethod
    def row_version(row):
        """A compare token, not a claim of safety or repair authority."""
        return digest(b'task-risk-row-version-v1', row)

    def record_host(self, updates, *, expected_versions=None, projection_id=None):
        rows = self.read_origins(key.split(':',1)[0] for key in updates)
        pending = {}
        for key, update in updates.items():
            if key not in rows:
                raise ValueError('Original ledger row missing')
            if expected_versions is not None:
                if not isinstance(projection_id, str) or len(projection_id) != 64:
                    raise ValueError('Risk projection identity missing')
                if rows[key].get('_task_projection') == projection_id:
                    continue  # Applied before an acknowledgement failure.
                if self.row_version(rows[key]) != expected_versions.get(key):
                    raise ValueError('Risk ledger row changed; retain pending projection')
            pending[key] = update
        # Validate every row before changing any; one conflicting row cannot
        # cause a partial technical-result rollback on an otherwise valid one.
        for key, update in pending.items():
            rows[key].update(update)
            if expected_versions is not None:
                rows[key]['_task_projection'] = projection_id
        if pending:
            self.save(rows)
