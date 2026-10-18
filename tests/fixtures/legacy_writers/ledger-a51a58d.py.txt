"""Signed per-finding outcomes; never edit authority or production safety."""
from __future__ import annotations
import hmac
import json
from pathlib import Path
from .closeout_state import digest
from .hook_state import atomic_bytes, no_links
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
        self.path = hooks.workspace_directory(self.root) / 'task-risk-ledger.json'

    def read(self):
        no_links(self.path)
        if not self.path.exists():
            return {}
        if self.path.stat().st_size > MAX_BYTES:
            raise ValueError('Risk ledger byte budget exceeded')
        data = json.loads(self.path.read_bytes())
        if (data.get('contract') != 'task-risk-ledger-v1' or not isinstance(data.get('rows'), dict)
                or len(data['rows']) > MAX_ROWS or data.get('workspace') != str(self.root)
                or not hmac.compare_digest(data['mac'], digest(self.hooks.key(self.root), data['rows']))):
            raise ValueError('Risk ledger cannot be verified')
        return data['rows']

    def save(self, rows):
        if len(rows) > MAX_ROWS:
            raise ValueError('Risk ledger row budget exceeded')
        data = dict(contract='task-risk-ledger-v1', workspace=str(self.root), rows=rows,
                    mac=digest(self.hooks.key(self.root), rows))
        raw = json.dumps(data, ensure_ascii=False).encode()
        if len(raw) > MAX_BYTES:
            raise ValueError('Risk ledger byte budget exceeded')
        atomic_bytes(self.path, raw)

    def register(self, record):
        rows = self.registration_rows(record, self.read())
        self.save(rows)

    def registration_rows(self, record, rows):
        rows = dict(rows)
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
        rows = self.read()
        if origin_record and origin_record.get('end'):
            rows = self.registration_rows(origin_record, rows)
        selected = [dict(r) for r in rows.values() if r['origin_task_ref'] == task_ref]
        from .task_risk_feedback import project_feedback, project_disposition, _configuration_state
        configuration = (_configuration_state(self.root) if any(
            (row.get('feedback') or {}).get('status') == 'HOST_FALSE_POSITIVE'
            for row in selected) else None)
        counts, handling_counts = {}, {}
        for row in selected:
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
        return {p for r in self.read().values() if r['origin_scan_id'] == scan_id and r['finding_id'] in ids
                for p in r['required_source_paths']}

    def record_native(self, scan_id, results, before):
        if not self.read():
            return dict(status='NOT_REGISTERED', recorded=0)
        with self.hooks.lock(self.root) as acquired:
            if not acquired:
                return dict(status='BUSY', recorded=0)
            rows = self.read()
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
                count += 1
            if count:
                self.save(rows)
            return dict(status='STALE' if unstable else 'RECORDED' if count else 'NOT_REGISTERED',
                        recorded=count, unverified_current=unstable)

    def validate_host(self, record, resolutions, coverage):
        if not isinstance(resolutions, list) or len(resolutions) > 30:
            raise ValueError('Invalid risk resolutions')
        rows = self.read()
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

    def record_host(self, updates):
        rows = self.read()
        for key, update in updates.items():
            if key not in rows:
                raise ValueError('Original ledger row missing')
            rows[key].update(update)
        if updates:
            self.save(rows)
