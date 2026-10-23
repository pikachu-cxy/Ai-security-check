"""Scanner-result authority plus recoverable ledger/closure delivery receipts.

The durable source contains only detector metadata, coordinates and Runtime
execution facts. It never contains source bodies or host approval, and pending
deliveries have no TTL. Preparation and queries never create this journal.
"""
from __future__ import annotations
import copy
import uuid

from ..private_authority import revision
from ..repair_impact_store import RepairImpactStore
from .risk_ledger import TaskRiskLedger, current_hashes
from ..risk_closure import RiskClosureService

CONTRACT = 'task-verification-journal-v1'
MAX_RECORDS = 512


def originals_metadata(members):
    return [dict(id=row['id'], category=row['category'], file_path=row['file_path'],
        line_start=row.get('line_start',1), line_end=row.get('line_end',row.get('line_start',1)),
        scanner_sources=row['scanner_sources'], technical_details={k:v for k,v in
            (row.get('technical_details') or {}).items() if k in {
                'rule_id','engine','rule_pack_checksum','rule_version'}}) for row in members]


class TaskVerificationJournal:
    def __init__(self, hooks, root):
        self.hooks, self.root = hooks, root
        self.store = RepairImpactStore(hooks.workspace_directory(root)/'repair-impact')

    def _load(self, db, ref):
        value = self.store.load(db, 'task_verifications', ref)
        if (value is not None and (value.get('contract') != CONTRACT
                or value.get('workspace') != str(self.root) or value.get('event_id') != ref
                or value.get('state') not in {'PENDING','APPLIED','SUPERSEDED'})):
            raise ValueError('Verification journal cannot be verified')
        return value

    def pending(self, task_ref=None, limit=8):
        if type(limit) is not int or not 1 <= limit <= MAX_RECORDS:
            raise ValueError('Invalid verification recovery limit')
        if not self.store.path.exists(): return []
        with self.store.connect() as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='task_verifications'").fetchone():
                return []
            refs = db.execute('SELECT id FROM task_verifications ORDER BY rowid LIMIT ?', (MAX_RECORDS+1,)).fetchall()
            if len(refs) > MAX_RECORDS: raise ValueError('Verification journal capacity exceeded')
            selected = []
            for row in refs:
                value = self._load(db, row[0])
                if value['state'] == 'PENDING' and (task_ref is None or value['task_ref'] == task_ref):
                    selected.append(value)
                    if len(selected) == limit: break
            return selected

    def append(self, *, task_ref, scan_id, members, results, before, expected_rows,
               closure_version, activity_epoch, input_hashes=None, input_context=None):
        if not self.hooks.lock_held(self.root): raise ValueError('Verification workspace lock required')
        record = dict(contract=CONTRACT, event_id='tvj1-'+uuid.uuid4().hex, workspace=str(self.root),
            task_ref=task_ref, scan_id=scan_id, originals=originals_metadata(members),
            results=copy.deepcopy(results), before=dict(before), expected_rows=dict(expected_rows),
            closure_version=closure_version, activity_epoch=activity_epoch, state='PENDING', targets={})
        if input_hashes is not None:
            record['input_hashes']=dict(input_hashes)
        if input_context is not None:
            record['input_context']=copy.deepcopy(input_context)
        with self.store.connect(write=True) as db:
            if db.execute('SELECT count(*) FROM task_verifications').fetchone()[0] >= MAX_RECORDS:
                raise ValueError('Verification journal capacity exceeded; history and pending receipts retained')
            self.store.save(db,'task_verifications',record['event_id'],record)
        return record

    def _ack(self, original, target, result):
        with self.store.connect(write=True) as db:
            current = self._load(db, original['event_id'])
            if current is None: raise ValueError('Original verification journal missing')
            source = lambda v: {k:value for k,value in v.items() if k not in {'targets','state'}}
            if source(current) != source(original): raise ValueError('Verification source changed')
            old = current['targets'].get(target)
            if old is not None and old != result: raise ValueError('Verification acknowledgement conflict')
            current['targets'][target] = copy.deepcopy(result)
            if {'ledger','closure'} <= set(current['targets']):
                current['state'] = ('SUPERSEDED' if any(v.get('status') in {'SUPERSEDED','STALE','NEW_ACTIVITY'}
                    for v in current['targets'].values()) else 'APPLIED')
            self.store.save(db,'task_verifications',current['event_id'],current)
            return current

    def _superseded(self, record, reason):
        """Keep committed target acknowledgements as history, revoke publication."""
        with self.store.connect(write=True) as db:
            current=self._load(db,record['event_id'])
            if current is None: raise ValueError('Original verification journal missing')
            if current['state']!='PENDING': return current
            if current!=record: raise ValueError('Verification source changed')
            current['state']='SUPERSEDED'
            current['superseded_reason']=reason
            self.store.save(db,'task_verifications',current['event_id'],current)
            return current

    def drain(self, record):
        if not self.hooks.lock_held(self.root): raise ValueError('Verification workspace lock required')
        if record['state'] != 'PENDING': return record
        ledger, closure = TaskRiskLedger(self.hooks,self.root), RiskClosureService(self.hooks)
        # Old evidence is retained as a historical source fact, never replayed
        # onto changed source or a newer independently observed result.
        inputs=record.get('input_hashes',record['before'])
        if (record.get('input_context') is not None
                and record['input_context'].get('applicability')!='CURRENT'
                or current_hashes(self.root, record['before']) != record['before']
                or current_hashes(self.root,inputs)!=inputs):
            for target in ('ledger','closure'):
                if target not in record['targets']:
                    record = self._ack(record,target,dict(status='SUPERSEDED',reason='SOURCE_CHANGED'))
            return record
        # An ACK proves the target committed at the time. A pending source may
        # resume only while that exact technical effect remains current; newer
        # independent facts must never turn the old source into a fresh result.
        acknowledged=record['targets'].get('ledger',{})
        if (acknowledged.get('status') in {'RECORDED','NOT_REGISTERED'}
                and not ledger.effect_current(record)):
            return self._superseded(record,'LEDGER_EFFECT_SUPERSEDED')
        acknowledged=record['targets'].get('closure',{})
        if (acknowledged.get('status')=='SAVED'
                and not closure.effect_current(self.root,record['event_id']+':closure')):
            return self._superseded(record,'CLOSURE_EFFECT_SUPERSEDED')
        if 'ledger' not in record['targets']:
            receipt = ledger.apply_native_event(record)
            receipt.pop('already_applied',None)
            record = self._ack(record,'ledger',receipt)
            if receipt.get('status') in {'SUPERSEDED','STALE','NEW_ACTIVITY'}:
                return self._superseded(record,'LEDGER_EFFECT_SUPERSEDED')
        if 'closure' not in record['targets']:
            if any(row['category'] == 'secret' for row in record['originals']):
                receipt = closure.record(self.root,record['originals'],record['results'],
                    source='MANUAL_INDEPENDENT_RECHECK', expected_activity=record['activity_epoch'],
                    expected_version=record['closure_version'], effect_id=record['event_id']+':closure', locked=True)
                receipt.pop('already_applied',None)
                receipt.pop('cache_sync',None)
            else: receipt = dict(status='NOT_APPLICABLE',confirmed=0)
            record = self._ack(record,'closure',receipt)
        return record

    def reconcile(self, limit=8):
        if not self.hooks.lock_held(self.root): raise ValueError('Verification workspace lock required')
        return [self.drain(record) for record in self.pending(limit=limit)]
