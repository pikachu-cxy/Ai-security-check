"""Explicit closeout requests; reads and edit events never dispatch scans."""
import hashlib
import uuid
import random

from ..closeout_state import encode
from .durable import SignedRecords
from .ownership import record_owner, valid_owner

CONTRACT = 'task-closeout-queue-v1'
PENDING = frozenset({'QUEUED', 'RUNNING', 'RETRY_WAIT'})
TERMINAL = frozenset({'READY_FOR_REVIEW', 'NO_CHANGES', 'STALE', 'CANCELLED', 'FAILED', 'EXPIRED'})


def fingerprint(value):
    return hashlib.sha256(encode(value)).hexdigest()


class CloseoutQueue(SignedRecords):
    def __init__(self, hooks, root, **kwargs):
        super().__init__(hooks, root, 'task-closeout-queue.db', **kwargs)

    def submit(self, record, end, configuration, input_ref=None, preparation_ms=0):
        owner = record_owner(record)
        if not valid_owner(owner):
            raise ValueError('Closeout owner required')
        revision = fingerprint(dict(hashes=end['hashes'], inventory=end.get('inventory'),
            limitations=end.get('limitations'), configuration=configuration))
        with self.transaction() as db:
            old = self._get(db, record['task_ref'])
            if old and old['revision'] == revision and old['state'] not in {'CANCELLED', 'FAILED', 'EXPIRED', 'STALE'}:
                return old
            if old and old['state'] == 'RUNNING' and old['lease_until'] > self.now():
                raise ValueError('Closeout is running; cancel or wait before submitting another version')
            generation = old['generation']+1 if old else 1
            return self._put(db, record['task_ref'], dict(contract=CONTRACT,
                task_ref=record['task_ref'], job_ref='cq1-'+uuid.uuid4().hex, owner=owner,
                baseline_digest=fingerprint(record['baseline']), end=end,
                input_ref=input_ref,
                configuration=configuration, revision=revision, generation=generation,
                state='QUEUED', created_at=self.now(), expires_at=self.now()+86400,
                preparation_ms=preparation_ms, scan_started_at=None, finished_at=None,
                next_attempt_at=self.now(), attempts=0, lease_owner=None, lease_until=0,
                reason=None))

    def claim(self, ref, worker, *, seconds=120):
        with self.transaction() as db:
            row = self._get(db, ref)
            if not row or row['state'] not in PENDING:
                return None
            if row['expires_at'] <= self.now():
                self._put(db, ref, dict(row, state='EXPIRED', reason='QUEUE_RETENTION_EXPIRED'))
                return None
            if row['next_attempt_at'] > self.now() or row['state'] == 'RUNNING' and row['lease_until'] > self.now():
                return None
            return self._put(db, ref, dict(row, state='RUNNING', lease_owner=worker,
                generation=row['generation']+1, lease_until=self.now()+seconds,
                attempts=row['attempts']+1))

    @staticmethod
    def matches(row, claim):
        return bool(row and row['state'] == 'RUNNING' and all(row[k] == claim[k]
            for k in ('job_ref', 'generation', 'lease_owner')))

    def current(self, claim):
        row = self.read(claim['task_ref'])
        return self.matches(row, claim) and row['lease_until'] > self.now()

    def renew(self, claim):
        with self.transaction() as db:
            row = self._get(db, claim['task_ref'])
            if not self.matches(row, claim) or row['lease_until'] <= self.now():
                return False
            self._put(db, row['task_ref'], dict(row, lease_until=self.now()+120))
            return True

    def started(self, claim):
        with self.transaction() as db:
            row = self._get(db, claim['task_ref'])
            if not self.matches(row, claim) or row['lease_until'] <= self.now():
                return False
            self._put(db, row['task_ref'], dict(row, scan_started_at=row.get('scan_started_at') or self.now()))
            return True

    def finish(self, claim, state, reason=None):
        if state not in TERMINAL | {'RETRY_WAIT'}:
            raise ValueError('Invalid queue transition')
        with self.transaction() as db:
            row = self._get(db, claim['task_ref'])
            if not self.matches(row, claim) or row['lease_until'] <= self.now():
                return False
            delay = min(30, 2**min(row['attempts'], 5)) + random.uniform(0, 0.5)
            self._put(db, row['task_ref'], dict(row, state=state, reason=reason,
                finished_at=self.now() if state in TERMINAL else None,
                lease_owner=None, lease_until=0, next_attempt_at=self.now()+delay))
            return True

    def cancel(self, ref, owner):
        with self.transaction() as db:
            row = self._get(db, ref)
            if not row or row['owner'] != owner:
                raise ValueError('Closeout owner mismatch')
            if row['state'] in PENDING:
                row = self._put(db, ref, dict(row, state='CANCELLED',
                    generation=row['generation']+1, lease_owner=None, lease_until=0))
            return row

    def view(self, ref, owner):
        row = self.read(ref)
        if not row:
            return dict(status='NOT_QUEUED', task_ref=ref)
        if row['owner'] != owner:
            raise ValueError('Closeout owner mismatch')
        return dict(status=row['state'], task_ref=ref, job_ref=row['job_ref'],
            end_version_ref=row['end'].get('version_ref'), current_source_rechecked=False,
            generation=row['generation'], attempts=row['attempts'], reason=row['reason'],
            queued_at=row['created_at'], next_attempt_at=row['next_attempt_at'],
            preparation_ms=row.get('preparation_ms'),
            queue_wait_ms=round(1000*(row['scan_started_at']-row['created_at'])) if row.get('scan_started_at') else None,
            scan_elapsed_ms=round(1000*(row['finished_at']-row['scan_started_at']))
                if row.get('finished_at') and row.get('scan_started_at') else None,
            next_action='prepare_task_security_review' if row['state'] == 'READY_FOR_REVIEW'
                else 'get_task_closeout_status', baseline_recreated=False)
