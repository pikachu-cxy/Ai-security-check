"""Stable report identity and semantic reminder receipts, separate from risk truth.

Only an explicit host delivery acknowledgement permits folding a later unchanged
existing risk. Preparing/reading a page or flushing a Hook is not that event.
Neither built-in connector currently supplies automatic final-report ACKs.
"""
import copy

from .durable import SignedRecords
from .delivery_receipts import result_version
from .security import digest_value
from .ownership import record_owner

CONTRACT = 'task-risk-report-v1'
LABELS = dict(EXISTING='已有风险', INTRODUCED='本次新增', EXPANDED='影响扩大', UNKNOWN='归属不明')


def report_ref(record):
    return 'trp1-'+digest_value([CONTRACT, record['workspace'], record_owner(record), result_version(record)])


def semantic_key(finding):
    value = finding.get('risk_attribution') or {}
    if not all(value.get(k) for k in ('issue_key', 'evidence_revision', 'detector_identity')):
        return None
    return digest_value([value['issue_key'], value['evidence_revision'], value['detector_identity'],
        finding.get('category'), finding.get('severity'), finding.get('impact')])


def grouped_rows(record):
    static = (record.get('static') or {}).get('findings', [])
    host = (record.get('review') or {}).get('findings', [])
    rows = [('STATIC_SCAN', copy.deepcopy(f)) for f in static]
    by_id = {f['id']:f for _, f in rows}
    for finding in host:
        target = by_id.get(finding.get('same_issue_as'))
        if target is not None:
            target.setdefault('related_observations', []).append(copy.deepcopy(finding))
        else:
            rows.append(('HOST_TASK_REVIEW', copy.deepcopy(finding)))
    return rows


class ReportNotifications(SignedRecords):
    def __init__(self, hooks, root, **kwargs):
        super().__init__(hooks, root, 'risk-notifications.db', **kwargs)

    def _prune(self, db):
        for row in self._all(db):
            if row['expires_at'] <= self.now():
                db.execute('DELETE FROM records WHERE key=?', (row['key'],))

    def acknowledge(self, record, owner, finding_ids, *, final_report_submitted):
        """Host integration callback after actual submission, not before final.

        The caller owns observation of delivery. This records a host attestation,
        never authenticated user reading, user handling or repair permission.
        Partial/page ACKs acknowledge only the explicitly delivered original IDs.
        """
        if (final_report_submitted is not True or record_owner(record) != owner
                or record['phase'] not in {'COMPLETE', 'INCOMPLETE', 'NO_CHANGES'}
                or len(finding_ids) > 1000):
            raise ValueError('Original terminal report delivery required')
        rows = [f for _, f in grouped_rows(record)]
        by_id = {f['id']:f for f in rows}
        if not set(finding_ids).issubset(by_id):
            raise ValueError('Only delivered original findings may be acknowledged')
        with self.transaction() as db:
            self._prune(db)
            for identifier in set(finding_ids):
                key = semantic_key(by_id[identifier])
                if key:
                    self._put(db, key, dict(report_ref=report_ref(record), task_ref=record['task_ref'],
                        finding_id=identifier, owner=owner, delivered_at=self.now(),
                        expires_at=self.now()+30*86400, delivery='HOST_REPORTED', user_consumption='UNKNOWN'))
        return dict(report_ref=report_ref(record), acknowledged_count=len(set(finding_ids)),
                    user_consumption='UNKNOWN', repair_authorized=False)

    def prior(self, finding):
        value = finding.get('risk_attribution') or {}
        if value.get('origin') != 'EXISTING' or value.get('impact') != 'UNCHANGED':
            return None
        key = semantic_key(finding)
        row = self.read(key) if key else None
        return ({k:row.get(k) for k in ('report_ref', 'task_ref', 'scan_id', 'finding_id', 'delivery')}
                if row and row['expires_at'] > self.now() else None)

    def acknowledge_project(self, result, owner, finding_ids, *, final_report_submitted):
        """Optional host callback for an explicitly displayed project report."""
        from pathlib import Path
        from dataclasses import asdict
        from .ownership import valid_owner
        if (final_report_submitted is not True or owner is not None and not valid_owner(owner)
                or Path(result.target_profile.path).resolve() != self.root
                or len(finding_ids) > 1000):
            raise ValueError('Original project report delivery required')
        rows = {f.id:asdict(f) for f in result.findings}
        if not set(finding_ids).issubset(rows):
            raise ValueError('Unknown project finding acknowledgement')
        report = 'prp1-'+digest_value([CONTRACT, str(self.root), result.scan_id])
        proof = result.scanner_diagnostics.get('comparison_proof') or {}
        with self.transaction() as db:
            self._prune(db)
            for identifier in set(finding_ids):
                scope = (result.source_scopes or {}).get(identifier, {})
                rows[identifier]['risk_attribution'] = dict(issue_key=scope.get('issue_key'),
                    evidence_revision=scope.get('evidence_revision'), detector_identity=proof.get('provider_identity'))
                key = semantic_key(rows[identifier])
                if key:
                    self._put(db, key, dict(report_ref=report, task_ref=None, scan_id=result.scan_id,
                        finding_id=identifier, owner=owner, delivered_at=self.now(),
                        expires_at=self.now()+30*86400, delivery='HOST_REPORTED', user_consumption='UNKNOWN'))
        return dict(report_ref=report, user_consumption='UNKNOWN', repair_authorized=False)


def describe(record):
    rows = grouped_rows(record)
    counts = {kind:0 for kind in LABELS}
    for _, finding in rows:
        kind = (finding.get('risk_attribution') or {}).get('origin', 'UNKNOWN')
        counts[kind if kind in counts else 'UNKNOWN'] += 1
    return dict(contract=CONTRACT, report_ref=report_ref(record), attribution_counts=counts,
        distinct_issue_count=len(rows),
        raw_observation_count=sum(len((record.get(k) or {}).get('findings', [])) for k in ('static', 'review')),
        notification_policy='EXPLICIT_FINAL_REPORT_ACK_ONLY', automatic_host_ack=False,
        user_consumption='UNKNOWN')
