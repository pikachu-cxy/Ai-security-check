"""Finding quality observations and independent, non-enforcing review decisions.

Legacy scanner IDs remain workspace-scoped remediation references. Portable
quality IDs are never used as authorization or as global database lookup keys.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath

from .diagnostics import sanitize

STATUSES = ('UNREVIEWED', 'TRUE_POSITIVE', 'FALSE_POSITIVE', 'NEEDS_CONTEXT',
            'ACCEPTED_RISK', 'NOT_APPLICABLE')
SOURCES = ('HUMAN', 'AI', 'POLICY')
VERSION = 'finding-quality-v1'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                    separators=(',', ':')).encode()).hexdigest()


def relative_file(value):
    name = str(value).replace('\\', '/')
    path = PurePosixPath(name)
    if (path.is_absolute() or PureWindowsPath(name).drive or '..' in path.parts
            or not name or name == '[outside workspace]'):
        raise ValueError('Quality findings require a workspace-relative file')
    return path.as_posix()


def quality_finding(finding):
    """Derived stored-scanner evidence only; never infer taint flow from code."""
    md = finding.get('technical_details', {})
    file = relative_file(finding['file_path'])
    kind = finding['category']
    rule = md.get('rule_id', '')
    scanner = sorted(set(finding.get('scanner_sources', [])))
    start, end = finding['line_start'], finding.get('line_end', finding['line_start'])
    if type(start) is not int or type(end) is not int or not 1 <= start <= end:
        raise ValueError('Invalid finding range')
    # Retain existing same-category/same-line deduplication semantics; changing
    # representative rule or scanner order must not invent a second finding.
    identity = [VERSION, kind, file, start, rule if kind == 'configuration' else '']
    if kind == 'dependency':
        # Advisory aliases/provider choice and manifest line movement do not
        # duplicate an affected package/advisory already normalized by Runtime.
        identity = [VERSION, kind, file, md.get('ecosystem'), md.get('package'),
                    md.get('package_version'), md.get('canonical_vulnerability_id', rule)]
    level = {'secret': 'SECRET_MATCH', 'dependency': 'DEPENDENCY_MATCH',
             'configuration': 'CONFIG_MATCH'}.get(kind, 'DIRECT_MATCH')
    stored_evidence = sanitize(finding.get('evidence', ''), 2000)
    placeholder = 'semgrep' in scanner and stored_evidence.strip().lower() == 'requires login'
    matched_status = ('REDACTED' if kind == 'secret' else 'NOT_APPLICABLE' if kind == 'dependency'
        else 'UNAVAILABLE_SCANNER_PLACEHOLDER' if placeholder else 'AVAILABLE' if stored_evidence else 'NOT_PROVIDED')
    evidence = dict(evidence_level=level, provenance='STORED_SCANNER_OUTPUT', source=None, sink=None, trace=[],
                    matched_code=stored_evidence if matched_status == 'AVAILABLE' else None,
                    matched_code_status=matched_status,
                    scanner_evidence='[REDACTED_SECRET]' if kind == 'secret' else stored_evidence,
                    rule_metadata={k: md[k] for k in ('rule_id', 'rule_pack', 'rule_pack_version',
                        'rule_pack_checksum', 'capability_id', 'capability_maturity', 'cwe', 'framework') if k in md},
                    dataflow_available=False)
    row = dict(finding_id='fq1-' + digest(identity)[:32], scanner_finding_id=finding['id'],
        rule_id=rule, scanner=scanner, capability=md.get('capability_id') or 'UNMAPPED',
        file=file, line=start, line_end=end, severity=finding['severity'],
        confidence=finding['confidence'], message=sanitize(finding.get('description') or finding.get('plain_title', ''), 2000),
        evidence=evidence, scanner_metadata=md,
        triage_status='UNREVIEWED', triage_reason='', triage_source=None, triaged_at=None)
    # Review reuse is conservative: changed scanner observations need review.
    # Root/scan/time/ordering are excluded, while confidence/message/range and
    # normalized scanner metadata/evidence changes invalidate prior decisions.
    observation = {k: row[k] for k in ('finding_id', 'rule_id', 'scanner', 'file', 'line',
        'line_end', 'severity', 'confidence', 'message', 'evidence', 'scanner_metadata')}
    row['observation_hash'] = digest(observation)
    return row


def metrics(findings):
    def count(rows):
        counts = {s: sum(f['triage_status'] == s for f in rows) for s in STATUSES}
        tp, fp = counts['TRUE_POSITIVE'], counts['FALSE_POSITIVE']
        return dict(total=len(rows), reviewed=len(rows)-counts['UNREVIEWED'], TP=tp, FP=fp,
            NEEDS_CONTEXT=counts['NEEDS_CONTEXT'], ACCEPTED_RISK=counts['ACCEPTED_RISK'],
            NOT_APPLICABLE=counts['NOT_APPLICABLE'], UNREVIEWED=counts['UNREVIEWED'],
            precision_on_reviewed=tp/(tp+fp) if tp+fp else None,
            precision_denominator=tp+fp)
    groups = {}
    for key in ('rule_id', 'capability'):
        groups[key] = [dict(group=value, **count([r for r in findings if r[key] == value]))
                       for value in sorted({f[key] for f in findings})]
    return dict(overall=count(findings), by_rule=groups['rule_id'], by_capability=groups['capability'],
        by_source={s: count([r for r in findings if r['triage_source'] == s]) for s in SOURCES},
        rankings={name: sorted([r for r in groups['rule_id'] if r[name] > 0],
                    key=lambda r: (-r[name], r['group'])) for name in ('FP', 'TP', 'NEEDS_CONTEXT')},
        recall=None, recall_reason='No independently labelled missed-finding denominator',
        precision_scope='Recorded decisions only; AI/POLICY labels are not independent human ground truth')


class FindingQualityService:
    def __init__(self, store):
        self.store = store

    def view(self, scan_id):
        scan = self.store.get_scan(scan_id)
        if scan is None:
            raise ValueError('Scan does not exist')
        workspace = str(Path(scan['target_profile']['path']).resolve())
        # Stable identity correlates rescans; labels do not automatically carry
        # across snapshots without independent evidence of unchanged context.
        reviews = self.store.finding_reviews(workspace, scan_id)
        findings = []
        seen = set()
        for finding in scan['findings']:
            row = quality_finding(finding)
            if row['finding_id'] in seen:
                raise ValueError('Ambiguous portable finding identity in scan')
            seen.add(row['finding_id'])
            review = reviews.get((row['finding_id'], row['observation_hash']))
            if review:
                row.update({key: review[key] for key in ('triage_status', 'triage_reason', 'triage_source', 'triaged_at')})
            findings.append(row)
        return dict(contract=VERSION, scan_id=scan_id, scan_coverage=scan.get('coverage'),
                    findings=findings, metrics=metrics(findings))

    def review(self, scan_id, decisions):
        # Explicit local review, no AI provider, policy enforcement or suppression.
        view = self.view(scan_id)
        rows = {r['finding_id']: r for r in view['findings']}
        if not isinstance(decisions, list) or len(decisions) > 10000:
            raise ValueError('Invalid review batch')
        records, seen = [], set()
        for decision in decisions:
            if not isinstance(decision, dict) or set(decision) != {
                    'finding_id', 'observation_hash', 'triage_status', 'triage_reason', 'triage_source'}:
                raise ValueError('Invalid review fields')
            fid = decision['finding_id']
            if not isinstance(fid, str):
                raise ValueError('Invalid finding ID')
            row = rows.get(fid)
            if fid in seen or row is None or decision['observation_hash'] != row['observation_hash']:
                raise ValueError('Unknown, duplicate or changed finding observation')
            seen.add(fid)
            status, source, reason = (decision[k] for k in ('triage_status', 'triage_source', 'triage_reason'))
            if status not in STATUSES or source not in SOURCES or not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
                raise ValueError('Review requires valid status, source and bounded reason')
            records.append({**decision, 'triage_reason': sanitize(reason, 4000),
                            'triaged_at': datetime.now(timezone.utc).isoformat()})
        scan = self.store.get_scan(scan_id)
        self.store.save_finding_reviews(str(Path(scan['target_profile']['path']).resolve()), scan_id, records)
        return self.view(scan_id)
