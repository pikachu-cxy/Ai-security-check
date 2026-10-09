"""Explicit local-only quality dataset export/review; no scans, AI or source edits."""
import argparse
from collections import Counter
import json
from pathlib import Path

from security_runtime.finding_quality import FindingQualityService
from security_runtime.storage import ReadOnlySQLiteStore, SQLiteStore


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['export', 'review'])
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--scan')
    parser.add_argument('--database', type=Path)
    parser.add_argument('--decisions', type=Path, help='Explicit JSON list of review decisions')
    parser.add_argument('--local-evidence', action='store_true', help='Include bounded redacted local context; never changes stored scans or reviews')
    args = parser.parse_args(argv)
    root = args.workspace.resolve(strict=True)
    if args.database is not None:
        candidates = [ReadOnlySQLiteStore(args.database)]
    else:
        from security_runtime.global_workspace import workspace_state
        candidates = [ReadOnlySQLiteStore(workspace_state(root) / 'scans.db'), ReadOnlySQLiteStore()]
    store, scan = candidates[0], None
    for candidate in candidates:
        found = candidate.get_scan(args.scan) if args.scan else candidate.latest_scan(root)
        if found is not None and Path(found['target_profile']['path']).resolve() == root:
            store, scan = candidate, found
            break
    if scan is None or Path(scan['target_profile']['path']).resolve() != root:
        parser.error('A stored scan belonging to this workspace is required')
    service = FindingQualityService(store)
    # Validate local output boundaries before any review persistence.
    from security_runtime.hook_state import no_links
    output = root / '.security-runtime' / 'finding-quality'
    no_links(output)
    for name in ('baseline.json', 'review-template.json', 'REPORT.md'):
        no_links(output / name)
    if args.action == 'review':
        if args.decisions is None or args.decisions.stat().st_size > 4_000_000:
            parser.error('A bounded explicit decisions JSON file is required')
        decisions = json.loads(args.decisions.read_text(encoding='utf-8'))
        # User explicitly requested persistence; export remains fully read-only.
        service = FindingQualityService(SQLiteStore(store.path))
        service.review(scan['scan_id'], decisions)
    dataset = service.view(scan['scan_id'])
    if args.local_evidence:
        from security_runtime.local_evidence import attach_local_evidence
        attach_local_evidence(dataset, scan)
        statuses = Counter(r['local_evidence']['evidence_status'] for r in dataset['findings'])
        dataset['local_evidence_summary'] = dict(
            status={status: statuses[status] for status in ('EXACT', 'STALE', 'MISSING', 'UNAVAILABLE')},
            reasons=dict(Counter(r['local_evidence']['reason'] for r in dataset['findings'] if r['local_evidence']['reason'])),
            current_context_available=sum(r['local_evidence']['current_context'] is not None for r in dataset['findings']),
            secret_redacted=sum(r['local_evidence']['reason'] == 'SECRET_REDACTED' for r in dataset['findings']))
    # Fixed ignored destination: never accidentally put private rows in docs or
    # tracked fixtures. Refuse linked output parents before writing any report.
    output.mkdir(parents=True, exist_ok=True)
    (output / 'baseline.json').write_text(json.dumps(dataset, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    template = [{k:r[k] for k in ('finding_id', 'observation_hash', 'triage_status', 'triage_reason', 'triage_source')}
                for r in dataset['findings']]
    (output / 'review-template.json').write_text(json.dumps(template, indent=2)+'\n', encoding='utf-8')
    report = '# Local finding quality baseline\n\nPrivate local dataset; never commit. No AI analysis or automatic fix was run.\n\n'
    report += 'Scan: `' + dataset['scan_id'] + '`; scanner coverage: `' + str(dataset['scan_coverage']) + '`. Coverage is not precision or recall.\n\n'
    report += 'All labels start UNREVIEWED. Review template entries are not decisions until explicitly edited and imported; retain only reviewed entries and supply source and reason.\n\n'
    evidence_status = dict(Counter(row['evidence']['matched_code_status'] for row in dataset['findings']))
    report += 'Stored matched-code availability: `' + json.dumps(evidence_status) + '`. Scanner placeholders are not source code; source/sink are null and trace is empty. Use existing bounded evidence preparation or local files for review.\n\n'
    if args.local_evidence:
        report += 'Local evidence freshness / availability: `' + json.dumps(dataset['local_evidence_summary']) + '`. Missing historical hashes cannot be recovered retroactively: inspect current_context separately from original_evidence. All code is UNTRUSTED_CODE and conservatively redacted.\n\n'
    report += 'Metrics and rankings (precision denominator is TP + FP; missing labels are not TP; recall is unavailable):\n\n```json\n'
    report += json.dumps(dataset['metrics'], indent=2) + '\n```\n'
    (output / 'REPORT.md').write_text(report, encoding='utf-8')
    print(json.dumps(dict(scan_id=dataset['scan_id'], coverage=dataset['scan_coverage'],
                         metrics=dataset['metrics']['overall'], output=str(output))))


if __name__ == '__main__':
    main()
