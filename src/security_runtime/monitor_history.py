"""Explicit bounded read-only history import, independent of product startup."""
import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from .product_metrics import assessment, envelope, scan_fact


def import_history(store, source, *, workspace, before=None, limit=100, run='history'):
    """Read old outcomes only. Never infer old line counts from current files."""
    if type(limit) is not int or not 1 <= limit <= 200 or before is not None and (type(before) is not int or before < 1):
        raise ValueError('INVALID_HISTORY_PAGE')
    from .hook_state import no_links
    from .context_cost import run_label
    run = run_label(run)
    source = Path(source).absolute()
    no_links(source)
    if not source.is_file() or source == store.path.absolute() or (store.path.exists() and os.path.samefile(source,store.path)):
        return dict(status='UNAVAILABLE', reason_code='HISTORY_SOURCE_UNAVAILABLE')
    if store.monitoring().get('mode') == 'off':
        return dict(status='UNAVAILABLE', reason_code='MONITOR_DISABLED')
    workspace = os.path.normcase(os.path.abspath(workspace))
    saved = store.snapshot()
    if saved['status'] != 'AVAILABLE':
        return dict(status='UNAVAILABLE', reason_code='HISTORY_MONITOR_UNAVAILABLE')
    prior = saved.get('product_facts', [])
    recorded, skipped, invalid, consumed, scanned = 0, 0, 0, 0, 0
    cursor, has_more = before, False
    started = time.monotonic()
    try:
        with closing(sqlite3.connect(source.as_uri()+'?mode=ro', uri=True, timeout=.2)) as db:
            db.execute('PRAGMA query_only=ON')
            db.set_progress_handler(lambda: int(time.monotonic()-started > 10), 1000)
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'scans' not in tables:
                return dict(status='UNAVAILABLE', reason_code='HISTORY_TABLE_UNAVAILABLE')
            rows = db.execute('SELECT rowid,length(CAST(data AS BLOB)),substr(data,1,2097153) FROM scans WHERE rowid<? ORDER BY rowid DESC LIMIT ?',
                (before or 2**63-1, limit+1))
            # Explicit monitor administration can open its own DB; no product path does this.
            target, key = store._connect(write=True)
            target.close()
            workspace_hash = store._digest(key, 'workspace', workspace)
            seen = {(e['product_fact']['kind'], e['product_fact']['reference'],
                     json.dumps(e['product_fact']['items'], sort_keys=True)) for e in prior if e.get('workspace_hash') == workspace_hash}
            seen_scans = {item[:2] for item in seen if item[0]=='SCAN'}

            def write(fact):
                nonlocal recorded, skipped, invalid
                fact['source'] = 'HISTORY'
                identity = (fact['kind'], store._digest(key,'product_scope',fact['reference']),
                    json.dumps([dict(i,id=store._digest(key,'finding',i['id']), **(
                        {'risk_key':store._digest(key,'risk_identity',i['risk_key'])} if i.get('risk_key') else {}))
                        for i in fact['items']], sort_keys=True))
                if identity in seen or fact['kind']=='SCAN' and identity[:2] in seen_scans:
                    skipped += 1
                    return
                result = store.record_observation(envelope(fact, workspace=workspace, run=run))
                if result['status'] == 'RECORDED':
                    seen.add(identity)
                    if fact['kind']=='SCAN':
                        seen_scans.add(identity[:2])
                    recorded += 1
                else:
                    invalid += 1

            for rowid,size,raw in rows:
                if scanned >= limit or consumed + size > 32*1024*1024:
                    has_more = True
                    break
                cursor, scanned = rowid, scanned+1
                if size > 2*1024*1024:
                    invalid += 1
                    continue
                consumed += size
                try:
                    scan = json.loads(raw)
                    if os.path.normcase(os.path.abspath(scan['target_profile']['path'])) != workspace:
                        continue
                    write(scan_fact(scan))
                    if 'triage_records' in tables:
                        # Latest persisted state per finding, bounded independently of scan JSON.
                        records = db.execute('SELECT substr(data,1,65537) FROM triage_records WHERE scan_id=? ORDER BY id DESC LIMIT 201', (scan['scan_id'],)).fetchall()
                        seen_findings = set()
                        if len(records) > 200:
                            invalid += 1
                        for (data,) in records[:200]:
                            if len(data.encode('utf-8')) > 65536:
                                invalid += 1
                                continue
                            value = json.loads(data)
                            if value['finding_id'] not in seen_findings:
                                write(assessment(value))
                                seen_findings.add(value['finding_id'])
                except (ValueError, TypeError, KeyError):
                    invalid += 1
    except sqlite3.DatabaseError:
        return dict(status='PARTIAL', recorded=recorded, skipped=skipped, invalid=invalid+1,
                    next_before=cursor, has_more=True, reason_code='HISTORY_READ_INCOMPLETE')
    return dict(status='PARTIAL' if invalid or has_more else 'RECORDED', recorded=recorded,
        skipped=skipped, invalid=invalid, inspected_scans=scanned, has_more=has_more,
        next_before=cursor if has_more else None, line_counts='UNKNOWN_FOR_OLD_SCANS',
        history_scope='SAVED_SCANS_AND_TRIAGE_ONLY; NOT_HOST_TASK_LEDGER; NOT_CURRENT_SOURCE_VALIDATION')
