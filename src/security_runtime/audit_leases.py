"""Small cross-process admission budget; no model or source data in the lease DB."""
from contextlib import closing
import json
import sqlite3
import time
from .hook_state import no_links, identity
from .storage import SQLiteStore


def reserve(workspace, owner, audit_id):
    path = SQLiteStore.default_path().parent/'business-audit-leases.db'
    no_links(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = identity(str(workspace)+'\0'+json.dumps(owner,sort_keys=True))
    with closing(sqlite3.connect(path, timeout=2)) as db, db:
        db.execute('CREATE TABLE IF NOT EXISTS leases (scope TEXT PRIMARY KEY, audit TEXT, expires REAL)')
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM leases WHERE expires<?', (time.time(),))
        count = db.execute('SELECT count(*) FROM leases WHERE scope<>?', (key,)).fetchone()[0]
        if count >= 2:
            raise ValueError('BUSINESS_AUDIT_CONCURRENCY_LIMIT')
        db.execute('INSERT OR REPLACE INTO leases VALUES (?,?,?)', (key, audit_id, time.time()+300))


def release(audit_id):
    path = SQLiteStore.default_path().parent/'business-audit-leases.db'
    no_links(path)
    if path.exists():
        with closing(sqlite3.connect(path, timeout=2)) as db, db:
            db.execute('DELETE FROM leases WHERE audit=?', (audit_id,))
