from __future__ import annotations

import json
import os
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Protocol

from .models import Finding, ScanResult


class ScanStore(Protocol):
    def save(self, result: ScanResult) -> None: ...
    def get_scan(self, scan_id: str) -> dict | None: ...
    def get_finding(self, finding_id: str) -> tuple[dict, dict] | None: ...


class SQLiteStore:
    @staticmethod
    def default_path() -> Path:
        configured = os.getenv("SECURITY_RUNTIME_STATE_DIR")
        if configured:
            directory = Path(configured)
        elif os.name == "nt" and os.getenv("LOCALAPPDATA"):
            directory = Path(os.environ["LOCALAPPDATA"]) / "AI Security Runtime"
        else:
            directory = Path(os.getenv("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "ai-security-runtime"
        return directory / "scans.db"

    def __init__(self, path: Path | None = None):
        self.path = path if path is not None else self.default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            with db:
                db.execute('BEGIN IMMEDIATE')
                db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
                db.execute("CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data TEXT NOT NULL)")
                db.execute('CREATE TABLE IF NOT EXISTS triage_records (id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, cache_key TEXT NOT NULL, data TEXT NOT NULL, UNIQUE(scan_id,finding_id,cache_key))')
                db.execute('CREATE INDEX IF NOT EXISTS triage_cache ON triage_records(cache_key)')
                db.execute('CREATE TABLE IF NOT EXISTS finding_reviews (id INTEGER PRIMARY KEY, workspace TEXT NOT NULL, scan_id TEXT NOT NULL, data TEXT NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS finding_scope_snapshots (scan_id TEXT, finding_id TEXT, data TEXT NOT NULL, PRIMARY KEY(scan_id,finding_id))')
                from .scan_history_index import initialize, reconcile
                initialize(db)
                reconcile(db)

    def _connect(self):
        return sqlite3.connect(self.path)

    def save(self, result: ScanResult) -> None:
        data = result.to_dict()
        from .finding_scope_snapshot import capture_scopes
        scopes = capture_scopes(data['target_profile']['path'], data['findings'])
        with closing(self._connect()) as db:
            with db:
                db.execute("INSERT OR REPLACE INTO scans VALUES (?, ?)", (result.scan_id, json.dumps(data)))
                db.execute('DELETE FROM finding_scope_snapshots WHERE scan_id=?', (result.scan_id,))
                db.executemany('INSERT INTO finding_scope_snapshots VALUES (?,?,?)',
                    [(result.scan_id, fid, json.dumps(scope)) for fid, scope in scopes.items()])
                for finding in data["findings"]:
                    db.execute("INSERT OR REPLACE INTO findings VALUES (?, ?, ?)", (finding["id"], result.scan_id, json.dumps(finding)))
                from .scan_history_index import reconcile
                reconcile(db)

    def get_scan(self, scan_id: str) -> dict | None:
        with closing(self._connect()) as db:
            row = db.execute("SELECT data FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def latest_scan(self, workspace=None):
        from .scan_history_index import has_pending, latest, reconcile
        with closing(self._connect()) as db:
            if has_pending(db):
                with db:
                    db.execute('BEGIN IMMEDIATE')
                    reconcile(db)
            return latest(db, workspace)

    def save_triage(self, record, cache_key):
        data=record.to_dict()
        with closing(self._connect()) as db:
            with db:
                db.execute('INSERT OR REPLACE INTO triage_records(scan_id,finding_id,cache_key,data) VALUES (?,?,?,?)',
                    (record.scan_id,record.finding_id,cache_key,json.dumps(data)))

    def triage_records(self, scan_id):
        with closing(self._connect()) as db:
            rows=db.execute('SELECT data FROM triage_records WHERE scan_id=? ORDER BY id', (scan_id,)).fetchall()
        return {record['finding_id']:record for record in (json.loads(row[0]) for row in rows)}

    def cached_triage(self, cache_key):
        with closing(self._connect()) as db:
            rows=db.execute('SELECT data FROM triage_records WHERE cache_key=? ORDER BY id DESC',(cache_key,)).fetchall()
        return next((data for data in (json.loads(row[0]) for row in rows) if data['status']=='VALID'),None)

    def evidence_key(self):
        # Local random HMAC key, not an API key. It never enters packets,
        # records, logs or provider requests. Secret changes can invalidate a
        # redacted context without exposing a guessable unkeyed secret hash.
        path=self.path.parent/'triage-evidence.key'
        if path.is_symlink(): raise ValueError('Invalid local evidence key path')
        try:
            descriptor=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor,'wb') as stream: stream.write(secrets.token_bytes(32))
        key=path.read_bytes()
        if len(key)!=32: raise ValueError('Invalid local evidence key')
        return key

    def get_finding(self, finding_id: str) -> tuple[dict, dict] | None:
        with closing(self._connect()) as db:
            row = db.execute("SELECT scan_id, data FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        scan = self.get_scan(row[0])
        return json.loads(row[1]), scan

    def finding_reviews(self, workspace, scan_id):
        return ReadOnlySQLiteStore(self.path).finding_reviews(workspace, scan_id)

    def finding_review_history(self, workspace, scan_id=None):
        return ReadOnlySQLiteStore(self.path).finding_review_history(workspace, scan_id)

    def finding_scope_snapshot(self, scan_id, finding_id):
        return ReadOnlySQLiteStore(self.path).finding_scope_snapshot(scan_id, finding_id)

    def equivalent_finding_references(self, workspace, finding):
        return ReadOnlySQLiteStore(self.path).equivalent_finding_references(workspace, finding)

    def save_finding_reviews(self, workspace, scan_id, records):
        # Append-only audit history. Batch is validated before this transaction;
        # scanner scans/findings and existing AI triage records are untouched.
        with closing(self._connect()) as db:
            with db:
                db.executemany('INSERT INTO finding_reviews(workspace,scan_id,data) VALUES (?,?,?)',
                    [(workspace, scan_id, json.dumps(record)) for record in records])


class ReadOnlySQLiteStore:
    """Existing state only: no schema migration, directory/key creation or writes."""

    def __init__(self, path: Path | None = None):
        self.path = path if path is not None else SQLiteStore.default_path()

    def _rows(self, table: str, query: str, parameters=()):
        if not self.path.is_file():
            return []
        try:
            with closing(sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
                db.execute('PRAGMA query_only=ON')
                if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                    return []
                return db.execute(query, parameters).fetchall()
        except sqlite3.DatabaseError:
            raise ValueError('Existing scan state cannot be read safely; no state was changed') from None

    def get_scan(self, scan_id):
        rows = self._rows('scans', 'SELECT data FROM scans WHERE id=?', (scan_id,))
        return json.loads(rows[0][0]) if rows else None

    def finding_scope_snapshot(self, scan_id, finding_id):
        rows = self._rows('finding_scope_snapshots',
            'SELECT data FROM finding_scope_snapshots WHERE scan_id=? AND finding_id=?',
            (scan_id, finding_id))
        return json.loads(rows[0][0]) if rows else None

    def equivalent_finding_references(self, workspace, finding):
        # Compatibility for scans predating snapshot bindings. Equal line
        # numbers alone never establish identity across different source bytes.
        from .finding_scope_snapshot import observation_signature
        signature = observation_signature(finding)
        if signature is None:
            return []
        references = []
        for row in self._rows('scans', 'SELECT id,data FROM scans ORDER BY rowid DESC'):
            scan = json.loads(row[1])
            if Path(scan['target_profile']['path']).resolve() != Path(workspace).resolve():
                continue
            for old in scan['findings']:
                try:
                    equivalent = observation_signature(old) == signature
                except ValueError:
                    continue
                if equivalent:
                    references.append((row[0], old['id']))
        return references

    def latest_scan(self, workspace):
        # Never offer a global latest alias, even if only one scan exists.
        if workspace is None:
            raise ValueError('A workspace is required for the security summary')
        if not self.path.is_file():
            return None
        from .scan_history_index import latest
        try:
            with closing(sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
                db.execute('PRAGMA query_only=ON')
                return latest(db, workspace)
        except sqlite3.DatabaseError:
            raise ValueError('Existing scan state cannot be read safely; no state was changed') from None

    def triage_records(self, scan_id):
        rows = self._rows('triage_records', 'SELECT data FROM triage_records WHERE scan_id=? ORDER BY id', (scan_id,))
        return {record['finding_id']: record for record in (json.loads(row[0]) for row in rows)}

    def finding_reviews(self, workspace, scan_id):
        rows = self._rows('finding_reviews',
            'SELECT data FROM finding_reviews WHERE workspace=? AND scan_id=? ORDER BY id', (workspace, scan_id))
        values = [json.loads(row[0]) for row in rows]
        return {(r['finding_id'], r['observation_hash']): r for r in values}

    def finding_review_history(self, workspace, scan_id=None):
        # The existing append-only quality log also stores conversational review
        # events. Old databases remain readable without adding tables or keys.
        query = 'SELECT scan_id,data FROM finding_reviews WHERE workspace=?'
        parameters = (workspace,)
        if scan_id is not None:
            query += ' AND scan_id=?'
            parameters += (scan_id,)
        return [dict(json.loads(row[1]), review_scan_id=row[0]) for row in
                self._rows('finding_reviews', query + ' ORDER BY id', parameters)]

    def evidence_key(self):
        path = self.path.parent / 'triage-evidence.key'
        if path.is_symlink() or path.is_junction():
            raise ValueError('Invalid local evidence key path')
        with path.open('rb') as stream:
            key = stream.read(33)
        if len(key) != 32:
            raise ValueError('Invalid local evidence key')
        return key
