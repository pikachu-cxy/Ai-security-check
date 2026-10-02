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
                db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
                db.execute("CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data TEXT NOT NULL)")
                db.execute('CREATE TABLE IF NOT EXISTS triage_records (id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, cache_key TEXT NOT NULL, data TEXT NOT NULL, UNIQUE(scan_id,finding_id,cache_key))')
                db.execute('CREATE INDEX IF NOT EXISTS triage_cache ON triage_records(cache_key)')

    def _connect(self):
        return sqlite3.connect(self.path)

    def save(self, result: ScanResult) -> None:
        data = result.to_dict()
        with closing(self._connect()) as db:
            with db:
                db.execute("INSERT OR REPLACE INTO scans VALUES (?, ?)", (result.scan_id, json.dumps(data)))
                for finding in data["findings"]:
                    db.execute("INSERT OR REPLACE INTO findings VALUES (?, ?, ?)", (finding["id"], result.scan_id, json.dumps(finding)))

    def get_scan(self, scan_id: str) -> dict | None:
        with closing(self._connect()) as db:
            row = db.execute("SELECT data FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def latest_scan(self, workspace=None):
        with closing(self._connect()) as db:
            rows=db.execute('SELECT data FROM scans ORDER BY rowid DESC').fetchall()
        for row in rows:
            data=json.loads(row[0])
            if workspace is None or Path(data['target_profile']['path']).resolve()==Path(workspace).resolve():
                return data
        return None

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

    def latest_scan(self, workspace):
        # Never offer a global latest alias, even if only one scan exists.
        if workspace is None:
            raise ValueError('A workspace is required for the security summary')
        for row in self._rows('scans', 'SELECT data FROM scans ORDER BY rowid DESC'):
            scan = json.loads(row[0])
            if Path(scan['target_profile']['path']).resolve() == Path(workspace).resolve():
                return scan
        return None

    def triage_records(self, scan_id):
        rows = self._rows('triage_records', 'SELECT data FROM triage_records WHERE scan_id=? ORDER BY id', (scan_id,))
        return {record['finding_id']: record for record in (json.loads(row[0]) for row in rows)}

    def evidence_key(self):
        path = self.path.parent / 'triage-evidence.key'
        if path.is_symlink() or path.is_junction():
            raise ValueError('Invalid local evidence key path')
        with path.open('rb') as stream:
            key = stream.read(33)
        if len(key) != 32:
            raise ValueError('Invalid local evidence key')
        return key
