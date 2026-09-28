from __future__ import annotations

import json
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
    def __init__(self, path: Path | None = None):
        self.path = path or Path.cwd() / ".security-runtime" / "scans.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            with db:
                db.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
                db.execute("CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data TEXT NOT NULL)")

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

    def get_finding(self, finding_id: str) -> tuple[dict, dict] | None:
        with closing(self._connect()) as db:
            row = db.execute("SELECT scan_id, data FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        scan = self.get_scan(row[0])
        return json.loads(row[1]), scan
