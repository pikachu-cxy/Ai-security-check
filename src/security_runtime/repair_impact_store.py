"""Private transactional metadata storage. Source bodies are never stored here."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3

from .hook_state import no_links
from .closeout_state import readonly_uri
from .repair_impact_models import RepairImpactError, MAX_RECORD_BYTES, encoded


class RepairImpactStore:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        no_links(self.directory)
        self.path = self.directory / 'assessments.sqlite3'
        self.key_path = self.directory / 'integrity.key'
        no_links(self.path)

    def _key(self):
        no_links(self.key_path)
        try:
            key = self.key_path.read_bytes()
        except OSError:
            raise RepairImpactError('REPAIR_IMPACT_STORAGE_UNAVAILABLE') from None
        if len(key) != 32:
            raise RepairImpactError('REPAIR_IMPACT_STORAGE_INTEGRITY')
        return key

    @contextmanager
    def connect(self, *, write=False):
        no_links(self.path)
        db = None
        try:
            if write:
                self.directory.mkdir(parents=True, exist_ok=True)
                no_links(self.directory)
                no_links(self.key_path)
                if self.path.exists() and not self.key_path.is_file():
                    raise RepairImpactError('REPAIR_IMPACT_STORAGE_INTEGRITY')
                try:
                    descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    pass
                else:
                    with os.fdopen(descriptor, 'wb') as stream:
                        stream.write(secrets.token_bytes(32))
                self._key()
                db = sqlite3.connect(self.path, timeout=1)
                db.execute('CREATE TABLE IF NOT EXISTS cycles (id TEXT PRIMARY KEY, record TEXT NOT NULL)')
                db.execute('CREATE TABLE IF NOT EXISTS assessments (id TEXT PRIMARY KEY, cycle_id TEXT NOT NULL, record TEXT NOT NULL)')
                db.execute('CREATE INDEX IF NOT EXISTS impact_cycle ON assessments(cycle_id)')
                db.commit()
                db.execute('BEGIN IMMEDIATE')
            else:
                if not self.path.is_file():
                    raise RepairImpactError('REPAIR_IMPACT_REFERENCE_INVALID')
                self._key()
                # HookStateStore supplies native Windows extended paths. Their
                # prefix must remain a URI path, never an authority component.
                db = sqlite3.connect(readonly_uri(self.path), uri=True, timeout=1)
                db.execute('PRAGMA query_only=ON')
            yield db
            if write:
                db.commit()
        except sqlite3.OperationalError as exc:
            if db is not None:
                db.rollback()
            raise RepairImpactError('REPAIR_IMPACT_BUSY' if 'locked' in str(exc).lower()
                                    else 'REPAIR_IMPACT_STORAGE_UNAVAILABLE') from None
        except sqlite3.DatabaseError:
            if db is not None:
                db.rollback()
            raise RepairImpactError('REPAIR_IMPACT_STORAGE_UNAVAILABLE') from None
        except OSError:
            if db is not None:
                db.rollback()
            raise RepairImpactError('REPAIR_IMPACT_STORAGE_UNAVAILABLE') from None
        except BaseException:
            if db is not None:
                db.rollback()
            raise
        finally:
            if db is not None:
                db.close()

    def load(self, db, table, ref):
        if table not in {'cycles', 'assessments'}:
            raise RepairImpactError('REPAIR_IMPACT_STORAGE_UNAVAILABLE')
        row = db.execute(f'SELECT record FROM {table} WHERE id=?', (ref,)).fetchone()
        if row is None:
            return None
        try:
            if len(row[0].encode()) > MAX_RECORD_BYTES+512:
                raise ValueError('oversized record')
            envelope = json.loads(row[0])
            if not isinstance(envelope, dict) or set(envelope) != {'payload', 'mac'}:
                raise ValueError('unsigned record')
            content = encoded([table, ref, envelope['payload']])
            if not isinstance(envelope['mac'], str) or not hmac.compare_digest(
                    envelope['mac'], hmac.new(self._key(), content, hashlib.sha256).hexdigest()):
                raise ValueError('invalid record signature')
            return envelope['payload']
        except (TypeError, ValueError):
            raise RepairImpactError('REPAIR_IMPACT_STORAGE_INTEGRITY') from None

    def save(self, db, table, ref, record, *, cycle_id=None):
        mac = hmac.new(self._key(), encoded([table, ref, record]), hashlib.sha256).hexdigest()
        content = encoded(dict(payload=record, mac=mac))
        if len(content) > MAX_RECORD_BYTES:
            raise RepairImpactError('REPAIR_IMPACT_STORAGE_CAPACITY')
        if table == 'cycles':
            db.execute('INSERT OR REPLACE INTO cycles VALUES (?,?)', (ref, content.decode()))
        elif table == 'assessments':
            db.execute('INSERT OR REPLACE INTO assessments VALUES (?,?,?)',
                       (ref, cycle_id, content.decode()))
        else:
            raise RepairImpactError('REPAIR_IMPACT_STORAGE_UNAVAILABLE')
