"""Recover only non-authoritative Hook observations, retaining corrupt bytes.

Readers never repair. Writers serialize an atomic generation pointer; they never
replace the old database, so older processes cannot write into a replacement.
"""
from contextlib import contextmanager, closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from .hook_state import HookStateStore, atomic_bytes, native_io_path, no_links

CONTRACT = 'hook-diagnostic-recovery-v1'
MAX_BYTES = 32_000_000
MAX_GENERATIONS = 3


def corrupt_error(error):
    code = getattr(error, 'sqlite_errorcode', None)
    return isinstance(error, sqlite3.DatabaseError) and type(code) is int and (code & 255) in {
        sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}


def _stamp(path):
    no_links(path)
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES
            or os.name != 'nt' and info.st_uid != os.getuid()):
        raise ValueError('Hook diagnostic storage is not an owned regular file')
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


class DiagnosticHistory:
    def __init__(self, base):
        self.base = Path(base).absolute()
        self.marker = self.base.with_name(self.base.name + '.active.json')

    def descriptor(self):
        no_links(self.marker)
        if not self.marker.exists():
            return None
        if _stamp(self.marker)[2] > 4096:
            raise ValueError('Hook diagnostic generation unavailable')
        value = json.loads(self.marker.read_bytes())
        if (not isinstance(value, dict) or set(value) != {'contract', 'generation', 'database', 'backup'}
                or value['contract'] != CONTRACT or type(value['generation']) is not int
                or not 1 <= value['generation'] <= MAX_GENERATIONS):
            raise ValueError('Hook diagnostic generation unavailable')
        generation = str(value['generation'])
        pattern = re.escape(self.base.name) + r'\.recovered-' + generation + r'-([0-9a-f]{64})\.db'
        match = re.fullmatch(pattern, value['database']) if isinstance(value['database'], str) else None
        if not match or value['backup'] != self.base.name + '.corrupt-' + generation + '-' + match[1] + '.db':
            raise ValueError('Hook diagnostic generation unavailable')
        return value

    def path(self):
        descriptor = self.descriptor()
        path = native_io_path(self.base.with_name(descriptor['database']) if descriptor else self.base)
        no_links(path)
        if descriptor:
            _stamp(path)  # Missing published history never falls back to the original database.
        return path

    def facts(self):
        value = self.descriptor()
        if value is None:
            return None
        backup = self.base.with_name(value['backup'])
        no_links(backup)
        return dict(contract=CONTRACT, status='RECOVERED', generation=value['generation'],
                    previous_history='UNAVAILABLE', corrupt_backup_retained=backup.is_file(),
                    authoritative_state_changed=False)

    @contextmanager
    def writer(self):
        locks = HookStateStore(self.base.parent / '.hook-diagnostic-locks')
        with locks.lock(self.base, wait_seconds=.1) as acquired:
            if not acquired:
                raise sqlite3.OperationalError('Hook diagnostic writer busy')
            yield

    def _snapshot(self, path):
        # A sidecar can hold committed state or another writer's pending work.
        if any(Path(str(path) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')):
            raise ValueError('Hook diagnostic recovery waits for existing SQLite sidecars')
        before = _stamp(path)
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES or _stamp(path) != before:
            raise ValueError('Hook diagnostic storage changed during recovery')
        if raw[:16] == b'SQLite format 3\0' and raw[18:20] != b'\x01\x01':
            raise ValueError('Hook diagnostic journal mode requires separate recovery')
        return raw, before

    @staticmethod
    def _damaged(raw):
        if not raw:
            return False  # SQLite accepts an empty, not-yet-initialized database.
        try:
            with closing(sqlite3.connect(':memory:')) as db:
                db.deserialize(raw)
                db.execute('PRAGMA trusted_schema=OFF')
                db.execute('PRAGMA query_only=ON')
                return db.execute('PRAGMA quick_check(1)').fetchall() != [('ok',)]
        except sqlite3.DatabaseError as error:
            if corrupt_error(error) or len(raw) < 100 or raw[:16] != b'SQLite format 3\0':
                return True
            raise

    def repair_locked(self, initialize):
        path = self.path()
        if not path.exists():
            return dict(status='NOT_INSTALLED', state_modified=False, security_proof=False)
        raw, before = self._snapshot(path)
        if not self._damaged(raw):
            return dict(status='NOT_NEEDED', state_modified=False, security_proof=False)
        previous = self.descriptor()
        generation = (previous['generation'] if previous else 0) + 1
        if generation > MAX_GENERATIONS:
            raise ValueError('Hook diagnostic recovery generation budget exhausted')
        identity = hashlib.sha256(raw).hexdigest()
        backup = native_io_path(self.base.with_name(f'{self.base.name}.corrupt-{generation}-{identity}.db'))
        target = native_io_path(self.base.with_name(f'{self.base.name}.recovered-{generation}-{identity}.db'))
        no_links(backup)
        if not backup.exists():
            fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        if _stamp(backup)[2] != len(raw) or backup.read_bytes() != raw:
            raise ValueError('Hook diagnostic backup cannot be verified')
        no_links(target)
        if target.exists():
            _stamp(target)  # Resume only this deterministic, private replacement after interrupted publication.
        initialize(target)
        if _stamp(path) != before or self.descriptor() != previous:
            raise ValueError('Hook diagnostic storage changed before publication')
        if any(Path(str(path) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')):
            raise ValueError('Hook diagnostic writer appeared before publication')
        descriptor = dict(contract=CONTRACT, generation=generation, database=target.name, backup=backup.name)
        atomic_bytes(self.marker, json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode())
        return dict(self.facts(), state_modified=True, backup_path=str(backup),
                    scanner_run=False, source_modified=False, security_proof=False)
