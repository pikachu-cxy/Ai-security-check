"""Bounded, root-bound signed records for asynchronous task operations."""
from contextlib import closing, contextmanager
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
from functools import wraps

from ..closeout_state import digest, encode, readonly_uri
from ..hook_state import no_links


class TaskOperationError(ValueError):
    def __init__(self, reason, *, observed=None, limit=None):
        self.reason_code, self.observed, self.limit = reason, observed, limit
        super().__init__(reason)


def operation_failure(error):
    for _ in range(8):
        if isinstance(error, TaskOperationError):
            capacity = error.reason_code in {'TASK_OPERATION_CAPACITY_REQUIRED', 'TASK_OPERATION_DISK_FULL'}
            busy = error.reason_code == 'TASK_OPERATION_BUSY'
            return dict(status='CAPACITY_REQUIRED' if capacity else 'BUSY' if busy else 'INCONCLUSIVE',
                reason_code=error.reason_code, stage='TASK_OPERATION_STORAGE',
                retryable=busy,
                source_modified=False, baseline_recreated=False, original_task_preserved=True,
                security_proof=False, repair_authorized=False,
                capacity=dict(required_bytes=error.observed, limit_bytes=error.limit) if capacity else None,
                message=('结束快照不可用或无法校验，原任务和基线已保留，请保留现场。'
                         if error.reason_code == 'TASK_CLOSEOUT_SNAPSHOT_UNAVAILABLE' else
                         '当前版本不支持这条收尾记录格式，请核对 Runtime 版本并沿原任务继续。'
                         if error.reason_code == 'TASK_CLOSEOUT_FORMAT_UNSUPPORTED' else
                         '任务状态存储暂时繁忙，请沿原任务重试，保留原基线。' if busy else
                         '任务状态记录或磁盘容量不足，原任务和基线已保留；请沿原任务处理容量问题。'
                         if capacity else '任务队列存储格式异常，原任务和基线已保留；请保留现场核对存储，不能清空历史或重建基线。'))
        error = error.__cause__ or error.__context__
        if error is None:
            break
    return None


def storage_errors(function):
    @wraps(function)
    @contextmanager
    def wrapped(self):
        try:
            with function(self) as db:
                yield db
        except sqlite3.Error as error:
            code = (getattr(error, 'sqlite_errorcode', 0) or 0) & 255
            reason = ('TASK_OPERATION_DISK_FULL' if code == sqlite3.SQLITE_FULL else
                      'TASK_OPERATION_BUSY' if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
                      else 'TASK_OPERATION_STORAGE_INVALID')
            raise TaskOperationError(reason) from error
    return wrapped


class SignedRecords:
    max_rows = 128
    max_record_bytes = 4_000_000

    def __init__(self, hooks, root, name, *, now=time.time):
        self.hooks, self.root, self.now = hooks, Path(root).resolve(), now
        self.path = hooks.workspace_directory(self.root) / name

    def _paths(self):
        for path in (self.path, *(Path(str(self.path)+s) for s in ('-journal', '-wal', '-shm'))):
            no_links(path)
            if path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 128_000_000:
                    raise ValueError('Task operation storage unavailable')

    def _key(self):
        path = self.path.parent / 'snapshot.key'
        no_links(path)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError('Task operation key unavailable')
        return key

    @storage_errors
    @contextmanager
    def transaction(self):
        self._paths()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        self._paths()
        with closing(sqlite3.connect(self.path, timeout=2)) as db, db:
            db.execute('PRAGMA trusted_schema=OFF')
            db.execute('PRAGMA synchronous=FULL')
            # Initialize independently: a failed first job must not roll the
            # schema back and leave a zero-byte/unreadable queue behind.
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and 'records' not in tables:
                raise TaskOperationError('TASK_OPERATION_STORAGE_INVALID')
            db.execute('CREATE TABLE IF NOT EXISTS records (key TEXT PRIMARY KEY, data TEXT NOT NULL, mac TEXT NOT NULL)')
            self._require_schema(db)
            db.commit()
            db.execute('BEGIN IMMEDIATE')
            yield db

    def _decode(self, row):
        if row is None:
            return None
        key, raw, mac = row
        if not isinstance(raw, str) or not isinstance(mac, str):
            raise ValueError('Task operation storage limit exceeded')
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('key') != key
                or value.get('workspace') != str(self.root)
                or not hmac.compare_digest(mac, digest(self._key(), value))):
            raise ValueError('Task operation signature mismatch')
        return value

    def _select(self):
        return ('SELECT key, CASE WHEN length(CAST(data AS BLOB))<=' + str(self.max_record_bytes)
                + ' THEN data END, CASE WHEN length(mac)=64 THEN mac END FROM records')

    def _get(self, db, key):
        return self._decode(db.execute(self._select()+' WHERE key=?', (key,)).fetchone())

    def _all(self, db):
        rows = db.execute(self._select()+' ORDER BY rowid LIMIT ?', (self.max_rows+1,)).fetchall()
        if len(rows) > self.max_rows:
            raise ValueError('Task operation capacity exceeded')
        return [self._decode(row) for row in rows]

    def _put(self, db, key, value):
        value = dict(value, key=key, workspace=str(self.root))
        raw = encode(value)
        if len(raw) > self.max_record_bytes:
            raise TaskOperationError('TASK_OPERATION_CAPACITY_REQUIRED',
                                     observed=len(raw), limit=self.max_record_bytes)
        used = db.execute('SELECT coalesce(sum(length(CAST(data AS BLOB))),0) FROM records WHERE key<>?',
                          (key,)).fetchone()[0]
        if used+len(raw) > 96_000_000:
            raise TaskOperationError('TASK_OPERATION_CAPACITY_REQUIRED',
                                     observed=used+len(raw), limit=96_000_000)
        if not self._get(db, key) and db.execute('SELECT count(*) FROM records').fetchone()[0] >= self.max_rows:
            raise ValueError('Task operation capacity exceeded')
        db.execute('INSERT OR REPLACE INTO records VALUES(?,?,?)',
                   (key, raw.decode(), digest(self._key(), value)))
        return value

    def read(self, key):
        self._paths()
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            self._require_schema(db)
            return self._get(db, key)

    def rows(self):
        self._paths()
        if not self.path.exists() or self.path.stat().st_size == 0:
            return []
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            self._require_schema(db)
            return self._all(db)

    @staticmethod
    def _require_schema(db):
        try:
            columns = [r[1] for r in db.execute('PRAGMA table_info(records)')]
        except sqlite3.DatabaseError as error:
            raise TaskOperationError('TASK_OPERATION_STORAGE_INVALID') from error
        if columns != ['key', 'data', 'mac']:
            raise TaskOperationError('TASK_OPERATION_STORAGE_INVALID')
