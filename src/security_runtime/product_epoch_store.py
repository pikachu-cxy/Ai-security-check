"""Private signed product observation graph, atomically published in one DB.

Scope and hash-only observations have separate fixed references and retention
domain. Current and in-flight epochs are conservatively retained; task page GC
does not own this database. No live source is used to repair missing history.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile

from .hook_state import identity, no_links


DOMAIN = 'PRODUCT_EPOCH_GC_V1'
CONTRACT = 'product-epoch-observed-v1'
MAX_DATABASE_BYTES = 128_000_000


class ProductEpochError(ValueError):
    def __init__(self, reason):
        self.reason_code = reason
        super().__init__(reason)


def fail(reason='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
    raise ProductEpochError(reason)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


class ProductEpochStore:
    def __init__(self, hooks, root):
        self.hooks, self.root = hooks, Path(root).absolute()
        no_links(self.root)
        self.root = self.root.resolve(strict=True)
        info = self.root.stat()
        if not stat.S_ISDIR(info.st_mode):
            fail()
        self.root_identity = [info.st_dev, info.st_ino]
        self.workspace_id = identity(os.path.normcase(str(self.root)))
        self.directory = hooks.workspace_directory(self.root) / 'product-epochs'
        if self.directory == self.root or self.directory.is_relative_to(self.root):
            fail('PRODUCT_EPOCH_PRIVATE_DIRECTORY_REQUIRED')
        self.path = self.directory / 'observations.db'
        self.marker = self.directory.parent / 'product-epoch-store.identity'
        self.storage_identity = None
        if self.directory.exists():
            info = self.directory.stat()
            self.storage_identity = [info.st_dev, info.st_ino]
        self.binding = dict(contract=CONTRACT, retention_domain=DOMAIN,
                            workspace_id=self.workspace_id, root_identity=self.root_identity,
                            storage_identity=self.storage_identity)

    def check_root(self):
        try:
            no_links(self.root)
            info = self.root.stat()
            if [info.st_dev, info.st_ino] != self.root_identity or not stat.S_ISDIR(info.st_mode):
                fail()
        except (OSError, ValueError):
            fail()

    def key(self, *, create=False):
        path = self.hooks.workspace_directory(self.root) / 'snapshot.key'
        no_links(path)
        if not path.exists():
            if create and not self.directory.exists():
                return self.hooks.key(self.root)
            fail()
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 32
                or (os.name != 'nt' and info.st_mode & 0o077)):
            fail()
        with path.open('rb') as stream:
            key = stream.read(33)
        if len(key) != 32:
            fail()
        return key

    def _mac(self, key, kind, value):
        return hmac.new(key, encode(dict(binding=self.binding, kind=kind, value=value)), hashlib.sha256).hexdigest()

    def _registry_next(self, key, previous, ref, policy):
        return hmac.new(key, b'product-epoch-registry-v1'+previous.encode()+encode([ref, policy]),
                        hashlib.sha256).hexdigest()

    def check_presence(self):
        no_links(self.marker)
        if self.marker.exists() != self.directory.exists():
            fail()
        if self.directory.exists() and not self.path.exists():
            fail()

    def _verify_marker(self, key):
        no_links(self.marker)
        info = self.marker.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096
                or (os.name != 'nt' and info.st_mode & 0o077)):
            fail()
        with self.marker.open('rb') as stream:
            raw = stream.read(4097)
        try:
            value = json.loads(raw)
            if (set(value) != {'binding', 'mac'} or value['binding'] != self.binding
                    or not hmac.compare_digest(value['mac'], self._mac(key, 'store-marker', self.binding))):
                fail()
        except (ValueError, TypeError, KeyError, UnicodeError):
            fail()

    def _publish_marker(self, key):
        raw = encode(dict(binding=self.binding, mac=self._mac(key, 'store-marker', self.binding)))
        fd, temporary = tempfile.mkstemp(prefix='.product-epoch-', dir=self.directory.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, self.marker, follow_symlinks=False)
        finally:
            Path(temporary).unlink(missing_ok=True)
        fd = os.open(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def decode(self, key, kind, data, mac):
        try:
            if not isinstance(data, bytes) or len(data) > 65536 or not isinstance(mac, str):
                fail()
            value = json.loads(data)
            if not isinstance(value, dict) or not hmac.compare_digest(mac, self._mac(key, kind, value)):
                fail()
            return value
        except (TypeError, ValueError, UnicodeError, RecursionError):
            fail()

    def _paths(self):
        self.check_root()
        for path in (self.directory, self.path,
                     *(Path(str(self.path)+suffix) for suffix in ('-journal', '-wal', '-shm'))):
            no_links(path)
            if path.exists():
                info = path.stat()
                if path == self.directory and self.storage_identity is None:
                    self.storage_identity = [info.st_dev, info.st_ino]
                    self.binding['storage_identity'] = self.storage_identity
                valid = stat.S_ISDIR(info.st_mode) if path == self.directory else (
                    stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                if not valid or (os.name != 'nt' and info.st_mode & 0o077):
                    fail()
                if (path == self.directory and self.storage_identity is not None
                        and [info.st_dev, info.st_ino] != self.storage_identity):
                    fail()

    @contextmanager
    def db(self, *, write=False, create=False):
        self._paths()
        self.check_presence()
        exists = self.path.exists()
        if not exists and (not create or self.directory.exists()):
            fail()
        if write and exists and self.path.stat().st_size > MAX_DATABASE_BYTES:
            fail('PRODUCT_EPOCH_WAITING_CAPACITY')
        if exists:
            # This private store uses rollback journals. Refuse an externally
            # switched WAL format before SQLite can create a read-side SHM file.
            with self.path.open('rb') as stream:
                prefix = stream.read(100)
            if prefix[:16] != b'SQLite format 3\0' or prefix[18:20] != b'\x01\x01':
                fail()
        key = self.key(create=create)
        if not exists:
            self.directory.mkdir(mode=0o700)
            info = self.directory.stat()
            self.storage_identity = [info.st_dev, info.st_ino]
            self.binding['storage_identity'] = self.storage_identity
            self._paths()
            self._publish_marker(key)
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self._verify_marker(key)
        connection = None
        try:
            connection = sqlite3.connect(self.path.as_uri() + ('?mode=rw' if write else '?mode=ro'),
                                         uri=True, timeout=1)
            connection.execute('PRAGMA trusted_schema=OFF')
            if write:
                connection.execute('PRAGMA synchronous=FULL')
                connection.execute('PRAGMA secure_delete=ON')
                pages = connection.execute('PRAGMA page_size').fetchone()[0]
                connection.execute(f'PRAGMA max_page_count={MAX_DATABASE_BYTES//pages}')
                connection.execute('BEGIN IMMEDIATE')
            else:
                connection.execute('PRAGMA query_only=ON')
                connection.execute('BEGIN')
            if not exists:
                connection.execute('CREATE TABLE store_identity (data BLOB,mac TEXT)')
                initial = dict(self.binding, epoch_count=0, epoch_chain='0'*64)
                connection.execute('INSERT INTO store_identity VALUES(?,?)',
                                   (encode(initial), self._mac(key, 'identity', initial)))
                connection.execute('CREATE TABLE epochs (ref TEXT PRIMARY KEY,policy TEXT UNIQUE,data BLOB,mac TEXT)')
                connection.execute('CREATE TABLE directories (epoch TEXT,seq INTEGER,path TEXT,dev INTEGER,ino INTEGER,'
                                   'done INTEGER,data BLOB,mac TEXT,PRIMARY KEY(epoch,seq),'
                                   'UNIQUE(epoch,path),UNIQUE(epoch,dev,ino))')
                connection.execute('CREATE INDEX pending_directories ON directories(epoch,done,seq)')
                connection.execute('CREATE TABLE members (epoch TEXT,seq INTEGER,path TEXT,data BLOB,mac TEXT,'
                                   'PRIMARY KEY(epoch,seq),UNIQUE(epoch,path))')
                connection.execute('CREATE TABLE observations (epoch TEXT,seq INTEGER,path TEXT,data BLOB,mac TEXT,'
                                   'PRIMARY KEY(epoch,seq),UNIQUE(epoch,path))')
            rows = connection.execute('SELECT data,mac FROM store_identity LIMIT 2').fetchall()
            if len(rows) != 1:
                fail()
            registry = self.decode(key, 'identity', *rows[0])
            if (set(registry) != set(self.binding)|{'epoch_count', 'epoch_chain'}
                    or any(registry.get(name) != value for name, value in self.binding.items())):
                fail()
            count, chain = 0, '0'*64
            for ref, policy in connection.execute('SELECT ref,policy FROM epochs ORDER BY rowid'):
                if (not isinstance(ref, str) or re.fullmatch('pe1-[a-f0-9]{32}', ref) is None
                        or not isinstance(policy, str) or re.fullmatch('[a-f0-9]{64}', policy) is None):
                    fail()
                chain = self._registry_next(key, chain, ref, policy)
                count += 1
            if registry['epoch_count'] != count or registry['epoch_chain'] != chain:
                fail()
            yield connection, key
            if write:
                self._paths()
                connection.commit()
        except sqlite3.Error as exc:
            if connection is not None:
                connection.rollback()
            fail('PRODUCT_EPOCH_WAITING_CAPACITY' if getattr(exc, 'sqlite_errorcode', None) == sqlite3.SQLITE_FULL
                 else 'PRODUCT_EPOCH_HISTORY_UNAVAILABLE')
        finally:
            if connection is not None:
                connection.close()

    def load(self, db, key, *, ref=None, policy=None):
        if ref is not None and (not isinstance(ref, str) or re.fullmatch('pe1-[a-f0-9]{32}', ref) is None):
            fail()
        row = db.execute('SELECT ref,policy,data,mac FROM epochs WHERE '+('ref=?' if ref is not None else 'policy=?'),
                         (ref if ref is not None else policy,)).fetchone()
        if row is None:
            return None
        value = self.decode(key, 'epoch', row[2], row[3])
        if (value.get('epoch_ref') != row[0] or value.get('policy_digest') != row[1]
                or value.get('workspace_id') != self.workspace_id or value.get('root_identity') != self.root_identity
                or value.get('contract') != CONTRACT or value.get('retention_domain') != DOMAIN):
            fail()
        for table, count in (('members', value['members']), ('directories', value['directories']),
                             ('observations', value['observed']+value['file_gaps'])):
            if db.execute(f'SELECT count(*) FROM {table} WHERE epoch=?', (row[0],)).fetchone()[0] != count:
                fail()
        if (db.execute('SELECT count(*) FROM directories WHERE epoch=? AND done=1', (row[0],)).fetchone()[0]
                != value['directories_done'] or value['file_cursor'] != value['observed']+value['file_gaps']
                or hashlib.sha256(encode(value['policy'])).hexdigest() != value['policy_digest']):
            fail()
        return value

    def save(self, db, key, header):
        raw = encode(header)
        if len(raw) > 65536:
            fail('PRODUCT_EPOCH_WAITING_CAPACITY')
        prior = db.execute('SELECT policy FROM epochs WHERE ref=?', (header['epoch_ref'],)).fetchone()
        if prior is None:
            registry = self.decode(key, 'identity', *db.execute('SELECT data,mac FROM store_identity').fetchone())
            registry['epoch_count'] += 1
            registry['epoch_chain'] = self._registry_next(key, registry['epoch_chain'], header['epoch_ref'],
                                                        header['policy_digest'])
            db.execute('UPDATE store_identity SET data=?,mac=?',
                       (encode(registry), self._mac(key, 'identity', registry)))
        elif prior[0] != header['policy_digest']:
            fail()
        db.execute('INSERT INTO epochs VALUES(?,?,?,?) ON CONFLICT(ref) DO UPDATE SET data=excluded.data,mac=excluded.mac',
                   (header['epoch_ref'], header['policy_digest'], raw, self._mac(key, 'epoch', header)))

    def row(self, db, key, header, table, *, seq=None, path=None, pending=False):
        if table not in {'members', 'directories', 'observations'}:
            fail()
        sql = f'SELECT seq,path,data,mac FROM {table} WHERE epoch=?'
        parameters = [header['epoch_ref']]
        if seq is not None:
            sql += ' AND seq=?'; parameters.append(seq)
        elif path is not None:
            sql += ' AND path=?'; parameters.append(path)
        elif pending and table == 'directories':
            sql += ' AND done=0 ORDER BY seq LIMIT 1'
        else:
            fail()
        row = db.execute(sql, parameters).fetchone()
        if row is None:
            return None
        value = self.decode(key, table, row[2], row[3])
        if (value.get('epoch_ref') != header['epoch_ref'] or value.get('policy_digest') != header['policy_digest']
                or value.get('seq') != row[0] or value.get('path') != row[1]):
            fail()
        if table == 'directories':
            columns = db.execute('SELECT dev,ino,done FROM directories WHERE epoch=? AND seq=?',
                                 (header['epoch_ref'], row[0])).fetchone()
            if columns is None or [columns[0], columns[1]] != value.get('identity') or bool(columns[2]) != value.get('done'):
                fail()
        return value

    def insert(self, db, key, header, table, payload):
        value = dict(payload, epoch_ref=header['epoch_ref'], policy_digest=header['policy_digest'])
        raw, mac = encode(value), self._mac(key, table, value)
        if len(raw) > 65536:
            fail('PRODUCT_EPOCH_WAITING_CAPACITY')
        if table == 'directories':
            db.execute('INSERT INTO directories VALUES(?,?,?,?,?,?,?,?)',
                       (value['epoch_ref'], value['seq'], value['path'], *value['identity'], int(value['done']), raw, mac))
        elif table in {'members', 'observations'}:
            db.execute(f'INSERT INTO {table} VALUES(?,?,?,?,?)',
                       (value['epoch_ref'], value['seq'], value['path'], raw, mac))
        else:
            fail()

    def finish_directory(self, db, key, header, value):
        value = dict(value, done=True)
        db.execute('UPDATE directories SET done=1,data=?,mac=? WHERE epoch=? AND seq=?',
                   (encode(value), self._mac(key, 'directories', value), value['epoch_ref'], value['seq']))
        header['directories_done'] += 1
