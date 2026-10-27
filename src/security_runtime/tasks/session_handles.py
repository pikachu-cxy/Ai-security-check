"""Short opaque routing references issued only after native claim validation.

The private, signed record carries the original owner and workspace. A handle
is not an edit grant, and validation never creates keys, records or bindings.
"""
import hashlib
import re
import secrets
import time

from .durable import SignedRecords
from .ownership import SESSION_TTL, session_owner, valid_owner
from ..hook_state import no_links

HANDLE = re.compile(r'sh1-[a-f0-9]{32}')


class SessionHandleError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__('Task session reference is invalid, expired or belongs to another workspace')


def _store(hooks, root, now):
    store = SignedRecords(hooks, root, 'session-routing.db', now=now)
    store.max_rows, store.max_record_bytes = 512, 4096
    return store


def _identity(root):
    no_links(root)
    info = root.stat()
    return [info.st_dev, info.st_ino]


def _key(token):
    return 'handle:'+hashlib.sha256(token.encode()).hexdigest()


def issue_session_handle(hooks, root, host, session, *, now=time.time):
    owner = session_owner(host, session)
    if host not in {'codex', 'cursor'} or not valid_owner(owner):
        raise ValueError('Invalid task session')
    store = _store(hooks, root, now)
    identity = _identity(store.root)
    owner_index = 'owner:'+hashlib.sha256((host+'\0'+owner['session']).encode()).hexdigest()
    hooks.key(store.root)
    with store.transaction() as db:
        # Reuse this exact owner's current handle, never the latest chat.
        index = store._get(db, owner_index)
        if index and index['expires'] - now() > SESSION_TTL / 2:
            row = store._get(db, _key(index['handle']))
            if row and row['owner'] == owner and row['root_identity'] == identity and row['expires'] - now() > SESSION_TTL / 2:
                return index['handle']
        for row in store._all(db):
            if row.get('expires', float('inf')) <= now():
                db.execute('DELETE FROM records WHERE key=?', (row['key'],))
        token = 'sh1-'+secrets.token_hex(16)
        issued = now()
        row = dict(kind='session-route-v1', owner=owner, root_identity=identity,
                   issued=issued, expires=issued+SESSION_TTL)
        store._put(db, _key(token), row)
        store._put(db, owner_index, dict(kind='session-route-index-v1', owner=owner,
                   handle=token, expires=row['expires']))
    return token


def verify_session_handle(hooks, root, token, *, now=None, host=None):
    if not isinstance(token, str) or not HANDLE.fullmatch(token):
        raise SessionHandleError('FORMAT_INVALID')
    instant = time.time() if now is None else now
    store = _store(hooks, root, lambda: instant)
    try:
        keypath = store.path.parent/'snapshot.key'
        no_links(keypath)
        metadata = keypath.stat()
        if metadata.st_size != 32 or metadata.st_nlink != 1:
            raise ValueError('Session key identity unavailable')
        row = store.read(_key(token))
    except (ValueError, OSError):
        raise SessionHandleError('HANDLE_STATE_UNVERIFIED') from None
    if row is None:
        raise SessionHandleError('HANDLE_UNAVAILABLE')
    if (row.get('kind') != 'session-route-v1' or not valid_owner(row.get('owner'))
            or row['owner']['host'] not in {'codex', 'cursor'}
            or row.get('root_identity') != _identity(store.root)
            or type(row.get('issued')) not in (int, float)
            or type(row.get('expires')) not in (int, float)
            or not row['issued'] <= instant < row['expires'] <= row['issued']+SESSION_TTL):
        raise SessionHandleError('HANDLE_UNAVAILABLE')
    if host is not None and row['owner']['host'] != host:
        raise SessionHandleError('OWNER_MISMATCH')
    return row['owner']
