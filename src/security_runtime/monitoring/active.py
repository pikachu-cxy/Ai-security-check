"""Private expiring observation leases; never change shared collection settings."""
import hashlib
import hmac
import json
import time
from contextlib import closing

from ..hook_state import atomic_bytes, no_links


def _path(store, owner):
    from ..task_ownership import valid_owner
    if not valid_owner(owner) or owner['host'] not in {'codex', 'cursor'}:
        raise ValueError('MONITOR_OWNER_INVALID')
    key = store._key()
    selector = store._digest(key, 'chat', owner['host'] + ':' + owner['session'])
    return store.path.parent / 'monitoring' / (selector + '.active'), key


def register(store, owner, monitor_id):
    db, _ = store._connect(write=True)
    with closing(db):
        pass
    path, key = _path(store, owner)
    payload = dict(id=monitor_id, expires=time.time() + 8 * 60 * 60)
    raw = json.dumps(payload, sort_keys=True).encode()
    atomic_bytes(path, json.dumps(dict(payload=payload,
        mac=hmac.new(key, raw, hashlib.sha256).hexdigest())).encode())


def enabled(store, owner):
    try:
        path, key = _path(store, owner)
        no_links(path)
        if path.stat().st_size > 2048:
            return False
        data = json.loads(path.read_bytes())
        raw = json.dumps(data['payload'], sort_keys=True).encode()
        return (hmac.compare_digest(data['mac'], hmac.new(key, raw, hashlib.sha256).hexdigest())
            and time.time() < data['payload']['expires'] <= time.time() + 8 * 60 * 60)
    except Exception:
        return False


def unregister(store, owner, monitor_id):
    try:
        path, _ = _path(store, owner)
        no_links(path)
        if path.stat().st_size <= 2048 and json.loads(path.read_bytes())['payload']['id'] == monitor_id:
            path.unlink()
    except Exception:
        pass
