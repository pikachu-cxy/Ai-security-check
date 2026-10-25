"""Recover the original signed namespace; never rewrite historical snapshots."""
import hmac
import json
import os
import stat

from .persisted_file_identity import historical_identity_matches


def _private_device_hint(store):
    from .hook_state import no_links
    marker = store.directory.parent/'snapshot-pages.gc.identity'
    lock = store.directory.parent/'snapshot-pages.gc.lock'
    try:
        no_links(marker)
        no_links(lock)
        info = marker.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size > 512 or info.st_uid != os.getuid() or info.st_mode & 0o077):
            return None
        with marker.open('rb') as stream:
            value = json.loads(stream.read(513))
        if (not isinstance(value, dict) or set(value) != {'contract', 'device', 'inode'}
                or value.get('contract') != 'snapshot-page-guard-v1'
                or not historical_identity_matches([value.get('device'), value.get('inode')],
                                                    lock.stat(), anchor=info)):
            return None
        return value['device']
    except (OSError, ValueError, TypeError):
        return None


def resolve(store, reader, marker):
    from .snapshot_store import _fail, SnapshotStoreError
    row = reader._db.execute("SELECT ref,task,CASE WHEN typeof(data)='blob' "
        "AND length(data)<=65536 THEN data END,CASE WHEN typeof(mac)='text' "
        "AND length(mac)=64 THEN mac END FROM captures ORDER BY rowid LIMIT 1").fetchone()
    if row is None:
        _fail('SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH')
    try:
        header = store._decode(row[2], row[3])
    except SnapshotStoreError:
        _fail('SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH')
    binding = header.get('binding')
    if not isinstance(binding, dict) or binding.get('root') != str(store.root):
        _fail('SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH')
    root_identity = binding.get('root_identity')
    anchor, root, directory = store.marker.stat(), store.root.stat(), store.directory.stat()
    if not historical_identity_matches(root_identity, root, anchor=anchor):
        _fail('SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH')
    original = store.root_identity, store.storage_identity
    # The guard may retain the private volume's former mount ID when source and
    # private storage are on different volumes. It is a hint, never authority:
    # every candidate must match the original store MAC exactly.
    for device in dict.fromkeys((root_identity[0], directory.st_dev, _private_device_hint(store))):
        if device is None:
            continue
        storage_identity = [device, directory.st_ino]
        if not historical_identity_matches(storage_identity, directory, anchor=anchor):
            continue
        store.root_identity, store.storage_identity = list(root_identity), storage_identity
        if hmac.compare_digest(marker, store._mac(store._store_identity()).encode()):
            try:
                store._strict_header_row(*row)
            except BaseException:
                store.root_identity, store.storage_identity = original
                raise
            return
    store.root_identity, store.storage_identity = original
    _fail('SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH')
