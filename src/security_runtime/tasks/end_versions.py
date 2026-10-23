"""Persist task-bound end evidence without extending raw scanner input lifetime."""
import uuid


def capture_end(service, root, record):
    from .security import capture
    from .activity import deferred
    from ..source_redaction import task_version
    version = task_version(record)
    kwargs = dict(known_paths=record['baseline'].get('inventory', record['baseline']['hashes']),
                  priority_paths=record.get('end', {}).get('read_priority', ()),
                  redaction_version=version)
    if not deferred(record):
        return capture(root, **kwargs, include_text=False), None
    previous = record.get('end', {})
    # First closeout inventories and stores each body in one pass. Repeated
    # requests need only hashes to reuse already captured immutable evidence.
    preview = capture(root, **kwargs, include_text=False) if previous.get('version_ref') else None
    keys = ('hashes', 'inventory', 'inventory_complete', 'read_limitations', 'redaction_version')
    if preview is not None and all(preview.get(k) == previous.get(k) for k in keys):
        return previous, None
    ref = 'ts1-'+uuid.uuid4().hex
    store = service.end_versions(root)
    with store.writer(ref, redaction_version=version) as writer:
        end = capture(root, **kwargs, preimage_writer=writer)
    if preview is not None and any(preview.get(k) != end.get(k) for k in keys):
        store.discard(ref)
        raise ValueError('Task source changed during end snapshot capture; retain original baseline')
    end['version_ref'] = ref
    return end, ref
