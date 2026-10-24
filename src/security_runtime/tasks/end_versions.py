"""Persist task-bound end evidence without extending raw scanner input lifetime."""
import uuid


def discard_unreferenced(service, root, task_ref, *candidates):
    """Best-effort cleanup; task and queue references win over late callers."""
    from .closeout_queue import CloseoutQueue, CONTRACT, PENDING, TERMINAL
    from .frozen_end_context import _ref
    from .ownership import valid_owner
    try:
        owner = service._owner()
        if (not valid_owner(owner) or not _ref(task_ref) or len(candidates) > 2
                or any(ref is not None and not _ref(ref) for ref in candidates)):
            return
        with service.hooks.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                return
            head = service.store(root)._frozen_body_record(task_ref, owner=owner)
            queued = CloseoutQueue(service.hooks, root, now=service.now).read(task_ref)
            protected = set()
            current = head.get('end')
            if current is not None:
                if not isinstance(current, dict) or not _ref(current.get('version_ref')):
                    return
                protected.add(current['version_ref'])
            if queued is not None:
                if (queued.get('contract') != CONTRACT or queued.get('task_ref') != task_ref
                        or queued.get('owner') != owner or queued.get('state') not in PENDING | TERMINAL
                        or not isinstance(queued.get('end'), dict)
                        or not _ref(queued['end'].get('version_ref'))):
                    return
                protected.add(queued['end']['version_ref'])
            store = service.end_versions(root)
            for ref in set(candidates) - protected - {None}:
                store.discard(ref)
    except Exception:
        # Never replace the original publication/result exception with cleanup
        # failure. Uncertain references keep their existing body TTL and quota.
        return


def capture_end(service, root, record):
    from .snapshot_pages import batched
    from .security import capture
    from .activity import deferred
    from ..source_redaction import task_version
    version = task_version(record)
    kwargs = dict(known_paths=record['baseline'].get('inventory', record['baseline']['hashes']),
                  priority_paths=record.get('end', {}).get('read_priority', ()),
                  batched_files=batched(record),
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
    from .frozen_body_context import PROFILE, PROFILE_FIELD, root_identity
    from .ownership import record_owner, valid_owner
    frozen_root = None
    if (getattr(service, 'frozen_body_contexts', False) and record.get(PROFILE_FIELD) == PROFILE
            and record.get('native_repair') is None and batched(record) and valid_owner(record_owner(record))):
        from .frozen_end_context import _parent
        _parent(service.hooks, root, record, service.now)
        _, frozen_root = root_identity(root)
    ref = 'ts1-'+uuid.uuid4().hex
    store = service.end_versions(root)
    with store.writer(ref, redaction_version=version,
                      paged=batched(record)) as writer:
        end = capture(root, **kwargs, preimage_writer=writer)
    if preview is not None and any(preview.get(k) != end.get(k) for k in keys):
        store.discard(ref)
        raise ValueError('Task source changed during end snapshot capture; retain original baseline')
    end['version_ref'] = ref
    if frozen_root is not None:
        from .frozen_end_context import build_end_context, END_CONTEXT_FIELD
        try:
            end[END_CONTEXT_FIELD] = build_end_context(service.hooks, root, end,
                writer=writer, parent_record=record, expected_root_identity=frozen_root, now=service.now)
        except BaseException:
            try:
                store.discard(ref)
            except (OSError, ValueError):
                pass  # Preserve the original failure; original TTL/quota still applies.
            raise
    return end, ref
