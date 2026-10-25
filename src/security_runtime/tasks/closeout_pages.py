"""Root/task/owner-bound end pages shared by queue, input and change views."""
from .snapshot_pages import POINTER, pack, unpack, _binding, _store
from .closeout_index import prepare, project, CONTRACT


def scope(record, end):
    from ..source_redaction import task_version
    from .ownership import record_owner
    value = dict(task_ref=record['task_ref'], task_owner=record_owner(record),
        contract=record['contract'], capture_policy=record['capture_policy'],
        baseline=dict(redaction_version=task_version(record)), end=end)
    # Preserve opt-in identity fences without copying the baseline's file maps.
    for name in ('workspace', 'check_policy', 'capture_source_profile',
                 'frozen_body_profile', 'capture_publication'):
        if name in record:
            value[name] = record[name]
    if 'frozen_body_context' in record['baseline']:
        value['baseline']['frozen_body_context'] = record['baseline']['frozen_body_context']
    return value


def freeze(state, record, end):
    indexed = prepare(state.root, record['baseline'], end)
    changes, unknown = project(indexed)
    value = dict(record, end=indexed, changes=changes, unverified_paths=unknown)
    small = pack(state, value)['end']
    return dict(indexed, **{POINTER:small[POINTER]}), small


def restore(state, record, end):
    if POINTER not in end:
        return end
    from ..snapshot_store import SnapshotStoreError
    from .durable import TaskOperationError
    try:
        return unpack(state, scope(record, end))['end']
    except SnapshotStoreError as error:
        if error.reason_code == 'SNAPSHOT_WAITING_CAPACITY':
            raise
        raise TaskOperationError('TASK_CLOSEOUT_SNAPSHOT_UNAVAILABLE') from error


def changes_page(state, record, end, *, after_seq=0, limit=256):
    pointer = end[POINTER]
    page = _store(state).page(pointer['ref'], _binding(record, 'end', pointer['source']),
                             after_seq=after_seq, limit=limit, include_content=True)
    import json
    changes, unknown = [], []
    for entry in page['entries']:
        maps = json.loads(entry['content'])['maps']
        if 'changed_entries' in maps:
            item = maps['changed_entries']
            changes.append(dict(path=entry['path'], change=item['change'], position=item['position']))
        if 'unknown_entries' in maps:
            unknown.append(dict(path=entry['path'], position=maps['unknown_entries']))
    return dict(contract=CONTRACT, changes=changes, unknown=unknown,
        next_cursor=None if page['complete'] else page['next_seq'],
        changed_count=end['changed_entry_count'], unknown_count=end['unknown_entry_count'])
