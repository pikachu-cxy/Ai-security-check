"""Page large task inventories outside the signed control record.

The caller still receives a compatibility projection for v3 review. Persisted
task heads contain only snapshot references and counters, never large path maps.
Old records without BATCHED_FILES_V1 are byte-for-byte on their existing path.
"""
import hashlib
import json
import re

from ..closeout_state import encode
from ..snapshot_store import SnapshotBinding, SnapshotStore, SnapshotStoreError
from ..source_redaction import task_version
from .ownership import record_owner
from .capture_source_profile import POLICY as SOURCE_POLICY, validate_record


MAPS = ('hashes', 'texts', 'text_truncations', 'preimages', 'text_unavailable', 'line_counts')
LISTS = ('inventory', 'read_priority')
POINTER = 'paged_entries'
GC_CONTRACT = 'task-security-paged-gc-v1'
REVIEW_CONTRACT = 'task-security-paged-review-v1'
GC_POLICY = 'BATCHED_FILES_GC_V1'
POLICIES = frozenset({'BATCHED_FILES_V1', GC_POLICY, SOURCE_POLICY})
MANAGED_POLICIES = frozenset({GC_POLICY, SOURCE_POLICY})


def batched(record):
    return record.get('capture_policy') in POLICIES


def managed(record):
    return (record.get('contract') in {GC_CONTRACT, REVIEW_CONTRACT}
            and record.get('capture_policy') in MANAGED_POLICIES)


def _store(state):
    return SnapshotStore(state.path.parent/'snapshot-pages', workspace_root=state.root, key=state.key())


def _binding(record, field, source):
    return SnapshotBinding(task_ref=record['task_ref']+':'+field+':'+source,
        owner=record_owner(record), source_ref=source, representation_version=task_version(record),
        kind='TASK_BEFORE_EDIT' if field == 'baseline' else 'TASK_END',
        captured_before_edit=field == 'baseline',
        retention_domain='TASK_PAGES_GC_V1' if managed(record) else None)


def snapshot_fields(snapshot):
    from .closeout_index import indexed, MAPS as CHANGE_MAPS
    return (*MAPS, *CHANGE_MAPS) if indexed(snapshot) else MAPS


def snapshot_head(snapshot, pointer):
    """The exact control encoding shared by page writers and capacity checks."""
    fields = (*snapshot_fields(snapshot), *LISTS, POINTER)
    return dict({key: value for key, value in snapshot.items() if key not in fields},
                **{POINTER: pointer})


def control_projection(record):
    """Project already loaded, fixed pages without allocating or writing pages.

    Loading/writing still authenticates the page reference and owner. Here a
    digest check prevents an altered hydrated map from being silently omitted.
    Unpaged snapshots keep their full inline cost, including legacy records.
    """
    validate_record(record)
    if not batched(record):
        return record
    result = dict(record)
    for field in ('baseline', 'end'):
        snapshot = record.get(field)
        if not isinstance(snapshot, dict) or POINTER not in snapshot:
            continue
        pointer = snapshot[POINTER]
        if (not isinstance(pointer, dict) or set(pointer) != {'ref', 'source'}
                or not isinstance(pointer['ref'], str)
                or re.fullmatch(r'ws2-[a-f0-9]{32}', pointer['ref']) is None
                or not isinstance(pointer['source'], str)
                or re.fullmatch(r'[a-f0-9]{64}', pointer['source']) is None):
            raise ValueError('Invalid snapshot page reference')
        fields = snapshot_fields(snapshot)
        if any(name in snapshot for name in (*fields, *LISTS)):
            body = dict(maps={key: snapshot.get(key, {}) for key in fields},
                        lists={key: snapshot.get(key, []) for key in LISTS})
            if hashlib.sha256(encode(body)).hexdigest() != pointer['source']:
                raise ValueError('Snapshot maps differ from fixed page reference')
        result[field] = snapshot_head(snapshot, pointer)
    return result


def pack(state, record):
    if record.get('contract') == REVIEW_CONTRACT:
        raise ValueError('Paged review heads require their atomic task store')
    validate_record(record)
    if not batched(record):
        return record
    if record.get('capture_policy') in MANAGED_POLICIES and not managed(record):
        raise ValueError('Snapshot collection contract mismatch')
    from .closeout_index import compact
    result = dict(compact(record))
    store = None
    for field in ('baseline', 'end'):
        snapshot = record.get(field)
        if not isinstance(snapshot, dict):
            continue
        map_fields = snapshot_fields(snapshot)
        maps = {key:snapshot.get(key, {}) for key in map_fields}
        lists = {key:snapshot.get(key, []) for key in LISTS}
        body = dict(maps=maps, lists=lists)
        source = hashlib.sha256(encode(body)).hexdigest()
        pointer = snapshot.get(POINTER)
        binding = _binding(record, field, source)
        store = store or _store(state)
        if pointer and pointer.get('source') == source:
            header = store.resume(pointer['ref'], binding)
            if header['state'] != 'SEALED':
                raise ValueError('Original snapshot pages are unavailable')
        else:
            header = store.create(binding)
            if header['state'] != 'SEALED':
                # A previous partial save cannot be filled from a changed input.
                # The source digest binds this exact in-memory fixed snapshot.
                indices = {key:{name:index for index,name in enumerate(names)} for key,names in lists.items()}
                names = sorted(set().union(*(set(values) for values in [*maps.values(), *lists.values()])))
                cursor, page = header['cursor'], []
                completed = header['entry_count']
                for index, name in enumerate(names):
                    if index < completed:
                        continue
                    data = dict(maps={key:values[name] for key,values in maps.items() if name in values},
                        positions={key:values[name] for key,values in indices.items() if name in values})
                    page.append((name, encode(data)))
                    if len(page) == store.batch_budget.files or index == len(names)-1:
                        next_cursor = str(index+1)
                        header = store.append_page(header['ref'], binding, page,
                            expected_cursor=cursor, cursor=next_cursor)
                        if header['state'] == 'WAITING_CAPACITY':
                            raise SnapshotStoreError('SNAPSHOT_WAITING_CAPACITY')
                        cursor, page = next_cursor, []
                header = store.seal(header['ref'], binding, expected_files=len(names), inventory_complete=True)
            pointer = dict(ref=header['ref'], source=source)
        result[field] = snapshot_head(snapshot, pointer)
    return result


def unpack(state, record):
    if record.get('contract') == REVIEW_CONTRACT:
        raise ValueError('Paged review heads require their bounded task reader')
    validate_record(record)
    if not batched(record):
        return record
    if record.get('capture_policy') in MANAGED_POLICIES and not managed(record):
        raise ValueError('Snapshot collection contract mismatch')
    result = dict(record)
    store = None
    for field in ('baseline', 'end'):
        snapshot = record.get(field)
        if not isinstance(snapshot, dict) or POINTER not in snapshot:
            continue
        pointer = snapshot[POINTER]
        binding = _binding(record, field, pointer['source'])
        store = store or _store(state)
        header = store.resume(pointer['ref'], binding)
        if header['state'] != 'SEALED':
            raise ValueError('Original snapshot pages are unavailable')
        maps, positions = {key:{} for key in snapshot_fields(snapshot)}, {key:[] for key in LISTS}
        seq = 0
        while True:
            page = store.page(pointer['ref'], binding, after_seq=seq, include_content=True)
            for entry in page['entries']:
                data = json.loads(entry['content'])
                for key, value in data['maps'].items():
                    if key not in maps:
                        raise ValueError('Invalid snapshot page field')
                    maps[key][entry['path']] = value
                for key, index in data['positions'].items():
                    if key not in positions or type(index) is not int or index < 0:
                        raise ValueError('Invalid snapshot page position')
                    positions[key].append((index, entry['path']))
            if page['complete']:
                break
            seq = page['next_seq']
        lists = {}
        for key, values in positions.items():
            ordered = sorted(values)
            if [index for index,_ in ordered] != list(range(len(ordered))):
                raise ValueError('Original snapshot list is incomplete')
            lists[key] = [name for _,name in ordered]
        if hashlib.sha256(encode(dict(maps=maps, lists=lists))).hexdigest() != pointer['source']:
            raise ValueError('Original snapshot pages changed')
        result[field] = dict(snapshot, **maps, **lists)
    from .closeout_index import indexed, project
    if indexed(result.get('end') or {}):
        result['changes'], result['unverified_paths'] = project(result['end'])
    return result
