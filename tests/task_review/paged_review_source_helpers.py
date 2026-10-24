"""Synthetic pre-edit source fixtures written directly into the new domain.

No live tree, scanner, Runtime task, native host claim or old capture migration
is involved. The maps/list digest and per-path entries use the existing source
page format, with an independently bound retention domain from first write.
"""
import hashlib

from security_runtime.closeout_state import encode
from security_runtime.snapshot_store import SnapshotStore
from security_runtime.task_review.metadata_store import ReviewMetadataBinding
from security_runtime.task_review.paged_task_store import source_binding
from security_runtime.tasks.snapshot_page_guard import page_guard
from security_runtime.tasks.snapshot_pages import MAPS, LISTS


def pack_review_sources(state, template):
    """Return baseline/end two-key pointers for immutable fixture snapshots."""
    result = {}
    store = SnapshotStore(state.path.parent / 'snapshot-pages',
                          workspace_root=state.root, key=state.key())
    with page_guard(state.path.parent, create=True):
        for field in ('baseline', 'end'):
            snapshot = template[field]
            maps = {key: snapshot.get(key, {}) for key in MAPS}
            lists = {key: snapshot.get(key, []) for key in LISTS}
            source = hashlib.sha256(encode(dict(maps=maps, lists=lists))).hexdigest()
            model = ReviewMetadataBinding(template['task_ref'], template['task_owner'],
                                           1, source, snapshot['redaction_version'])
            binding = source_binding(model, field, source)
            header = store.create(binding)
            if header['state'] != 'SEALED':
                # Test fixtures are immutable and finite from their creation.
                assert header['state'] == 'CAPTURING' and header['entry_count'] == 0
                indices = {key: {name: index for index, name in enumerate(names)}
                           for key, names in lists.items()}
                names = sorted(set().union(*(set(values) for values in [*maps.values(), *lists.values()])))
                cursor, page = header['cursor'], []
                for index, name in enumerate(names):
                    value = dict(maps={key: values[name] for key, values in maps.items() if name in values},
                                 positions={key: values[name] for key, values in indices.items() if name in values})
                    page.append((name, encode(value)))
                    if len(page) == store.batch_budget.files or index == len(names) - 1:
                        header = store.append_page(header['ref'], binding, page,
                            expected_cursor=cursor, cursor=str(index + 1))
                        assert header['state'] != 'WAITING_CAPACITY'
                        cursor, page = header['cursor'], []
                header = store.seal(header['ref'], binding, expected_files=len(names), inventory_complete=True)
            assert header['state'] == 'SEALED'
            result[field] = dict(paged_entries=dict(ref=header['ref'], source=source),
                                 redaction_version=snapshot['redaction_version'])
    return result
