"""Change lists are projections of the same immutable paged end snapshot."""
CONTRACT = 'closeout-change-pages-v1'
FIELD = 'change_index_contract'
MAPS = ('changed_entries', 'unknown_entries')
CONTENT_SOURCE = 'closeout_content_source'


def indexed(snapshot):
    value = snapshot.get(FIELD)
    if value is not None and value != CONTRACT:
        raise ValueError('Unsupported closeout change index')
    return value == CONTRACT


def prepare(root, baseline, end):
    from .security import task_changes
    from .frozen_body_context import baseline_source
    changes, unknown = task_changes(root, baseline, end)
    return dict(end, **{FIELD: CONTRACT, CONTENT_SOURCE: baseline_source(end)},
        changed_entries={v['path']:dict(position=i, change=v['change']) for i,v in enumerate(changes)},
        unknown_entries={path:i for i,path in enumerate(unknown)},
        changed_entry_count=len(changes), unknown_entry_count=len(unknown))


def project(end):
    if not indexed(end):
        raise ValueError('Closeout change index unavailable')
    if CONTENT_SOURCE in end:
        from .frozen_body_context import baseline_source
        from .snapshot_pages import MAPS as SOURCE_MAPS
        if (all(name in end for name in SOURCE_MAPS)
                and baseline_source(end) != end[CONTENT_SOURCE]):
            raise ValueError('Closeout content source differs from fixed end')
    changed, unknown = end['changed_entries'], end['unknown_entries']
    ordered = []
    for path, item in changed.items():
        if (not isinstance(item, dict) or set(item) != {'position', 'change'}
                or type(item['position']) is not int
                or item['change'] not in {'ADDED', 'MODIFIED', 'DELETED'}):
            raise ValueError('Invalid closeout change index')
        ordered.append((item['position'], dict(path=path, change=item['change'])))
    ordered.sort(key=lambda item:item[0])
    if any(type(position) is not int for position in unknown.values()):
        raise ValueError('Invalid closeout change index')
    missing = sorted((position,path) for path,position in unknown.items())
    if ([p for p,_ in ordered] != list(range(len(ordered)))
            or [p for p,_ in missing] != list(range(len(missing)))
            or len(ordered) != end.get('changed_entry_count')
            or len(missing) != end.get('unknown_entry_count')):
        raise ValueError('Incomplete closeout change index')
    return [v for _,v in ordered], [path for _,path in missing]


def compact(record):
    end = record.get('end') or {}
    if not indexed(end) or not all(name in end for name in MAPS):
        return record
    changes, unknown = project(end)
    if ('changes' in record and record['changes'] != changes
            or 'unverified_paths' in record and record['unverified_paths'] != unknown):
        raise ValueError('Task change list differs from fixed end snapshot')
    result = dict(record)
    result.pop('changes', None)
    result.pop('unverified_paths', None)
    return result
