"""Bounded name discovery for explicit non-Git workspaces; never reads source."""
from __future__ import annotations

import os
from pathlib import Path


def non_git_inventory(root, ignored, *, max_entries, max_directories, max_depth,
                      max_name_bytes):
    """Return observed names and closed limitations without materializing a walk.

    Every entry consumes discovery capacity, including ignored entries. A single
    lookahead can establish that the entry allowance has a tail; its contents are
    never inspected. Unknown tails are explicitly unknown, not an empty remainder.
    Directory handles close before another directory opens or the function exits.
    """
    values = dict(max_entries=max_entries, max_directories=max_directories,
                  max_depth=max_depth, max_name_bytes=max_name_bytes)
    if any(type(value) is not int or value < (0 if key == 'max_depth' else 1)
           for key, value in values.items()):
        raise ValueError('Invalid non-Git inventory capacity')
    root = Path(root).absolute()
    names, limitations = [], []
    try:
        if any(path.is_symlink() or path.is_junction() for path in (root, *root.parents)):
            return [], [dict(reason='LINK_OR_DEPTH_EXCLUDED', path='.')]
        boundary = root.resolve(strict=True)
    except (OSError, RuntimeError):
        return [], [dict(reason='INVENTORY_DIRECTORY_UNAVAILABLE', path='.')]
    pending = [(root, 0)]
    visited = entries = name_bytes = 0

    def budget(reason, limit, used, **details):
        limitations.append(dict(reason=reason, limit=limit, used=used,
                                pending_count_unknown=True, **details))

    while pending:
        directory, depth = pending.pop()
        relative = directory.relative_to(root).as_posix()
        if visited >= max_directories:
            budget('SNAPSHOT_INVENTORY_DIRECTORY_BUDGET', max_directories,
                   visited, path=relative, observed_at_least=visited+1)
            break
        try:
            # Recheck queued directories: an earlier entry check alone cannot
            # protect against replacement by a link while it waits in the queue.
            chain = (directory, *directory.parents)
            if (any(path.is_symlink() or path.is_junction() for path in chain)
                    or not directory.resolve(strict=True).is_relative_to(boundary)):
                limitations.append(dict(reason='LINK_OR_DEPTH_EXCLUDED', path=relative))
                continue
            visited += 1
            with os.scandir(directory) as contents:
                for entry in contents:
                    entries += 1
                    if entries > max_entries:
                        budget('SNAPSHOT_INVENTORY_ENTRY_BUDGET', max_entries,
                               max_entries, observed_at_least=entries)
                        return names, limitations
                    name = (directory/entry.name).relative_to(root).as_posix()
                    try:
                        cost = len(name.encode('utf-8'))
                    except UnicodeError:
                        limitations.append(dict(reason='INVENTORY_PATH_ENCODING_UNSUPPORTED'))
                        continue
                    if name_bytes+cost > max_name_bytes:
                        budget('SNAPSHOT_INVENTORY_NAME_BYTE_BUDGET', max_name_bytes,
                               name_bytes, required=cost)
                        return names, limitations
                    name_bytes += cost
                    if (entry.name in ignored or entry.name == '.test-tmp'
                            or entry.name.startswith('.test-tmp-')):
                        continue
                    try:
                        if (entry.is_symlink() or
                                (getattr(entry, 'is_junction', None) and entry.is_junction())):
                            limitations.append(dict(reason='LINK_OR_DEPTH_EXCLUDED', path=name))
                        elif entry.is_dir(follow_symlinks=False):
                            if depth >= max_depth:
                                limitations.append(dict(reason='LINK_OR_DEPTH_EXCLUDED', path=name))
                            else:
                                pending.append((directory/entry.name, depth+1))
                        else:
                            names.append(name)
                    except OSError:
                        limitations.append(dict(reason='INVENTORY_ENTRY_UNAVAILABLE', path=name))
        except (OSError, RuntimeError):
            limitations.append(dict(reason='INVENTORY_DIRECTORY_UNAVAILABLE', path=relative))
    return names, limitations
