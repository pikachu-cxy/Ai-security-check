"""Read-only Git index projection. Never checkout, stash or update the index."""
from __future__ import annotations

import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from .git import GitError
from .hook_state import no_links

MAX_FILES = 10_000
MAX_BYTES = 128_000_000
MAX_FILE_BYTES = 4_000_000


@contextmanager
def index_projection(git):
    before = git._run_bytes('ls-files', '--stage', '-z')
    entries = before.split(b'\0')
    if len(entries) > MAX_FILES + 1:
        raise GitError('INDEX_SNAPSHOT_FILE_BUDGET_EXCEEDED')
    with tempfile.TemporaryDirectory(prefix='runtime-index-') as directory:
        root = Path(directory)
        consumed = 0
        for entry in entries:
            if not entry:
                continue
            try:
                metadata, raw_name = entry.split(b'\t', 1)
                mode, oid, stage = metadata.decode('ascii').split(' ')
                name = raw_name.decode('utf-8')
                path = PurePosixPath(name)
                if (stage != '0' or mode not in {'100644', '100755'} or path.is_absolute()
                    or '..' in path.parts or ':' in name or '\\' in name or path.as_posix() != name):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise GitError('INDEX_ENTRY_UNSUPPORTED') from None
            target = root / name
            no_links(target)
            raw = git._run_bytes('cat-file', 'blob', oid, maximum=MAX_FILE_BYTES)
            consumed += len(raw)
            if consumed > MAX_BYTES:
                raise GitError('INDEX_SNAPSHOT_BYTE_BUDGET_EXCEEDED')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        if git._run_bytes('ls-files', '--stage', '-z') != before:
            raise GitError('INDEX_CHANGED_DURING_SNAPSHOT')
        yield root
        if git._run_bytes('ls-files', '--stage', '-z') != before:
            raise GitError('INDEX_CHANGED_DURING_SCAN')
