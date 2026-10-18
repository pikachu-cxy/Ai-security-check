"""Read-only Git index projection through the shared private input capture."""
from __future__ import annotations

from contextlib import contextmanager

from .git import GitError
from .scan_input import ScanInputLimits, capture_scan_input, index_inventory
from .scan_request import ScanInputError, ScanRequest, SourceKind

MAX_FILES = 10_000
MAX_BYTES = 128_000_000
MAX_FILE_BYTES = 4_000_000


@contextmanager
def index_projection(git):
    limits = ScanInputLimits(files=MAX_FILES, bytes=MAX_BYTES, file_bytes=MAX_FILE_BYTES)
    try:
        names, revision = index_inventory(git, limits=limits)
        request = ScanRequest(git.root, 'quick', SourceKind.INDEX, names,
                              selection_revision=revision)
        with capture_scan_input(request, git=git, limits=limits) as view:
            yield view.execution_root
            applicability = view.check_current()
            if applicability.state != 'CURRENT':
                raise GitError('INDEX_CHANGED_DURING_SCAN')
    except ScanInputError as error:
        codes = {'SCAN_INPUT_INDEX_ENTRY_UNSUPPORTED': 'INDEX_ENTRY_UNSUPPORTED',
                 'SCAN_INPUT_INDEX_CHANGED': 'INDEX_CHANGED_DURING_SNAPSHOT',
                 'SCAN_INPUT_FILE_COUNT_BUDGET': 'INDEX_SNAPSHOT_FILE_BUDGET_EXCEEDED',
                 'SCAN_INPUT_BYTE_BUDGET': 'INDEX_SNAPSHOT_BYTE_BUDGET_EXCEEDED'}
        raise GitError(codes.get(error.reason_code, error.reason_code)) from None
