"""Advance a fresh baseline intent using only its original sealed donor.

Each turn copies one bounded page. Raw commits precede their control checkpoint;
the authenticated target cursor is authoritative after a lost acknowledgement.
Publishing requires a complete canonical verification in the current raw view.
This opt-in SDK is not a live capture, body refresh, or native host assertion.
"""
import os
import stat

from ..hook_state import no_links
from ..snapshot_store import SnapshotStoreError
from ..task_review.capture_source_binding import (CaptureSourceBinding,
    raw_source_binding, source_descriptor)
from ..task_review.snapshot_source import CaptureCanonicalView
from . import capture_publication_store as control
from .snapshot_page_guard import page_guard
from .snapshot_pages import _binding, _store


def status(state, task_ref, *, owner):
    """Read original control state without repairing or advancing anything."""
    head = state._frozen_body_record(task_ref, owner=owner)
    try:
        return control.status(state, task_ref, owner=owner)
    except control.CapturePublicationError as error:
        if (error.reason_code == 'CAPTURE_PUBLICATION_UNAVAILABLE'
                and control.MARKER_FIELD not in head):
            return dict(task_ref=task_ref, state='UNREQUESTED')
        raise


def _cursor(count):
    return 'cp-copy-v1:' + str(count) if count else None


def _target_header(store, binding, current):
    header = store.strict_header(current['target_ref'], binding)
    anchor, saved = current['donor_header'], current['progress']
    count = header['entry_count']
    if (count > anchor['entry_count'] or header['source_bytes'] > anchor['source_bytes']
            or header['cursor'] != _cursor(count)
            or not isinstance(saved, dict) or count < saved['entry_count']
            or header['source_bytes'] < saved['source_bytes']
            or count - saved['entry_count'] > store.batch_budget.files
            or header['source_bytes'] - saved['source_bytes'] > store.batch_budget.bytes
            or (count == saved['entry_count'] and any(header.get(key) != saved[key]
                for key in ('cursor', 'source_bytes', 'root_digest')))
            or (saved['state'] == 'SEALED' and header['state'] != 'SEALED')):
        raise control.CapturePublicationError()
    if (header['state'] == 'SEALED' and (count != anchor['entry_count']
            or header['source_bytes'] != anchor['source_bytes']
            or header.get('coverage_complete') is not True)):
        raise control.CapturePublicationError()
    return header


def _checkpoint(state, task_ref, owner, current):
    return control.checkpoint(state, task_ref, owner=owner, request_id=current['request_id'],
        expected_intent_generation=current['intent_generation'])


def _scratch(state):
    # Only this fixed private child may be created. Never repair caller modes.
    path = state.path.parent / 'capture-publication-scratch'
    no_links(path)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise control.CapturePublicationError('STATE_UNAVAILABLE')
    return path


def _advance(state, task_ref, *, owner):
    initial = status(state, task_ref, owner=owner)
    if initial['state'] in {'UNREQUESTED', 'PUBLISHED'}:
        return initial
    # The original body context is verified on every new turn. No clock, pin,
    # activity, original ledger, or source preimage is refreshed here.
    state.get_frozen_body_context(task_ref, owner=owner)
    store = _store(state)
    with page_guard(state.path.parent, exclusive=True):
        current = control.status(state, task_ref, owner=owner)
        if current['state'] == 'PUBLISHED':
            return current
        binding = CaptureSourceBinding(task_ref, owner, 'baseline', task_ref,
            current['representation_version'])
        raw_binding = raw_source_binding(binding, current['source'])
        if current['target_ref'] is None:
            target = store.create(raw_binding)
            current = control.admit_target(state, task_ref, owner=owner,
                request_id=current['request_id'], expected_intent_generation=current['intent_generation'],
                target_ref=target['ref'])
        header = _target_header(store, raw_binding, current)
        # An append/seal can have committed before its control acknowledgement.
        # Checkpoint its actual header before choosing the next donor page.
        current = _checkpoint(state, task_ref, owner, current)
        if header['state'] != 'SEALED':
            page = store.strict_copy_page(current['donor']['ref'],
                _binding(dict(task_ref=task_ref, task_owner=owner,
                    contract='task-security-paged-gc-v1', capture_policy='BATCHED_FILES_GC_SOURCE_V2',
                    baseline=dict(redaction_version=current['representation_version'])),
                    'baseline', current['source']),
                after_seq=header['entry_count'], limit_files=store.batch_budget.files,
                limit_bytes=store.batch_budget.bytes, expected_header=current['donor_header'])
            if page['entries']:
                header = store.append_page(header['ref'], raw_binding,
                    [(entry['path'], entry['content'], entry['metadata']) for entry in page['entries']],
                    expected_cursor=header['cursor'], cursor=_cursor(page['next_seq']))
                current = _checkpoint(state, task_ref, owner, current)
                if header['state'] == 'WAITING_CAPACITY':
                    return dict(current, state='WAITING_CAPACITY', reason_code='SNAPSHOT_WAITING_CAPACITY')
            if not page['at_end']:
                return current
            header = store.seal(header['ref'], raw_binding,
                expected_files=current['donor_header']['entry_count'], inventory_complete=True)
            current = _checkpoint(state, task_ref, owner, current)
    # Release the exclusive copy/GC fence before opening the immutable view.
    # Keep a shared fence through canonical verification and the TaskDB CAS.
    with page_guard(state.path.parent):
        descriptor = source_descriptor(binding, header['ref'], current['source'])
        with CaptureCanonicalView(store, descriptor, capture_binding=binding,
                                  scratch_directory=_scratch(state)) as verified:
            for attempt in range(3):
                current = control.status(state, task_ref, owner=owner)
                if current['state'] == 'PUBLISHED':
                    return current
                try:
                    control.finalize(state, task_ref, owner=owner, request_id=current['request_id'],
                        expected_generation=current['task_generation'],
                        expected_intent_generation=current['intent_generation'], verified_view=verified)
                    return control.status(state, task_ref, owner=owner)
                except control.CapturePublicationError as error:
                    if error.reason_code != 'CAPTURE_PUBLICATION_CAS_CONFLICT' or attempt == 2:
                        raise


def advance(state, task_ref, *, owner):
    """Expected capacity/busy failures preserve the original ref and progress."""
    from ..task_review.typed_source_scratch import TypedSnapshotSourceError
    from .frozen_body_context import FrozenBodyContextUnavailable
    try:
        return _advance(state, task_ref, owner=owner)
    except (control.CapturePublicationError, SnapshotStoreError, TypedSnapshotSourceError,
            FrozenBodyContextUnavailable) as error:
        reason = error.reason_code
        if not any(word in reason for word in ('WAITING', 'BUSY', 'CAPACITY', 'CAS_CONFLICT')):
            raise
        # A status read may itself be busy. Never fabricate a new reference,
        # cursor or completed count from an unsuccessful checkpoint.
        try:
            current = status(state, task_ref, owner=owner)
        except (control.CapturePublicationError, SnapshotStoreError, FrozenBodyContextUnavailable) as status_error:
            if not any(word in status_error.reason_code for word in ('BUSY', 'WAITING')):
                raise
            current = dict(task_ref=task_ref)
        if current.get('state') == 'PUBLISHED':
            return current
        return dict(current, state='WAITING_CAPACITY' if any(word in reason for word in
            ('WAITING', 'CAPACITY')) else 'RETRY_REQUIRED', reason_code=reason)
