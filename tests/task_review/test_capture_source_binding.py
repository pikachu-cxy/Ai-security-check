"""Capture-only structural contracts; no task publication or capture proof."""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import copy
import os
import sqlite3

import pytest

from security_runtime.task_review.capture_source_binding import (
    CONTRACT, SCHEMA_VERSION, SOURCE_RETENTION_DOMAIN, CaptureSourceBinding,
    CaptureSourceBindingError, binding_identity, raw_source_binding,
    source_descriptor, validate_descriptor,
)
from security_runtime.task_review.metadata_store import ReviewMetadataBinding
from security_runtime.task_review.paged_task_store import source_binding as v1_binding
from security_runtime.tasks.snapshot_pages import _binding as old_binding, GC_CONTRACT, GC_POLICY

TASK = 'ts1-' + 'a' * 32
END = 'ts1-' + 'b' * 32
REF = 'ws2-' + 'c' * 32
SOURCE = 'd' * 64
OWNER = dict(host='codex', session='e' * 64)


def baseline():
    return CaptureSourceBinding(TASK, OWNER, 'baseline', TASK)


def test_all_identity_and_descriptor_operations_are_pure_without_review_placeholders(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Pure capture identity performed filesystem or SQLite I/O')
    monkeypatch.setattr(os, 'open', forbidden)
    monkeypatch.setattr(sqlite3, 'connect', forbidden)
    monkeypatch.setattr(Path, 'stat', forbidden)
    monkeypatch.setattr(Path, 'lstat', forbidden)
    model = baseline()
    descriptor = source_descriptor(model, REF, SOURCE)
    payload = validate_descriptor(model, descriptor)
    raw = raw_source_binding(model, SOURCE)
    assert payload == descriptor['capture_source']
    assert payload['contract'] == CONTRACT and payload['schema_version'] == SCHEMA_VERSION
    assert payload['retention_domain'] == raw.retention_domain == SOURCE_RETENTION_DOMAIN
    assert set(binding_identity(model)) == {'task_ref', 'owner', 'field', 'capture_ref', 'representation_version'}
    assert 'revision' not in payload and 'snapshot_id' not in payload and 'mac' not in descriptor


def test_owner_and_return_values_are_detached_and_binding_is_immutable():
    owner = dict(OWNER)
    model = CaptureSourceBinding(TASK, owner, 'baseline', TASK)
    owner['session'] = 'f' * 64
    assert dict(model.owner) == OWNER
    with pytest.raises(TypeError):
        model.owner['host'] = 'cursor'
    with pytest.raises(FrozenInstanceError):
        model.capture_ref = END
    descriptor = source_descriptor(model, REF, SOURCE)
    verified = validate_descriptor(model, descriptor)
    descriptor['capture_source']['owner']['host'] = 'cursor'
    verified['owner']['session'] = 'f' * 64
    detached = binding_identity(model)
    detached['owner']['host'] = 'connection'
    assert binding_identity(model)['owner'] == OWNER
    assert source_descriptor(model, REF, SOURCE)['capture_source']['owner'] == OWNER


def test_slots_are_versioned_and_distinct_from_v1_and_original_gc_domain():
    review = ReviewMetadataBinding(TASK, OWNER, 1, 'real-test-plan-fixture')
    old = old_binding(dict(task_ref=TASK, task_owner=OWNER, contract=GC_CONTRACT,
        capture_policy=GC_POLICY, baseline=dict(redaction_version=3)), 'baseline', SOURCE)
    v1 = v1_binding(review, 'baseline', SOURCE)
    v2 = raw_source_binding(baseline(), SOURCE)
    assert old.task_ref == v1.task_ref == TASK + ':baseline:' + SOURCE
    assert v1.retention_domain == 'TASK_PAGED_REVIEW_V1'
    assert v2.task_ref == 'task-capture-v2:' + TASK + ':baseline:' + TASK + ':' + SOURCE
    assert v2.task_ref != old.task_ref and v2.retention_domain == 'TASK_CAPTURE_SOURCE_V2'


def test_end_versions_with_identical_canonical_source_have_distinct_slots():
    first = CaptureSourceBinding(TASK, OWNER, 'end', END)
    second = replace(first, capture_ref='ts1-' + 'f' * 32)
    left, right = raw_source_binding(first, SOURCE), raw_source_binding(second, SOURCE)
    assert left.task_ref != right.task_ref
    assert left.source_ref == right.source_ref == SOURCE
    assert left.kind == right.kind == 'TASK_END'
    assert left.captured_before_edit is right.captured_before_edit is False
    original = raw_source_binding(baseline(), SOURCE)
    assert original.kind == 'TASK_BEFORE_EDIT' and original.captured_before_edit is True


@pytest.mark.parametrize('changes', [
    dict(task_ref='ts1-invalid'), dict(owner=dict(host=[], session='e' * 64)),
    dict(owner=dict(OWNER, unknown=True)), dict(field='review'),
    dict(capture_ref=END), dict(representation_version=True),
    dict(representation_version=0), dict(representation_version=256),
])
def test_invalid_identity_has_typed_failure(changes):
    values = dict(task_ref=TASK, owner=OWNER, field='baseline', capture_ref=TASK,
                  representation_version=3)
    values.update(changes)
    with pytest.raises(CaptureSourceBindingError) as error:
        CaptureSourceBinding(**values)
    assert error.value.reason_code == 'CAPTURE_SOURCE_BINDING_INVALID'


@pytest.mark.parametrize('changes', [
    dict(contract='task-capture-source-v1'), dict(schema_version=True),
    dict(retention_domain='TASK_PAGED_REVIEW_V1'), dict(ref='ws2-invalid'),
    dict(source='D' * 64), dict(unknown='must-not-be-ignored'),
])
def test_descriptor_rejects_unknown_version_domain_or_unbounded_locator(changes):
    descriptor = source_descriptor(baseline(), REF, SOURCE)
    descriptor['capture_source'].update(changes)
    with pytest.raises(CaptureSourceBindingError) as error:
        validate_descriptor(baseline(), descriptor)
    assert error.value.reason_code == 'CAPTURE_SOURCE_BINDING_INVALID'


@pytest.mark.parametrize('other', [
    CaptureSourceBinding('ts1-' + 'f' * 32, OWNER, 'baseline', 'ts1-' + 'f' * 32),
    CaptureSourceBinding(TASK, dict(host='cursor', session='e' * 64), 'baseline', TASK),
    CaptureSourceBinding(TASK, OWNER, 'end', END),
    CaptureSourceBinding(TASK, OWNER, 'baseline', TASK, 2),
])
def test_valid_foreign_capture_scope_is_rejected_exactly(other):
    with pytest.raises(CaptureSourceBindingError) as error:
        validate_descriptor(baseline(), source_descriptor(other, REF, SOURCE))
    assert error.value.reason_code == 'CAPTURE_SOURCE_BINDING_SCOPE_MISMATCH'


def test_v1_pointer_review_identity_and_unknown_wrapper_are_not_downgraded():
    model = baseline()
    review = ReviewMetadataBinding(TASK, OWNER, 1, 'test-fixture')
    invalid = [dict(ref=REF, source=SOURCE), dict(source_descriptor(model, REF, SOURCE), unknown={})]
    for descriptor in invalid:
        with pytest.raises(CaptureSourceBindingError):
            validate_descriptor(model, descriptor)
    for candidate in [review, binding_identity(model), None]:
        with pytest.raises(CaptureSourceBindingError) as error:
            raw_source_binding(candidate, SOURCE)
        assert error.value.reason_code == 'CAPTURE_SOURCE_BINDING_INVALID'
    descriptor = source_descriptor(model, REF, SOURCE)
    result = validate_descriptor(model, descriptor)
    assert result == copy.deepcopy(descriptor['capture_source'])
