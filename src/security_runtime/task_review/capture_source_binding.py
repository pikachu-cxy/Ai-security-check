"""Pure capture-only identity for the separately versioned V2 source domain.

These internal claims contain no review revision or snapshot ID. A descriptor
is not signed, a task-owner grant, evidence of capture timing, or proof that a
producer published anything. The raw reader must authenticate the expected
binding; future task publication must independently authenticate its parent.
Legacy V1 bindings and two-key pointers are not accepted or migrated here.
"""
from dataclasses import dataclass
import re
from types import MappingProxyType

from ..snapshot_store import SnapshotBinding
from ..tasks.ownership import valid_owner

CONTRACT = 'task-capture-source-v2'
SCHEMA_VERSION = 2
SOURCE_RETENTION_DOMAIN = 'TASK_CAPTURE_SOURCE_V2'
DESCRIPTOR_FIELD = 'capture_source'
_IDENTITY_FIELDS = frozenset({'task_ref', 'owner', 'field', 'capture_ref', 'representation_version'})
_FIELDS = _IDENTITY_FIELDS | {'contract', 'schema_version', 'retention_domain', 'ref', 'source'}


class CaptureSourceBindingError(ValueError):
    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _fail(suffix='INVALID'):
    raise CaptureSourceBindingError('CAPTURE_SOURCE_BINDING_' + suffix)


def _hex(value, prefix, length):
    return (isinstance(value, str) and len(value) == len(prefix) + length
            and value.startswith(prefix) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value[len(prefix):]) is not None)


def _identity(task_ref, owner, field, capture_ref, representation_version):
    try:
        if type(owner) not in {dict, MappingProxyType}:
            _fail()
        owner = dict(owner)
        if (not _hex(task_ref, 'ts1-', 32) or not valid_owner(owner)
                or not isinstance(field, str) or field not in {'baseline', 'end'}
                or not _hex(capture_ref, 'ts1-', 32)
                or field == 'baseline' and capture_ref != task_ref
                or type(representation_version) is not int or not 1 <= representation_version <= 255):
            _fail()
        return dict(task_ref=task_ref, owner=owner, field=field, capture_ref=capture_ref,
                    representation_version=representation_version)
    except (ValueError, TypeError, KeyError):
        _fail()


@dataclass(frozen=True)
class CaptureSourceBinding:
    task_ref: str
    owner: dict
    field: str
    capture_ref: str
    representation_version: int = 3

    def __post_init__(self):
        value = _identity(self.task_ref, self.owner, self.field, self.capture_ref, self.representation_version)
        object.__setattr__(self, 'owner', MappingProxyType(value['owner']))


def binding_identity(binding):
    """Return a detached ordinary dict, without I/O or review placeholders."""
    if type(binding) is not CaptureSourceBinding:
        _fail()
    return _identity(binding.task_ref, binding.owner, binding.field, binding.capture_ref,
                     binding.representation_version)


def raw_source_binding(binding, source):
    value = binding_identity(binding)
    if not _hex(source, '', 64):
        _fail()
    return SnapshotBinding(
        task_ref='task-capture-v2:' + value['task_ref'] + ':' + value['field'] + ':' + value['capture_ref'] + ':' + source,
        owner=value['owner'], source_ref=source, representation_version=value['representation_version'],
        kind='TASK_BEFORE_EDIT' if value['field'] == 'baseline' else 'TASK_END',
        captured_before_edit=value['field'] == 'baseline', retention_domain=SOURCE_RETENTION_DOMAIN)


def source_descriptor(binding, ref, source):
    value = binding_identity(binding)
    if not _hex(ref, 'ws2-', 32) or not _hex(source, '', 64):
        _fail()
    return {DESCRIPTOR_FIELD: dict(value, contract=CONTRACT, schema_version=SCHEMA_VERSION,
        retention_domain=SOURCE_RETENTION_DOMAIN, ref=ref, source=source)}


def validate_descriptor(binding, descriptor):
    """Validate expected capture scope; do not treat this as authentication."""
    expected = binding_identity(binding)
    if type(descriptor) is not dict or set(descriptor) != {DESCRIPTOR_FIELD}:
        _fail()
    value = descriptor[DESCRIPTOR_FIELD]
    if type(value) is not dict:
        _fail()
    value = dict(value)
    if (set(value) != _FIELDS or value.get('contract') != CONTRACT
            or type(value.get('schema_version')) is not int or value['schema_version'] != SCHEMA_VERSION
            or value.get('retention_domain') != SOURCE_RETENTION_DOMAIN
            or not _hex(value.get('ref'), 'ws2-', 32) or not _hex(value.get('source'), '', 64)):
        _fail()
    actual = _identity(*(value[key] for key in
        ('task_ref', 'owner', 'field', 'capture_ref', 'representation_version')))
    if actual != expected:
        _fail('SCOPE_MISMATCH')
    return dict(actual, contract=CONTRACT, schema_version=SCHEMA_VERSION,
                retention_domain=SOURCE_RETENTION_DOMAIN, ref=value['ref'], source=value['source'])
