"""Local persistence effects: facts and version expectations, never edit authority."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path

CONTRACT = 'persistence-effect-v1'
KINDS = {'ASSESSMENT', 'CLEAR_ASSESSMENT', 'MATERIAL_CHANGE'}
VERSION_FIELDS = {'choice_event_id', 'assessment_id', 'choice_revision', 'assessment_revision'}
MAX_EFFECT_BYTES = 32_000

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
        separators=(',', ':')).encode()).hexdigest()

def make_effect(*, kind, source_id, source_revision, workspace, issue_key, expected, payload):
    if (kind not in KINDS or not isinstance(source_id, str) or not 1 <= len(source_id) <= 256
            or type(source_revision) is not int or source_revision < 1
            or not isinstance(issue_key, str) or not 1 <= len(issue_key) <= 200
            or not isinstance(expected, dict) or set(expected) != VERSION_FIELDS
            or not isinstance(payload, dict)):
        raise ValueError('Invalid persistence effect contract')
    value = dict(contract=CONTRACT, kind=kind, source=dict(id=source_id, revision=source_revision),
        workspace=os.path.normcase(str(Path(workspace).resolve())), issue_key=issue_key,
        expected=dict(expected), payload=dict(payload))
    value['payload_sha256'] = digest(value)
    value['event_id'] = 'pe1-'+value['payload_sha256']
    if len(json.dumps(value, ensure_ascii=False).encode()) > MAX_EFFECT_BYTES:
        raise ValueError('Persistence effect capacity exceeded')
    return value

def validate_effect(value):
    if not isinstance(value, dict) or set(value) != {'contract', 'event_id', 'kind', 'source',
            'workspace', 'issue_key', 'expected', 'payload', 'payload_sha256'}:
        raise ValueError('Invalid persistence effect contract')
    source = value.get('source')
    if not isinstance(source, dict) or set(source) != {'id', 'revision'}:
        raise ValueError('Invalid persistence effect source')
    canonical = make_effect(kind=value['kind'], source_id=source['id'], source_revision=source['revision'],
        workspace=value['workspace'], issue_key=value['issue_key'], expected=value['expected'], payload=value['payload'])
    if value != canonical:
        raise ValueError('Persistence effect identity mismatch')
    return value
