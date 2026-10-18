"""Safe current-source windows and finite obligation-derived delivery accounting."""
from __future__ import annotations

import hashlib
import math

from .local_evidence import WorkspaceReader, safe_source
from .repair_impact_models import (HARD_BYTES, MAX_FILES, RESPONSE_BYTES,
    RepairImpactError, digest, encoded, merge, path, require, uncovered, wire_bytes)


def read_source(reader, name, secret_ranges=(), *, documentation=False):
    name = path(name, documentation=documentation)
    try:
        raw, text = reader.read(name)
        truncated = []
        lines = safe_source(text, secret_ranges, source_path=name, truncation_lines=truncated)
    except (OSError, ValueError, UnicodeError):
        raise RepairImpactError('REPAIR_IMPACT_SOURCE_UNAVAILABLE') from None
    return name, hashlib.sha256(raw).hexdigest(), lines, truncated


def new_ledger():
    return dict(source_bytes=0, navigation_bytes=0, control_bytes=0, reads=0,
                allocations={}, category_limits=dict(source=64_000, navigation=64_000, control=64_000))


def allocate(ledger, windows, source_data):
    """Only genuinely new path/hash/ranges add allowance; retries never reset it."""
    for window in windows:
        name = window['file_path']
        key = digest([name, window['file_sha256']])
        old = ledger['allocations'].get(key, dict(file_path=name, spans=[], bytes=0, frames=0))
        lines = source_data[name][1]
        additions = uncovered(window['start_line'], window['end_line'], old['spans'])
        size = sum(len(encoded(f'{n}: {lines[n-1]}')) + 2
                   for low, high in additions for n in range(low, high+1))
        frames = sum(max(1, math.ceil((high-low+1)/80), math.ceil(
            sum(len(encoded(lines[n-1])) for n in range(low, high+1))/12_000))
                     for low, high in additions)
        ledger['allocations'][key] = dict(file_path=name,
            spans=merge([*old['spans'], *additions]), bytes=old['bytes']+size,
            frames=old['frames']+frames)
    entries = list(ledger['allocations'].values())
    require(len({v['file_path'] for v in entries}) <= MAX_FILES, 'REPAIR_IMPACT_CAPACITY_REQUIRED')
    size, frames = sum(v['bytes'] for v in entries), sum(v['frames'] for v in entries)
    required = dict(source=max(64_000, size*2+32_000),
                    navigation=max(64_000, len(entries)*2_000+32_000),
                    control=max(64_000, frames*3_000+32_000))
    ledger['capacity_required'] = any(required[k] > HARD_BYTES[k] for k in required)
    ledger['category_limits'] = {k: min(HARD_BYTES[k], max(v, ledger['category_limits'][k]))
                                 for k, v in required.items()}


def charge(ledger, packet, category, *, source_bytes=0):
    cost = wire_bytes(packet)
    require(cost <= RESPONSE_BYTES, 'REPAIR_IMPACT_RESPONSE_LIMIT')
    amounts = dict(source=source_bytes,
                   navigation=cost if category == 'navigation' else 0,
                   control=cost-source_bytes if category != 'navigation' else 0)
    for key, amount in amounts.items():
        require(ledger[key+'_bytes']+amount <= ledger['category_limits'][key],
                'REPAIR_IMPACT_'+key.upper()+'_CAPACITY')
    for key, amount in amounts.items():
        ledger[key+'_bytes'] += amount


def unread(record):
    out = []
    for window in record['required_windows']:
        spans = [[item['start_line'], item['end_line']] for item in record['evidence'].values()
                 if item['file_path'] == window['file_path'] and
                 item['file_sha256'] == window['file_sha256']]
        for low, high in uncovered(window['start_line'], window['end_line'], spans):
            out.append(dict(file_path=window['file_path'], start_line=low, end_line=high))
    return out
