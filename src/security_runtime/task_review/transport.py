"""Readable, version-bound review transport without source or policy decisions.

The coordinator owns locking, source verification and persistence. These helpers
only compact already verified material and describe delivery gaps; a reference or
an omitted duplicate never counts as a newly delivered source line.
"""
from __future__ import annotations

import json

from .coverage import complete_spans


CAPACITY_BASIS = 'PERSISTED_CONTROL_V1'


def packet_bytes(packet):
    return len(json.dumps(packet, ensure_ascii=False).encode('utf-8'))


def record_capacity(record):
    """Check the storage encoding, reserving room for signed-store counters."""
    from ..closeout_state import encode
    from ..tasks.security_state import MAX_RECORD_BYTES, stored_record_projection
    required = len(encode(stored_record_projection(record))) + 4_096
    return dict(required_record_bytes=required, maximum_record_bytes=MAX_RECORD_BYTES,
                fits=required <= MAX_RECORD_BYTES, capacity_basis=CAPACITY_BASIS)


def retry_legacy_capacity(record, *, include_closed=False):
    """Only retry a pre-plan legacy byte diagnosis, never reset delivered work."""
    from .plan import _snapshot
    capacity = record.get('review_capacity') or {}
    return (record.get('phase') in ({'READY', 'INCOMPLETE'} if include_closed else {'READY'})
            and capacity.get('reason_code') == 'TASK_REVIEW_RECORD_CAPACITY'
            and 'capacity_basis' not in capacity
            and capacity.get('source_delivery_started') is False
            and capacity.get('reviewed_unit_count') == 0
            and capacity.get('snapshot_id') == _snapshot(record)
            and not any(record.get(key) for key in
                        ('review_plan', 'review_session', 'evidence', 'review_completion', 'review'))
            and (not record.get('review_ledger') or bool(record.get('pending_review_revision'))))


def delivered_ranges(record, path, file_sha256, location_version, low, high):
    """Return exact unread spans and references to previously sent evidence."""
    matching, references = [], []
    for identifier, item in record.get('evidence', {}).items():
        if (item.get('path'), item.get('file_sha256'), item.get('location_version')) != (
                path, file_sha256, location_version):
            continue
        first, last = item['start_line'], item['end_line']
        if last < low or first > high:
            continue
        matching.append(item)
        references.append(identifier)
    covered = [(max(low, first), min(high, last))
               for first, last in complete_spans(matching)]
    cursor, missing = low, []
    for first, last in sorted(covered):
        if first > cursor:
            missing.append([cursor, first - 1])
        cursor = max(cursor, last + 1)
    if cursor <= high:
        missing.append([cursor, high])
    return missing, references


def duplicate_packet(source_ref, low, high, references):
    """A bounded navigation receipt, never another source/evidence delivery."""
    return dict(status='ALREADY_DELIVERED', source_ref=source_ref,
                requested_range=[low, high], evidence_refs=references[:40],
                evidence_ref_count=len(references), source_lines_delivered=0)


def source_packet(evidence, source_ref, lines, *, requested_high, remaining_ranges=(),
                  registered_source=None, line_truncation=None):
    """Line index is start_line + array index; preserve every source character."""
    low, high = evidence['start_line'], evidence['end_line']
    packet = dict(evidence_id=evidence['evidence_id'], source_ref=source_ref,
                  start_line=low, lines=list(lines[low - 1:high]))
    if 'start_char' in evidence:
        first, last = evidence['start_char'], evidence['end_char']
        packet['lines'] = [lines[low - 1][first:last]]
        packet.update({key: evidence[key] for key in
                       ('start_char', 'end_char', 'line_chars')})
        packet['char_coordinates'] = 'UNICODE_CODEPOINTS_ZERO_BASED_HALF_OPEN'
    # A single continuation range is enough to resume the same original request.
    # The coordinator will subtract existing deliveries again on that request.
    if evidence.get('end_char', 0) < evidence.get('line_chars', 0):
        packet['next_range'] = [low, requested_high]
    elif high < requested_high:
        packet['next_range'] = [high + 1, requested_high]
    if remaining_ranges:
        packet['unread_ranges'] = [list(span) for span in remaining_ranges]
    if registered_source is not None:
        packet['source'] = dict(registered_source)
    if line_truncation:
        packet['line_truncation'] = dict(line_truncation)
    return packet


def terminal_receipt(record):
    """Saving a validated result is independent of evidence delivery allowances."""
    completion = record.get('review_completion') or {}
    return dict(status=record['phase'], task_ref=record['task_ref'], result_saved=True,
                review_required=False, scanner_run=False, source_modified=False,
                repair_authorized=False, result_details_required=True,
                scan_status=record.get('static', {}).get('status'),
                review_progress={key: completion[key] for key in
                                 ('unit_count', 'reviewed_unit_count', 'coverage') if key in completion},
                next_action=dict(tool='get_task_security_review', task_ref=record['task_ref'],
                                 completion_revision=record.get('review_revision', 1),
                                 finding_offset=0, finding_limit=1),
                delivery_contract='INDEPENDENT_TERMINAL_RECEIPT')
