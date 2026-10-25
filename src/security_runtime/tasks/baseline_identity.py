"""Stable original baseline identity across authenticated locator publication.

The extra V2 locator does not change the original content, limits or context.
All other fields, including paged_entries, remain part of the comparison.
"""
import hashlib

from ..closeout_state import encode
from .capture_source_profile import validate_record


def baseline_snapshot(record):
    validate_record(record)
    baseline = record['baseline']
    if 'capture_source' not in baseline:
        return baseline
    return {key: value for key, value in baseline.items() if key != 'capture_source'}


def baseline_fingerprint(record):
    return hashlib.sha256(encode(baseline_snapshot(record))).hexdigest()
