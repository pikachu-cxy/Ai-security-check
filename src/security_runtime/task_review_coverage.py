"""Exact source coverage for whole-line windows and Unicode character pieces.

Character offsets are zero-based and half-open in the already sanitized source.
A fragment is real delivered evidence, but satisfies a line obligation only
after all characters of that immutable line have been delivered.
"""
from __future__ import annotations


SOURCE_FIELDS = ('path', 'file_sha256', 'location_version', 'start_line', 'end_line')
CHAR_FIELDS = ('start_char', 'end_char', 'line_chars')


def evidence_fields(evidence):
    """Validate and retain the exact immutable location of issued evidence."""
    if not isinstance(evidence, dict) or any(key not in evidence for key in SOURCE_FIELDS):
        raise ValueError('Invalid source evidence')
    low, high = evidence['start_line'], evidence['end_line']
    if type(low) is not int or type(high) is not int or not 1 <= low <= high:
        raise ValueError('Invalid evidence range')
    present = [key in evidence for key in CHAR_FIELDS]
    item = {key: evidence[key] for key in SOURCE_FIELDS}
    if any(present):
        if not all(present):
            raise ValueError('Incomplete evidence character range')
        start, end, count = (evidence[key] for key in CHAR_FIELDS)
        if (low != high or any(type(value) is not int for value in (start, end, count))
                or not 0 <= start < end <= count):
            raise ValueError('Invalid evidence character range')
        item.update((key, evidence[key]) for key in CHAR_FIELDS)
    return item


def _merge(spans):
    merged = []
    for low, high in sorted(spans):
        if merged and low <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], high)
        else:
            merged.append([low, high])
    return merged


def complete_spans(items):
    """Return line spans covered in full; callers select one source identity."""
    covered, fragments = [], {}
    for value in items:
        item = evidence_fields(value)
        if 'start_char' not in item:
            covered.append([item['start_line'], item['end_line']])
            continue
        identity = tuple(item[key] for key in SOURCE_FIELDS[:3]) + (item['start_line'],)
        entry = fragments.setdefault(identity, dict(count=item['line_chars'], spans=[]))
        if entry['count'] != item['line_chars']:
            raise ValueError('Evidence fragments disagree on source line length')
        # Inclusive spans let the same small interval merger serve both units.
        entry['spans'].append([item['start_char'], item['end_char'] - 1])
    for identity, entry in fragments.items():
        if _merge(entry['spans']) == [[0, entry['count'] - 1]]:
            covered.append([identity[-1], identity[-1]])
    return _merge(covered)


def first_unread_char(items, line, line_chars):
    """Find a missing code point, or None; callers select one source identity."""
    if type(line) is not int or line < 1 or type(line_chars) is not int or line_chars < 1:
        raise ValueError('Invalid source line character count')
    spans, complete = [], False
    for value in items:
        item = evidence_fields(value)
        if not item['start_line'] <= line <= item['end_line']:
            continue
        if 'start_char' not in item:
            complete = True
        elif item['line_chars'] != line_chars:
            raise ValueError('Evidence fragments disagree on source line length')
        else:
            spans.append([item['start_char'], item['end_char'] - 1])
    if complete:
        return None
    cursor = 0
    for low, high in _merge(spans):
        if low > cursor:
            return cursor
        cursor = max(cursor, high + 1)
    return cursor if cursor < line_chars else None


def adds_read_coverage(items, evidence):
    """A new character renews activity even before its line becomes complete."""
    item = evidence_fields(evidence)
    prior = [value for value in items if all(value[key] == item[key] for key in SOURCE_FIELDS[:3])]
    if 'start_char' in item:
        spans = []
        for value in prior:
            old = evidence_fields(value)
            if not old['start_line'] <= item['start_line'] <= old['end_line']:
                continue
            if 'start_char' not in old:
                return False
            if old['line_chars'] != item['line_chars']:
                raise ValueError('Evidence fragments disagree on source line length')
            spans.append([old['start_char'], old['end_char'] - 1])
        low, high = item['start_char'], item['end_char'] - 1
    else:
        spans = complete_spans(prior)
        low, high = item['start_line'], item['end_line']
    cursor = low
    for start, end in _merge(spans):
        if end < cursor:
            continue
        if start > cursor:
            return True
        cursor = max(cursor, end + 1)
        if cursor > high:
            return False
    return cursor <= high
