"""Pure, bounded planning of sanitized before/after review windows.

Equal prefixes, suffixes and monotone unique-line anchors avoid a quadratic
whole-file diff. Only small gaps use SequenceMatcher; unresolved large gaps are
kept in full. This module does not read files or grant source/budget authority.
"""
from __future__ import annotations

from bisect import bisect_left
from collections import Counter
from difflib import SequenceMatcher
import re

from .task_preimage_fingerprints import opaque_semantic_lines


CONTEXT_LINES = 3
CONTEXT_JOIN_GAP = 2
LOCAL_MAX_LINES = 2_048
LOCAL_PAIR_BUDGET = 262_144
TOTAL_PAIR_BUDGET = 2_000_000


def _line_count(snapshot, path):
    lines = snapshot.get('texts', {}).get(path)
    if lines is not None:
        return len(lines)
    count = snapshot.get('line_counts', {}).get(path)
    return count if type(count) is int and count >= 0 else None


def _trim(old, new, a, b, c, d):
    while a < b and c < d and old[a] == new[c]:
        a += 1
        c += 1
    while a < b and c < d and old[b - 1] == new[d - 1]:
        b -= 1
        d -= 1
    return a, b, c, d


def _anchors(old, new, a, b, c, d):
    """Return an increasing subsequence of lines unique in both remainders."""
    old_counts, new_counts = Counter(old[a:b]), Counter(new[c:d])
    positions = {new[i]: i for i in range(c, d)
                 if new_counts[new[i]] == 1 and old_counts.get(new[i]) == 1}
    pairs = [(i, positions[old[i]]) for i in range(a, b)
             if old_counts[old[i]] == 1 and old[i] in positions]
    tails, indices, previous = [], [], []
    for index, (_, right) in enumerate(pairs):
        slot = bisect_left(tails, right)
        previous.append(indices[slot - 1] if slot else -1)
        if slot == len(tails):
            tails.append(right)
            indices.append(index)
        else:
            tails[slot], indices[slot] = right, index
    selected = []
    cursor = indices[-1] if indices else -1
    while cursor >= 0:
        selected.append(pairs[cursor])
        cursor = previous[cursor]
    selected.reverse()
    return selected


def _changed_ranges(old, new, budget=None):
    """Describe an exact transformation; ranges are zero-based half-open.

    Anchor selection is O(n log n) with linear storage. Matcher work is bounded
    by both a per-gap product and a cumulative product. Large ambiguous gaps
    consume no matcher work and remain mandatory source in both versions.
    """
    a, b, c, d = _trim(old, new, 0, len(old), 0, len(new))
    if a == b and c == d:
        return []
    anchors = _anchors(old, new, a, b, c, d) if a < b and c < d else []
    ranges = []
    budget = [TOTAL_PAIR_BUDGET] if budget is None else budget
    for left, right in [*anchors, (b, d)]:
        x, y, z, w = _trim(old, new, a, left, c, right)
        size, work = y - x + w - z, (y - x) * (w - z)
        if x != y or z != w:
            if (x < y and z < w and size <= LOCAL_MAX_LINES
                    and work <= LOCAL_PAIR_BUDGET
                    and work <= budget[0]):
                budget[0] -= work
                matcher = SequenceMatcher(None, old[x:y], new[z:w], autojunk=False)
                ranges.extend((x + i, x + j, z + k, z + l)
                              for tag, i, j, k, l in matcher.get_opcodes()
                              if tag != 'equal')
            else:
                ranges.append((x, y, z, w))
        a, c = left + 1, right + 1
    return ranges


def _merge_context(spans):
    merged = []
    for low, high in sorted(spans):
        if merged and low <= merged[-1][1] + CONTEXT_JOIN_GAP + 1:
            merged[-1][1] = max(merged[-1][1], high)
        else:
            merged.append([low, high])
    return merged


def _truncations(snapshot, path):
    value = snapshot.get('text_truncations', {}).get(path, {})
    return value.get('lines', []) if isinstance(value, dict) else []


def _semantic_proof(snapshot, path, lines):
    """Validate only private caller-supplied proof; never reconstruct history."""
    proof = snapshot.get('semantic_proofs', {}).get(path)
    if (not isinstance(proof, dict) or proof.get('version') != 1 or type(proof.get('version')) is not int
            or proof.get('complete') is not True or type(proof.get('line_count')) is not int
            or proof['line_count'] != len(lines) or not isinstance(proof.get('semantic_lines'), dict)):
        return None
    normalized = {}
    for number, value in proof['semantic_lines'].items():
        if (type(number) is str and len(number) <= 10 and number.isascii()
                and number.isdecimal() and str(int(number)) == number):
            number = int(number)
        if (type(number) is not int or not 1 <= number <= len(lines) or number in normalized
                or not isinstance(value, str) or re.fullmatch(r'[a-f0-9]{64}', value) is None):
            return None
        normalized[number] = value
    # Exact maximum-length visible lines are not automatically truncated when
    # native complete proof says otherwise. Only legacy fallback needs that
    # conservative heuristic.
    required = {number for number, line in enumerate(lines, 1)
                if '[REDACTED_LITERAL]' in line or '[REDACTED_SECRET]' in line}
    required.update(_truncations(snapshot, path))
    if not required <= normalized.keys():
        return None
    return normalized


def _line_spans(numbers):
    merged = []
    for number in sorted(set(numbers)):
        if merged and number == merged[-1][1]+1:
            merged[-1][1] = number
        else:
            merged.append([number, number])
    return merged


def _unknown_hidden_lines(old, new, old_proof, new_proof, changed, budget):
    """Find same sanitized instructions whose hidden semantics differ.

    Matching paired tokens first prevents an ordinary insertion from turning
    moved unchanged opaque lines into purported hidden value changes.
    """
    if not old_proof and not new_proof:
        return set(), set()
    old_changed = set(index for a, b, _, _ in changed for index in range(a, b))
    new_changed = set(index for _, _, c, d in changed for index in range(c, d))
    unknown_old, unknown_new = set(), set()
    same_visible = old == new
    left = right = 0
    visible = _changed_ranges(old, new, budget)
    for a, b, c, d in [*visible, (len(old), len(old), len(new), len(new))]:
        for old_index, new_index in zip(range(left, a), range(right, c)):
            if (old_proof.get(old_index+1) != new_proof.get(new_index+1)
                    and (old_index+1 in old_proof or new_index+1 in new_proof)
                    and (same_visible or (old_index in old_changed and new_index in new_changed))):
                unknown_old.add(old_index+1)
                unknown_new.add(new_index+1)
        left, right = b, d
    # A resource-bounded ambiguous diff can deliberately keep a whole block.
    # In that block, cancel matching private semantic identities first. A
    # remaining old/new opaque instruction with the same sanitized form still
    # has unobservable changed semantics, even without exact line alignment.
    for a, b, c, d in changed:
        left_rows, right_rows = {}, {}
        for index in range(a, b):
            if index+1 in old_proof:
                left_rows.setdefault(old[index], []).append(index+1)
        for index in range(c, d):
            if index+1 in new_proof:
                right_rows.setdefault(new[index], []).append(index+1)
        for line in left_rows.keys() & right_rows.keys():
            old_counts = Counter(old_proof[number] for number in left_rows[line])
            new_counts = Counter(new_proof[number] for number in right_rows[line])
            old_remaining, new_remaining = old_counts-new_counts, new_counts-old_counts
            if old_remaining and new_remaining:
                unknown_old.update(number for number in left_rows[line]
                                   if old_proof[number] in old_remaining)
                unknown_new.update(number for number in right_rows[line]
                                   if new_proof[number] in new_remaining)
    return unknown_old, unknown_new


def adaptive_windows(record, change):
    """Return the legacy (windows, gaps) contract using adaptive diff planning.

    Private semantic fingerprints only locate hidden changes. They never prove
    hidden values safe and are never returned in windows or coverage metadata.
    """
    path, kind = change['path'], change['change']
    before, after = record['baseline'], record['end']
    old, new = before.get('texts', {}).get(path), after.get('texts', {}).get(path)
    versions = ([('BEFORE_DELETION', before)] if kind == 'DELETED' else
                [('CURRENT_TASK_END', after)] if kind == 'ADDED' else
                [('BEFORE_TASK', before), ('CURRENT_TASK_END', after)])
    spans, gaps = {}, []
    if kind == 'MODIFIED' and old is not None and new is not None:
        old_proof, new_proof = _semantic_proof(before, path, old), _semantic_proof(after, path, new)
        budget = [TOTAL_PAIR_BUDGET]
        complete = old_proof is not None and new_proof is not None
        if complete:
            changed = _changed_ranges([(line, old_proof.get(index)) for index, line in enumerate(old, 1)],
                                      [(line, new_proof.get(index)) for index, line in enumerate(new, 1)], budget)
            hidden_old, hidden_new = _unknown_hidden_lines(old, new, old_proof, new_proof, changed, budget)
            for version, hidden in (('BEFORE_TASK', hidden_old), ('CURRENT_TASK_END', hidden_new)):
                gaps.extend(dict(reason='SANITIZED_CHANGE_UNOBSERVABLE', path=path,
                                 location_version=version, start_line=low, end_line=high)
                            for low, high in _line_spans(hidden))
        else:
            changed = _changed_ranges(old, new, budget)
        # Missing legacy proofs are not new before evidence. Include every
        # potentially hidden location in both versions, even when another
        # visible hunk would otherwise hide that ambiguity.
        old_opaque = opaque_semantic_lines(old, _truncations(before, path))
        new_opaque = opaque_semantic_lines(new, _truncations(after, path))
        missing = ((old_proof is None and old_opaque) or (new_proof is None and new_opaque))
        raw_changed = before['hashes'].get(path) != after['hashes'].get(path)
        if missing and raw_changed:
            for version, opaque, lines in (('BEFORE_TASK', old_opaque, old), ('CURRENT_TASK_END', new_opaque, new)):
                for low, high in _line_spans(opaque):
                    spans.setdefault(version, []).append([max(1, low-CONTEXT_LINES), min(len(lines), high+CONTEXT_LINES)])
                    gaps.append(dict(reason='SEMANTIC_LINE_PROOF_UNAVAILABLE', path=path,
                                     location_version=version, start_line=low, end_line=high))
        if changed:
            for version, lines, low_index, high_index in (
                    ('BEFORE_TASK', old, 0, 1), ('CURRENT_TASK_END', new, 2, 3)):
                if lines:
                    spans[version] = _merge_context([*spans.get(version, []), *[
                        [max(1, item[low_index] + 1 - CONTEXT_LINES),
                         min(len(lines), max(item[low_index] + 1, item[high_index]) + CONTEXT_LINES)]
                        for item in changed]])
        elif complete:
            spans.setdefault('BEFORE_TASK', [])
            spans.setdefault('CURRENT_TASK_END', [])
    windows = []
    for version, snapshot in versions:
        file_hash = snapshot['hashes'].get(path)
        if not file_hash:
            gaps.append(dict(reason='SOURCE_VERSION_UNAVAILABLE', path=path,
                             location_version=version))
            continue
        count = _line_count(snapshot, path)
        if count == 0:
            continue
        for low, high in spans.get(version, [[1, count]]):
            windows.append(dict(path=path, file_sha256=file_hash,
                                location_version=version, start_line=low, end_line=high))
    return windows, gaps
