"""Character delivery never silently satisfies an unread source line."""
import copy
import json

import pytest

from security_runtime.task_review.coverage import (
    adds_read_coverage, complete_spans, evidence_fields, first_unread_char,
)
from security_runtime.task_review.plan import (
    build_plan, finalize_plan, record_read, submit_units,
)
from security_runtime.tasks.security import _unread_context
from test_task_review_plan import task


def piece(start, end, *, line=1, count=10, path='main.py', identifier='piece'):
    return dict(evidence_id=identifier, path=path, file_sha256='a' * 64,
                location_version='CURRENT_TASK_END', start_line=line,
                end_line=line, start_char=start, end_char=end, line_chars=count)


def test_character_pieces_require_every_code_point_including_interior_gaps():
    # Offsets describe Unicode characters, independently of UTF-8 byte widths.
    line = '甲😀乙😀丙'
    parts = [piece(0, 2, count=len(line)), piece(3, 5, count=len(line))]
    assert complete_spans(parts) == []
    assert first_unread_char(parts, 1, len(line)) == 2
    assert adds_read_coverage(parts, piece(2, 3, count=len(line)))
    parts.append(piece(2, 3, count=len(line)))
    assert complete_spans(parts) == [[1, 1]]
    assert first_unread_char(parts, 1, len(line)) is None
    assert not adds_read_coverage(parts, piece(1, 4, count=len(line)))


def test_complete_source_windows_and_pieces_merge_only_when_fully_delivered():
    first = piece(0, 10, line=1)
    window = {key: value for key, value in piece(0, 10, line=2).items()
              if key not in {'start_char', 'end_char', 'line_chars'}}
    window['end_line'] = 4
    parts = [first, window, piece(0, 4, line=5)]
    assert complete_spans(parts) == [[1, 4]]
    assert first_unread_char(parts, 3, 10) is None
    parts.append(piece(4, 10, line=5))
    assert complete_spans(parts) == [[1, 5]]


def test_different_source_bindings_cannot_combine_character_coverage():
    left, right = piece(0, 4), piece(4, 10, path='other.py')
    assert complete_spans([left, right]) == []
    assert adds_read_coverage([right], left)
    other_version = dict(right, path='main.py', location_version='BEFORE_TASK')
    assert complete_spans([left, other_version]) == []
    other_hash = dict(right, path='main.py', file_sha256='b' * 64)
    assert complete_spans([left, other_hash]) == []


@pytest.mark.parametrize('changes', [
    dict(end_line=2), dict(start_char=-1), dict(start_char=4, end_char=4),
    dict(start_char=6, end_char=5), dict(end_char=11), dict(line_chars=0),
    dict(start_char=False), dict(end_char=True), dict(line_chars=True),
])
def test_invalid_fragment_offsets_are_rejected(changes):
    with pytest.raises(ValueError):
        evidence_fields(dict(piece(0, 4), **changes))


def test_fragment_metadata_cannot_be_partial_or_disagree_on_line_length():
    incomplete = piece(0, 4)
    del incomplete['end_char']
    with pytest.raises(ValueError, match='Incomplete'):
        evidence_fields(incomplete)
    inconsistent = [piece(0, 4), piece(4, 9, count=9)]
    with pytest.raises(ValueError, match='line length'):
        complete_spans(inconsistent)
    with pytest.raises(ValueError, match='line length'):
        first_unread_char(inconsistent, 1, 10)
    with pytest.raises(ValueError, match='line length'):
        adds_read_coverage([piece(0, 4)], piece(4, 9, count=9))


def prepared():
    record = task({}, {'main.py': ['abcdefghij']},
                  [dict(path='main.py', change='ADDED')])
    unit = build_plan(record, now=1)['units'][0]
    source = unit['required_windows'][0]
    return record, unit, dict(piece(0, 4, identifier='first'),
                              file_sha256=source['file_sha256'], total_lines=1)


def test_plan_and_requested_context_stay_unread_until_final_character_piece():
    record, unit, first = prepared()
    record_read(record, first, now=2)
    assert record['review_ledger']['activity_lease']['last_progress_at'] == 2
    assert submit_units(record, [unit['unit_id']], 'REVIEWED', [], now=3)['coverage'] == 'PARTIAL'
    record['context_requests'] = {'source': dict(
        path=first['path'], file_sha256=first['file_sha256'],
        location_version=first['location_version'], spans=[[1, 1]])}
    record['evidence'] = copy.deepcopy(record['review_plan']['evidence'])
    assert _unread_context(record) == [dict(path='main.py', start_line=1, end_line=1)]
    assert finalize_plan(record, now=4)['coverage'] == 'PARTIAL'

    # Reloading signed JSON must retain the exact partial-character binding.
    record = json.loads(json.dumps(record))
    second = dict(first, evidence_id='second', start_char=4, end_char=7)
    record_read(record, second, now=5)
    assert record['review_ledger']['activity_lease']['last_progress_at'] == 5
    assert finalize_plan(record, now=6)['coverage'] == 'PARTIAL'
    last = dict(first, evidence_id='last', start_char=7, end_char=10)
    record_read(record, last, now=7)
    record['evidence'] = copy.deepcopy(record['review_plan']['evidence'])
    assert _unread_context(record) == []
    assert submit_units(record, [unit['unit_id']], 'REVIEWED', [], now=8)['coverage'] == 'REVIEWED'
    assert finalize_plan(record, now=9)['coverage'] == 'REVIEWED'


def test_duplicate_characters_do_not_renew_activity_and_ids_cannot_rebind():
    record, _, first = prepared()
    record_read(record, first, now=2)
    record_read(record, first, now=3)
    assert record['review_ledger']['activity_lease']['last_progress_at'] == 2
    assert record['review_ledger']['reads'] == 1
    before = copy.deepcopy(record)
    with pytest.raises(ValueError, match='identifier cannot change'):
        record_read(record, dict(first, end_char=5), now=4)
    assert record == before
    with pytest.raises(ValueError, match='line length'):
        record_read(record, dict(first, evidence_id='changed-length',
                                 start_char=4, end_char=9, line_chars=9), now=4)
    assert record == before
