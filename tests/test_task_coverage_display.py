"""Whole-workspace capture failures must not impersonate changed file scope."""
import copy

from security_runtime.reply_adapters import task_facts
from security_runtime.task_coverage import display_limitations, CAPTURE_GAP
from security_runtime.task_security import _coverage_gaps


def record():
    missing = {f'.github/workflows/workflow_{i:03}.yml': 'TASK_PREIMAGE_WORKSPACE_BYTE_BUDGET'
               for i in range(105)}
    missing['website/theme.ts'] = 'TASK_PREIMAGE_WORKSPACE_BYTE_BUDGET'
    limits = [dict(reason=reason, path=path) for path, reason in list(missing.items())[:100]]
    return dict(phase='COMPLETE', changes=[dict(path='website/theme.ts', change='MODIFIED')],
        baseline=dict(text_unavailable=missing), limitations=limits,
        review=dict(coverage='PARTIAL', findings=[], limitations=[]),
        static=dict(status='SUCCESS', coverage='SCOPED', scope_files=['website/theme.ts'], findings=[]))


def test_missing_changed_file_beyond_first_100_is_named_and_state_remains_partial():
    value = record()
    original = copy.deepcopy(value)
    display = display_limitations(value, value['limitations'])
    assert display == [dict(reason=CAPTURE_GAP, count=106, paths=['website/theme.ts'],
                            affected_file_count=1, workspace_capture_only=True)]
    assert 'website/theme.ts' in _coverage_gaps(display)[0]
    facts = task_facts(value)
    assert facts.check.state == 'PARTIAL'
    rendered = str(facts)
    assert 'website/theme.ts' in rendered and '.github/workflows/' not in rendered
    assert value == original  # display cannot modify any closure input


def test_hash_inventory_and_unknown_failures_are_not_collapsed():
    value = record()
    extra = [dict(reason='SOURCE_UNAVAILABLE', path='auth.py'),
             dict(reason='SNAPSHOT_READ_FILE_BUDGET', pending_count=1),
             dict(reason='UNKNOWN_REASON', path='other.py')]
    value['limitations'].extend(extra)
    assert display_limitations(value, value['limitations'])[1:] == extra


def test_no_changed_body_gap_does_not_claim_workspace_capture_is_complete():
    value = record()
    value['changes'] = [dict(path='new.py', change='ADDED')]
    display = display_limitations(value, value['limitations'])
    assert display[0]['paths'] == [] and display[0]['count'] == 106
    assert task_facts(value).check.state == 'PARTIAL'
