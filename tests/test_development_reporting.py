"""Exercise the reporting handoff and its paging on real isolated risk stores."""
import pytest

from test_development_risks import sample, observation


@pytest.fixture(autouse=True)
def config(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(tmp_path/'preferences.toml'))


def test_submission_requires_fresh_read_and_all_pages(sample):
    root, service, ref, risks = sample
    values = []
    for i in range(6):
        value = observation(risks)
        value['issue_key'] = f'issue-{i}'
        values.append(value)
    result = risks.submit(values, 1)
    assert len(result['risks']) == 5 and result['total'] == 6
    action = result['next_action']
    assert action == dict(tool='get_development_risks', arguments=dict(
        check_ref=ref, workspace_path=str(root), offset=0))
    assert result['reporting']['reread_after_review']
    # A disposition saved after submission must be reflected by the fresh read.
    risks.disposition(result['risks'][0]['id'], 'DEFER', True)
    page = risks.get(offset=action['arguments']['offset'])
    assert page['risks'][0]['reminder_suppressed']
    assert page['next_action']['arguments']['offset'] == 5
    before = risks.store.path.read_bytes()
    last = risks.get(offset=page['next_action']['arguments']['offset'])
    assert len(last['risks']) == 1 and last['next_action'] is None
    assert last['next_offset'] is None
    assert risks.store.path.read_bytes() == before
    assert not last['reporting']['host_report_submitted']
    assert last['reporting']['required_sections'] == [
        'problem', 'conditional_impact', 'suggested_fix', 'unknowns']


def test_empty_review_still_routes_to_fresh_read_without_inventing_risks(sample):
    risks = sample[3]
    result = risks.submit([], 1)
    assert result['total'] == 0 and result['next_action']['arguments']['offset'] == 0
    page = risks.get()
    assert page['risks'] == [] and page['next_action'] is None
    assert '无待提醒风险且检查完整' in page['reporting']['instructions']
