"""Acceptance helper calls real v3 services; no installed/native driver execution."""
import asyncio
import copy
import importlib.util
from pathlib import Path

from test_task_security import service, prepared, candidate  # noqa: F401


_path = Path(__file__).resolve().parents[1]/'scripts/task_review_v3_acceptance.py'
_spec = importlib.util.spec_from_file_location('task_review_v3_acceptance', _path)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
V3Review = _module.V3Review


def real_call(sample, calls):
    service, root, _ = sample

    async def call(tool, **arguments):
        calls.append((tool, copy.deepcopy(arguments)))
        assert arguments.pop('workspace_path') == str(root)
        ref = arguments.pop('task_ref')
        if tool == 'get_task_review_plan':
            return service.review_plan(root, ref, arguments.pop('review_session'), **arguments)
        if tool == 'read_task_review_context':
            return service.read(root, ref, arguments.pop('review_session'),
                                arguments.pop('file_path'), **arguments)
        if tool == 'submit_task_review_batch':
            return service.submit_batch(root, ref, arguments.pop('review_session'), **arguments)
        if tool == 'submit_task_security_review':
            return service.submit(root, ref, arguments.pop('review_session'), **arguments)
        if tool == 'get_task_security_review':
            return service.get(root, ref, **arguments)
        raise AssertionError('Unexpected helper operation: '+tool)

    return call


def test_real_plan_pages_source_continuations_and_duplicate_ids(service):
    s, root, runtime = service
    ref = s.begin(root, 'acceptance-navigation')['task_ref']
    baseline = copy.deepcopy(s.load(root, ref)['baseline'])
    for index in range(12):
        body = ''.join(f'value_{line} = source_{line}\n' for line in range(220)) if index == 0 else 'value = source\n'
        (root/f'flow{index:02}.py').write_text(body)
    packet = s.prepare(root, ref, protocol_version=3)
    calls = []
    review = V3Review(real_call(service, calls), ref, packet['review_session'], root)

    async def exercise():
        units = await review.plan()
        assert len(units) == 12
        assert sum(tool == 'get_task_review_plan' for tool, _ in calls) > 1
        assert not s.load(root, ref)['evidence']  # Navigation did not issue source proof.
        first = await review.read('flow00.py', 1, 80)
        before = copy.deepcopy(s.load(root, ref)['review_ledger'])
        duplicate = await review.read('flow00.py', 1, 80)
        after = s.load(root, ref)['review_ledger']
        assert duplicate == first
        assert review.deliveries[-1]['status'] == 'ALREADY_DELIVERED'
        assert after['source_bytes'] == before['source_bytes'] and after['reads'] == before['reads']
        assert after['navigation_bytes'] > before['navigation_bytes']
        delivered_before_overlap = len(review.deliveries)
        await review.read('flow00.py', 40, 120)
        overlap = review.deliveries[delivered_before_overlap:]
        assert overlap[0]['start_line'] == 81
        assert [line for page in overlap for line in range(
            page['start_line'], page['start_line']+len(page['lines']))] == list(range(81, 121))
        issued = await review.read('flow00.py')
        record = s.load(root, ref)
        assert all(identifier in record['evidence'] for identifier in issued)
        spans = sorted((item['start_line'], item['end_line']) for item in record['evidence'].values()
                       if item['path'] == 'flow00.py')
        covered = [line for first, last in spans for line in range(first, last+1)]
        assert covered == list(range(1, 221)) and len(covered) == len(set(covered))
        assert all(item['status'] == 'PENDING' for item in record['review_plan']['units'])

    asyncio.run(exercise())
    reads = [arguments for tool, arguments in calls if tool == 'read_task_review_context']
    assert reads and all(0 <= item['end_line']-item['start_line'] < 80 for item in reads)
    assert s.load(root, ref)['baseline'] == baseline and len(runtime.calls) == 1


def test_partial_receipt_and_complete_risk_history_pages_keep_choices_and_are_read_only(service):
    s, root, runtime = service
    ref, session, _ = prepared(service)
    calls = []
    review = V3Review(real_call(service, calls), ref, session, root)

    async def exercise():
        await review.plan()
        changed = (await review.read('routes.py', 2, 2))[0]
        related = (await review.read('auth.py', 1, 2))[0]
        findings = [dict(candidate(changed, related), title=f'Fixture risk {index}') for index in range(4)]
        receipt, pages = await review.save_partial(findings,
            ['Fixed host fixture, requested source only; full semantic review was not observed.'])
        assert receipt['status'] == 'COMPLETE' and receipt['result_details_required']
        assert 'findings' not in receipt
        assert len(pages) == 2 and [len(page['findings']) for page in pages] == [3, 1]
        details = [item['detail'] for page in pages for item in page['findings']]
        assert [item['title'] for item in details] == [item['title'] for item in findings]
        assert all(item['details_complete'] for page in pages for item in page['findings'])
        assert all(item['preconditions'] and item['unknowns'] and item['counterevidence'] for item in details)
        choices = [item for page in pages for item in page['risk_choices']]
        assert {item['finding_id'] for item in choices} == {item['id'] for item in details}
        assert all(item['deferred_keeps_risk'] and not item['repair_authorized'] for item in choices)
        assert all(page['host_review']['coverage'] == 'PARTIAL' and not page['repair_authorized'] for page in pages)
        assert all(action['actions'] == ['FIX', 'DEFER'] for page in pages
                   for action in page['reply_plan']['required_actions'])
        stored, raw = copy.deepcopy(s.load(root, ref)), s.store(root).path.read_bytes()
        await review.history()
        assert s.load(root, ref) == stored and s.store(root).path.read_bytes() == raw
        assert all(unit['status'] == 'PARTIAL' for unit in stored['review_plan']['units'])

    asyncio.run(exercise())
    assert len(runtime.calls) == 1
