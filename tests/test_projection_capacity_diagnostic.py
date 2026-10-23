"""Actual task finish preserves its result and reports only projection capacity."""
from security_runtime.findings import FindingNormalizer
from security_runtime.tasks.risk_ledger import TaskRiskLedger
from test_task_security import service, begin  # noqa: F401


def test_finish_capacity_retains_result_and_baseline_and_retry_does_not_rescan(service,monkeypatch):
    tasks,root,runtime = service
    ref = begin(service)
    original_baseline = tasks.load(root,ref)['baseline']
    (root/'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    normalizer = FindingNormalizer(root)
    runtime.findings = [normalizer.make(scanner='fixture-only',category='authorization',
        title='Fixture candidate',description='Synthetic capacity boundary',severity='MEDIUM',confidence='MEDIUM',
        file_path='routes.py',line=number + 1,rule_id='fixture-rule-'+str(number)) for number in range(2)]
    import security_runtime.ledger_partitions as partitions
    original_limit = partitions.MAX_ROWS
    monkeypatch.setattr(partitions,'MAX_ROWS',1)
    result = tasks.finish(root,ref)
    sync = result['risk_ledger_sync']
    assert sync['state'] == 'PENDING' and sync['pending']
    assert sync['capacity_failure']['reason_code'] == 'TASK_RISK_LEDGER_ROW_CAPACITY'
    assert sync['capacity_failure']['capacity'] == dict(observed=2,maximum=1)
    assert sync['capacity_failure']['source_result_saved'] is True
    saved = tasks.load(root,ref)
    assert saved['phase'] == 'READY' and len(saved['static']['findings']) == 2
    assert saved['baseline'] == original_baseline and len(runtime.calls) == 1
    assert 'sync_failure' not in saved['ledger_projection']
    assert TaskRiskLedger(tasks.hooks,root).read() == {}
    monkeypatch.setattr(partitions,'MAX_ROWS',original_limit)
    retried = tasks.finish(root,ref)
    assert retried['risk_ledger_sync'] == dict(state='APPLIED',pending=False)
    assert len(TaskRiskLedger(tasks.hooks,root).read(ref)) == 2
    assert len(runtime.calls) == 1 and tasks.load(root,ref)['baseline'] == original_baseline
