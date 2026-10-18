"""Actual Cursor contexts keep arguments separate from durable receipt facts."""
import json

from security_runtime.cursor_tasks import CursorTaskBridge,DELIVERY_CONTEXT_MARKER
from security_runtime.task_delivery_receipts import TaskDeliveryReceipts
from test_hook_runtime import repo,FakeRuntime,coordinator
from test_cursor_automatic import tool,ingress


def test_post_tool_context_has_durable_prepared_receipt_and_exact_tool_arguments(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime())
    ref=tool(repo,tmp_path,core)[1]['task_ref']
    output,result=ingress(repo,tmp_path,core,'postToolUse',tool_name='Write',tool_use_id='opaque')
    context=output['additional_context']
    args=json.loads(context.splitlines()[1])
    assert set(args)=={'task_ref','workspace_path','session_ref'} and args['task_ref']==ref
    facts=json.loads(context.split(DELIVERY_CONTEXT_MARKER,1)[1])['task_delivery']
    receipt=facts['delivery_receipt']
    assert receipt['response_prepared'] and not receipt['transport_written']
    assert receipt['host_report_submitted']=='NOT_OBSERVED' and receipt['user_consumption']=='UNKNOWN'
    bridge=CursorTaskBridge(core,repo,'private-cursor-conversation','private-generation')
    assert TaskDeliveryReceipts(core.store,repo).get(receipt['delivery_ref'],bridge.owner)==receipt
    assert result['task_delivery']==facts and result['response_prepared']
    assert not core.runtime.calls
    assert not (core.store.workspace_directory(repo)/'host-events.db').exists()


def test_stop_retains_bounded_policy_and_prepared_receipt_is_not_report_receipt(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime());tool(repo,tmp_path,core)
    (repo/'A.java').write_text('task bytes')
    before=ingress(repo,tmp_path,core,'postToolUse',tool_name='Write',tool_use_id='opaque')[1]['task_delivery']['delivery_receipt']
    output,result=ingress(repo,tmp_path,core,'stop')
    receipt=result['task_delivery']['delivery_receipt']
    assert output['followup_message'] and receipt['delivery_ref']!=before['delivery_ref']
    assert receipt['result_version']==before['result_version'] and receipt['response_prepared']
    assert not receipt['transport_written'] and receipt['host_report_submitted']=='NOT_OBSERVED'
    assert receipt['user_consumption']=='UNKNOWN' and not core.runtime.calls
    assert ingress(repo,tmp_path,core,'stop')[0]=={} and ingress(repo,tmp_path,core,'stop',loop_count=1)[0]=={}


def test_receipt_storage_failure_preserves_context_without_claiming_durable_delivery(repo,tmp_path,monkeypatch):
    core=coordinator(tmp_path,FakeRuntime());tool(repo,tmp_path,core)
    monkeypatch.setattr(TaskDeliveryReceipts,'prepare',lambda *a,**k: (_ for _ in ()).throw(OSError('private failure')))
    output,result=ingress(repo,tmp_path,core,'postToolUse',tool_name='Write',tool_use_id='opaque')
    assert 'finish_security_task' in output['additional_context']
    receipt=result['task_delivery']['delivery_receipt']
    assert receipt['recording']=='UNAVAILABLE' and receipt['delivery_ref'] is None
    assert not receipt['response_prepared'] and not receipt['transport_written']
    assert 'private failure' not in json.dumps(output)
