"""Only the actual local stdout write+flush records transport success."""
import io
import json
from types import SimpleNamespace

import pytest

from security_runtime import cursor_hook
from security_runtime.cursor_tasks import CursorTaskBridge
from security_runtime.cursor_hook import CursorBindings
from security_runtime.recent_hooks import RecentHookStore
from security_runtime.task_delivery_receipts import DeliveryWriteObserver,TaskDeliveryReceipts
from test_cursor_automatic import tool
from test_cursor_host_adapter import payload
from test_hook_runtime import repo,coordinator,FakeRuntime


class Writer:
    def __init__(self,failure=None):
        self.failure=failure;self.parts=[];self.flushed=False
    def write(self,value):
        if self.failure=='write':raise BrokenPipeError()
        self.parts.append(value)
        return len(value)
    def flush(self):
        if self.failure=='flush':raise OSError()
        self.flushed=True


def cli(repo,tmp_path,monkeypatch,failure=None):
    core=coordinator(tmp_path,FakeRuntime());tool(repo,tmp_path,core)
    raw=payload(repo,'postToolUse',tool_name='Write',tool_use_id='opaque')
    actual=cursor_hook.handle_cursor_event;observed=[]
    def handler(value,**kwargs):
        kwargs.update(core=core,bindings=CursorBindings(tmp_path/'bindings'),
            project_dir=str(repo),store=RecentHookStore(tmp_path/'recent.db'))
        result=actual(value,**kwargs)
        observed.append(result)
        return result
    monkeypatch.setattr(cursor_hook,'handle_cursor_event',handler)
    monkeypatch.setattr(cursor_hook.sys,'stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(raw).encode())))
    stream=Writer(failure)
    monkeypatch.setattr(cursor_hook.sys,'stdout',stream)
    assert cursor_hook.main(automatic=True)==0
    receipt=observed[0][1]['task_delivery']['delivery_receipt']
    owner=CursorTaskBridge(core,repo,raw['conversation_id'],raw['generation_id']).owner
    return core,stream,receipt,TaskDeliveryReceipts(core.store,repo).get(receipt['delivery_ref'],owner)


def test_successful_flush_records_written_but_not_host_report_or_user_consumption(repo,tmp_path,monkeypatch):
    core,stream,serialized,saved=cli(repo,tmp_path,monkeypatch)
    assert stream.flushed and json.loads(''.join(stream.parts))['additional_context']
    assert not serialized['transport_written']  # Truth at serialization time.
    assert saved['transport_written'] and saved['host_report_submitted']=='NOT_OBSERVED'
    assert saved['user_consumption']=='UNKNOWN' and not core.runtime.calls


@pytest.mark.parametrize('failure',['write','flush'])
def test_failed_writer_retains_prepared_only_and_never_retries_scan(repo,tmp_path,monkeypatch,failure):
    core,stream,serialized,saved=cli(repo,tmp_path,monkeypatch,failure)
    assert saved==serialized and saved['response_prepared'] and not saved['transport_written']
    assert not stream.flushed and not core.runtime.calls


def test_ack_failure_after_successful_flush_does_not_discard_or_repeat_response(repo,tmp_path,monkeypatch):
    monkeypatch.setattr(TaskDeliveryReceipts,'observe',lambda *a,**k: (_ for _ in ()).throw(OSError('private failure')))
    core,stream,serialized,saved=cli(repo,tmp_path,monkeypatch)
    assert stream.flushed and json.loads(''.join(stream.parts))['additional_context']
    assert saved==serialized and not saved['transport_written'] and not core.runtime.calls


def test_late_writer_ack_is_bound_to_original_version_not_new_context(repo,tmp_path):
    core=coordinator(tmp_path,FakeRuntime());tool(repo,tmp_path,core)
    bridge=CursorTaskBridge(core,repo,'private-cursor-conversation','private-generation')
    bridge.context();first=bridge.last_delivery['delivery_receipt']
    writer=DeliveryWriteObserver();writer.bind(core.store,repo,bridge.owner,first)
    task=bridge.current();task['phase']='READY';bridge.tasks.store(repo).save(task)
    bridge.context();second=bridge.last_delivery['delivery_receipt']
    assert second['result_version']!=first['result_version']
    assert writer.written()
    receipts=TaskDeliveryReceipts(core.store,repo)
    assert receipts.get(first['delivery_ref'],bridge.owner)['transport_written']
    assert not receipts.get(second['delivery_ref'],bridge.owner)['transport_written']
    assert not core.runtime.calls
