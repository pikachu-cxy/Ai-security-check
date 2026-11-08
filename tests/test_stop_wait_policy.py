"""Transport ceilings are explicit; extended waits never redispatch scanning."""
import asyncio
import json
import pytest
from test_development_check import check, execute
from security_runtime.stop_wait_policy import host_limit
from security_runtime.development_check import native_wait_seconds


def test_host_ceilings_and_invalid_config(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_CODEX_HOME',str(tmp_path))
    assert host_limit()['status']=='UNVERIFIED'
    (tmp_path/'config.toml').write_text('[mcp_servers.ai_security_runtime]\ntool_timeout_sec=600\n')
    for seconds,expected in [(30,20),(600,590),(900,590),(0,18)]:
        (tmp_path/'hooks.json').write_text(json.dumps({'hooks':{'Stop':[{'hooks':[dict(type='mcp_tool',server='ai_security_runtime',tool='handle_stop_event',timeout=seconds)]}]}}))
        result=host_limit()
        assert result['effective_wait_seconds']==expected and not result['unlimited_supported']


def test_default_wait_does_not_read_host_config(monkeypatch):
    def forbidden(): pytest.fail('default Stop must not read host configuration')
    monkeypatch.setattr('security_runtime.stop_wait_policy.host_limit',forbidden)
    assert native_wait_seconds({})==18


@pytest.mark.parametrize('ready_at',[35,310])
def test_extended_wait_ignores_product_budget_and_dispatches_once(check,monkeypatch,ready_at):
    root,service,_,state=check
    ref=service.begin(root,'extended')['check_ref']
    service.record(root,ref,['app.ts'])
    launched=[]
    service.launcher=lambda *a:launched.append(a)
    submitted=service.finish(root,ref)
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref)
        service.store(root)._put(db,ref,dict(row,wait_deadline=0))
    clock=[0]
    service.monotonic=lambda:clock[0]
    async def sleep(seconds):
        clock[0]+=1
        if clock[0]==ready_at: execute(check,monkeypatch)
    service.wait_sleep=sleep
    result=asyncio.run(service.wait_saved(root,ref,590,submitted=submitted,native_extended=True))
    assert result['result_available'] and clock[0]==ready_at
    assert len(launched)==1 and state['calls']==1
    assert result['closeout_wait']['stopped_reason']=='STATE_AVAILABLE'


def test_extended_wait_reports_host_limit_without_resubmit(check):
    root,service,_,state=check
    ref=service.begin(root,'host-limit')['check_ref'];service.record(root,ref,['app.ts'])
    submitted=service.finish(root,ref)
    clock=[0];service.monotonic=lambda:clock[0]
    async def sleep(seconds):clock[0]+=seconds
    service.wait_sleep=sleep
    result=asyncio.run(service.wait_saved(root,ref,1,submitted=submitted,native_extended=True))
    assert result['status']=='QUEUED' and state['calls']==0
    assert result['closeout_wait']['stopped_reason']=='HOST_WAIT_LIMIT_REACHED'


def test_cancel_wait_keeps_original_task(check):
    root,service,_,state=check
    ref=service.begin(root,'cancel-wait')['check_ref'];service.record(root,ref,['app.ts'])
    submitted=service.finish(root,ref)
    async def cancel(_):raise asyncio.CancelledError
    service.wait_sleep=cancel
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(service.wait_saved(root,ref,590,submitted=submitted,native_extended=True))
    row=service.store(root).load(ref,service.owner)
    assert row['finish_requested'] and row['state']=='QUEUED' and state['calls']==0
