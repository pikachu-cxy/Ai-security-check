"""Real SDK transport exercises delegated capability boundary, without scanners."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session
from security_runtime.mcp_contracts import MCPRegistry
from security_runtime.mcp_tools.development_check import register
from security_runtime.global_mcp import create_global_server
from test_development_risks import sample


def decode(result):
    if result.structuredContent is not None:
        return result.structuredContent
    return json.loads(result.content[0].text)


@pytest.fixture
def endpoint(sample, monkeypatch):
    root, service, ref, risks = sample
    calls=[]
    def parent_service(check_ref, session_ref, workspace_path):
        calls.append(session_ref)
        if session_ref != 'parent-owner':
            raise ValueError('PARENT_SESSION_REQUIRED')
        return service
    child=FastMCP('audit-boundary')
    register(child,MCPRegistry(child),application=SimpleNamespace(
        development_service=parent_service, bound_path=lambda path:Path(path), hooks=service.hooks,
        runtime_provider=service.runtime_provider, scan_path_provider=service.scan_path_provider))
    pool=SimpleNamespace(host='codex',task_audit_mode=True,root=lambda path,**kw:Path(path),
                         validate_layers=lambda path:None,admit=lambda root:(child,None),close=lambda:None)
    server=create_global_server(workspaces=pool)
    yield server,root,ref,risks,calls
    server.global_workspaces.close()


async def parent(client,root,ref,action,**extra):
    result=await client.call_tool('development_review',{'operation':'manage_development_audit',
        'arguments':dict(workspace_path=str(root),session_ref='parent-owner',check_ref=ref,action=action,**extra)})
    assert not result.isError, result
    return decode(result)


async def setup(client,root,ref):
    prepared=await parent(client,root,ref,'stream_prepare')
    token=prepared['audit_token']
    again=await parent(client,root,ref,'stream_prepare')
    assert 'audit_token' not in again and token not in json.dumps(again)
    await parent(client,root,ref,'stream_started',agent_ref='real-child')
    return dict(workspace_path=str(root),check_ref=ref,audit_token=token,agent_ref='real-child')


async def call_child(client,args,action,**extra):
    return await client.call_tool('development_review',{'operation':'process_development_audit',
        'arguments':dict(args,action=action,**extra)})


def test_child_claim_read_submit_without_parent_session(endpoint):
    server,root,ref,risks,calls=endpoint
    async def run():
        async with create_connected_server_and_client_session(server) as client:
            args=await setup(client,root,ref)
            parent_calls=len(calls)
            claim=decode(await call_child(client,args,'claim'))
            batch=claim['batch']['batch_id']
            assert claim['batch']['versions']=={'query.py':1}
            assert args['audit_token'] not in json.dumps(claim)
            read=decode(await call_child(client,args,'read',batch_id=batch,
                windows=[dict(file_path='query.py',start_line=1,end_line=2)]))
            assert not read['errors']
            evidence=[v['evidence_ref'] for v in read['evidence']]
            reviews=[dict(file_path='query.py',rationale='Reviewed supplied query fixture and bounded input evidence.',
                          evidence_refs=evidence,coverage='COMPLETE',limitations=[])]
            result=await call_child(client,args,'submit',batch_id=batch,request_id='mcp-request-0001',
                                    business_reviews=reviews)
            assert not result.isError, result
            saved=decode(result)
            assert saved.get('review_saved') or saved.get('received'), saved
            replay=decode(await call_child(client,args,'submit',batch_id=batch,request_id='mcp-request-0001',
                                           business_reviews=reviews))
            assert replay['repeated']
            assert len(calls)==parent_calls, 'child must not resolve the parent session'
            assert len(risks.load()['reviews'])==1
    asyncio.run(run())


@pytest.mark.parametrize('change',['token','workspace','check','agent'])
def test_capability_is_bound_to_workspace_check_and_executor(endpoint,tmp_path,change):
    server,root,ref,risks,calls=endpoint
    async def run():
        async with create_connected_server_and_client_session(server) as client:
            args=await setup(client,root,ref)
            if change=='token': args['audit_token']='x'*68
            if change=='workspace':
                other=tmp_path/'other';other.mkdir();args['workspace_path']=str(other)
            if change=='check':args['check_ref']='dc1-'+'f'*32
            if change=='agent':args['agent_ref']='different-child'
            result=await call_child(client,args,'claim')
            assert result.isError or decode(result).get('status')=='INCONCLUSIVE', result
            assert not risks.current_check()['audit_stream']['batches']
    asyncio.run(run())


def test_child_capability_cannot_be_used_for_other_operations_or_unknown_parameters(endpoint):
    server,root,ref,risks,calls=endpoint
    async def run():
        async with create_connected_server_and_client_session(server) as client:
            args=await setup(client,root,ref)
            listed=await client.list_tools()
            schema=next(t.inputSchema for t in listed.tools if t.name=='development_review')
            branch=next(b for b in schema['oneOf'] if b['properties']['operation']['const']=='process_development_audit')
            arguments_schema=branch['properties']['arguments']
            if '$ref' in arguments_schema:
                arguments_schema=schema['$defs'][arguments_schema['$ref'].rsplit('/',1)[1]]
            assert 'session_ref' not in arguments_schema['properties']
            assert {'audit_token','agent_ref','workspace_path','check_ref','action'} <= set(arguments_schema['required'])
            assert arguments_schema['additionalProperties'] is False
            result=await call_child(client,args,'claim',unexpected='not-allowed')
            assert result.isError or decode(result).get('field_errors') or decode(result).get('status')=='INCONCLUSIVE'
            for group,operation,extra in [
                ('development_review','set_development_risk_disposition',dict(risk_id='not-real',decision='DEFER',user_requested=True)),
                ('scan','scan_files',dict(files=['query.py']))]:
                result=await client.call_tool(group,dict(operation=operation,
                    arguments=dict(workspace_path=str(root),audit_token=args['audit_token'],**extra)))
                assert result.isError or decode(result).get('status')=='INCONCLUSIVE' or decode(result).get('field_errors'),result
            assert not risks.current_check()['audit_stream']['batches']
    asyncio.run(run())


def test_missing_child_identity_returns_named_fields_without_token(endpoint):
    server, root, ref, risks, calls = endpoint
    async def run():
        async with create_connected_server_and_client_session(server) as client:
            args = await setup(client, root, ref)
            result = await client.call_tool('development_review', dict(operation='process_development_audit',
                arguments=dict(workspace_path=str(root), audit_token=args['audit_token'], action='claim')))
            value = decode(result)
            assert result.isError
            assert {e['field'] for e in value['field_errors']} == {'check_ref', 'agent_ref'}
            assert args['audit_token'] not in json.dumps(value)
            assert not risks.current_check()['audit_stream']['batches']
    asyncio.run(run())


def test_child_read_scope_and_revocation_are_enforced(endpoint):
    server,root,ref,risks,calls=endpoint
    (root/'private.py').write_text('do_not_disclose = True\n')
    async def run():
        async with create_connected_server_and_client_session(server) as client:
            args=await setup(client,root,ref)
            batch=decode(await call_child(client,args,'claim'))['batch']['batch_id']
            denied=decode(await call_child(client,args,'read',batch_id=batch,
                windows=[dict(file_path='private.py',start_line=1,end_line=1)]))
            assert denied['error']=='AUDIT_RELATED_AUTHORIZATION_REQUIRED'
            assert 'do_not_disclose' not in json.dumps(denied)
            await parent(client,root,ref,'stream_cancel')
            result=await call_child(client,args,'read',batch_id=batch,
                windows=[dict(file_path='query.py',start_line=1,end_line=2)])
            assert result.isError or decode(result).get('status')=='INCONCLUSIVE'
            assert args['audit_token'] not in json.dumps(result.model_dump())
    asyncio.run(run())


def test_nested_observation_errors_identify_fields_without_echoing_values(endpoint):
    server, root, ref, risks, calls = endpoint
    async def run():
        async with create_connected_server_and_client_session(server) as client:
            args = await setup(client, root, ref)
            claimed = decode(await call_child(client, args, 'claim'))
            assert 'description' in claimed['submission_contract']['observation_required']
            result = await call_child(client, args, 'submit', batch_id=claimed['batch']['batch_id'],
                request_id='invalid-nested', observations=[dict(kind='private-input-value',
                    title='private-input-value', evidence_refs=[])])
            value = decode(result)
            assert result.isError
            fields = {e['field']: e for e in value['field_errors']}
            assert fields['observations.0.description']['code'] == 'REQUIRED'
            assert fields['observations.0']['code'] == 'UNKNOWN_FIELDS'
            assert 'kind' not in fields['observations.0']['allowed_fields']
            assert 'private-input-value' not in json.dumps(value)
            assert not risks.load()['reviews']
    asyncio.run(run())
