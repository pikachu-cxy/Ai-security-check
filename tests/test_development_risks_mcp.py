import asyncio

import pytest

from test_development_check_mcp import development_server, call, projects, installed  # noqa: F401
from security_runtime.mcp_contracts import MCPRegistry


def test_unified_risk_tools_repair_round_trip(development_server):
    server, root, _, launches = development_server
    (root/'risk.py').write_text('def query(conn, name):\n    return conn.execute(name)\n')
    base = dict(workspace_path=str(root))
    check = call(server, 'begin_development_check', task_key='unified-risk', **base)
    base['check_ref'] = check['check_ref']
    check = call(server, 'record_development_changes', paths=['risk.py'], **base)
    evidence = call(server, 'read_development_risk_context', file_path='risk.py', start_line=1, end_line=2, **base)
    value = dict(issue_key='query', file_path='risk.py', line_start=2, line_end=2, category='sql-injection',
                 title='SQL', description='Unbound input', impact='Read rows', fix_advice='Bind name',
                 severity='HIGH', decision='CONFIRMED', rationale='Input passed to execute',
                 evidence_refs=[evidence['evidence_ref']])
    registry = MCPRegistry(server)
    asyncio.run(registry.dispatch('submit_development_review', dict(base, expected_seq=check['dirty_seq'], observations=[value])))
    risk = call(server, 'get_development_risks', **base)['risks'][0]
    fix = call(server, 'prepare_development_risk_fix', risk_id=risk['id'], proposal='Bind name',
               preserve=['API'], evidence_refs=value['evidence_refs'], user_requested=True,
               impact_summary='Only reject query syntax in name', critical_unknowns=[], repair_paths=['risk.py'], **base)
    assert fix['ready_for_host_fix']
    (root/'risk.py').write_text('def query(conn, name):\n    return conn.execute("SELECT ?", (name,))\n')
    evidence = call(server, 'read_development_risk_context', file_path='risk.py', start_line=1, end_line=2, **base)
    result = call(server, 'submit_development_risk_resolution', risk_id=risk['id'], repair_ref=fix['repair_ref'],
                  outcome='CODE_REVIEWED_RESOLVED', evidence_refs=[evidence['evidence_ref']], rationale='Bound value', **base)
    assert result['outcome'] == 'CODE_REVIEWED_RESOLVED'
    assert not launches
    assert registry.tool('get_development_risks').annotations.readOnlyHint


def test_transport_does_not_coerce_authorization_or_accept_extra_fields(development_server):
    server, root, _, _ = development_server
    registry = MCPRegistry(server)
    with pytest.raises(Exception):
        asyncio.run(registry.dispatch('prepare_development_risk_fix', dict(
            workspace_path=str(root), check_ref='dc1-'+'0'*32, risk_id='fake', proposal='fix', preserve=['API'],
            evidence_refs=['fake'], user_requested='true', impact_summary='none', critical_unknowns=[])))
    with pytest.raises(Exception):
        asyncio.run(registry.dispatch('get_development_risks', dict(
            workspace_path=str(root), check_ref='dc1-'+'0'*32, repair_authorized=True)))
