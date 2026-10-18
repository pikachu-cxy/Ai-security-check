"""Native ordinary MCP + invoked Hook ABI timing, not Desktop event observation.

Static-only isolated fixtures. Never run applications/install business deps.
Host review submission is explicitly a fixture, not an observed AI audit.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sqlite3
from contextlib import closing
import time

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from task_review_v3_acceptance import V3Review, require_v3


async def accept(executable, engine_root, output):
    output = output.resolve()
    if output.exists():
        raise ValueError('Use a fresh acceptance directory')
    output.mkdir(parents=True)
    definitions = json.loads((Path(__file__).resolve().parents[1]/'samples/manual-hook-lab/cases.json').read_text(encoding='utf-8'))
    results = []
    for project in definitions['projects']:
        root = output/project['language']
        root.mkdir()
        subprocess.run(['git','init','-q',str(root)], check=True)
        for case in project['cases']:
            path = root/case['file']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(case['safe'], encoding='utf-8')
        # Unchanged related source for bounded context retrieval.
        suffix = Path(project['cases'][0]['file']).suffix
        related = 'src/AccessControl'+suffix
        (root/related).write_text('def owns(user, owner):\n    return user.id == owner\n' if suffix == '.py' else
                                'class AccessControl { boolean owns(int user, int owner) { return user == owner; } }\n' if suffix == '.java' else
                                'export function owns(user, owner) { return user.id === owner; }\n', encoding='utf-8')
        env = {k:os.environ[k] for k in ('SystemRoot','PATH','LOCALAPPDATA','APPDATA','TEMP','TMP','USERPROFILE','HOMEDRIVE','HOMEPATH') if k in os.environ}
        state = output/'states'/project['language']
        env.update(SECURITY_RUNTIME_DATA_DIR=str(engine_root.resolve()),
                   SECURITY_RUNTIME_STATE_DIR=str(state), SECURITY_RUNTIME_WORKSPACE=str(root),
                   SECURITY_RUNTIME_OFFLINE='1', SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
        semgrep = Path(os.environ['LOCALAPPDATA'])/'Programs/Python/Python312/Scripts/semgrep.exe'
        if semgrep.is_file():
            env['SECURITY_RUNTIME_SEMGREP_PATH'] = str(semgrep)
            env['PATH'] = str(semgrep.parent)+os.pathsep+env.get('PATH','')
        params = StdioServerParameters(command=str(executable.resolve()), args=['mcp'], cwd=root, env=env)
        timings = []
        with (root/'stderr.txt').open('w', encoding='utf-8') as stderr:
            async with stdio_client(params, errlog=stderr) as (read,write):
                async with ClientSession(read,write) as client:
                    await client.initialize()
                    async def call(name, **arguments):
                        started = time.perf_counter()
                        response = await client.call_tool(name, arguments)
                        elapsed = round((time.perf_counter()-started)*1000, 2)
                        assert not response.isError, (name, response.content)
                        timings.append(dict(tool=name, elapsed_ms=elapsed))
                        data = response.structuredContent or json.loads(response.content[0].text)
                        return data.get('result',data), response
                    tools = {t.name for t in (await client.list_tools()).tools}
                    assert {'begin_security_task','finish_security_task','prepare_task_security_review',
                            'get_task_review_method','get_task_review_plan','submit_task_review_batch',
                            'read_task_review_context','submit_task_security_review','get_task_security_review'} <= tools
                    async def data_call(name, **arguments):
                        data, _ = await call(name, **arguments)
                        return data
                    info,_ = await call('get_runtime_info')
                    require_v3(info, tools)
                    await call('handle_readiness_event',event='SessionStart',workspace_path=str(root),session_id='acceptance')
                    async def hook(number):
                        return await call('handle_hook_event',event='PostToolUse',workspace_path=str(root),session_id='acceptance',
                                          turn_id='development',tool_use_id=f'edit-{number}',tool_name='Write')
                    await hook(0)  # Actual safe static baseline; no application execution.
                    started,_ = await call('begin_security_task',task_key='native-development',workspace_path=str(root))
                    ref = started['task_ref']
                    first,second = project['cases']
                    (root/first['file']).write_text(first['risky'], encoding='utf-8')
                    edited,hook_response = await hook(1)
                    assert edited['scanner_run'], project['language']
                    hook_wire = json.loads(hook_response.content[0].text)
                    assert hook_wire.get('continue') is True and 'stopReason' not in hook_wire and 'systemMessage' not in hook_wire
                    assert '没有授予修复权限' in hook_wire['hookSpecificOutput']['additionalContext']
                    (root/second['file']).write_text(second['safe']+('\n# task context\n' if suffix == '.py' else '\n// task context\n'), encoding='utf-8')
                    later_edit,_ = await hook(2)
                    finished,_ = await call('finish_security_task',task_ref=ref,workspace_path=str(root))
                    assert finished['changed_file_count'] == 2 and finished['review_required']
                    with closing(sqlite3.connect(state/'scans.db')) as db:
                        scan = json.loads(db.execute('SELECT data FROM scans WHERE id=?',(finished['static']['scan_id'],)).fetchone()[0])
                    assert first['expected_rule'] in {f['technical_details'].get('rule_id') for f in scan['findings']}
                    packet,_ = await call('prepare_task_security_review',task_ref=ref,workspace_path=str(root),protocol_version=3)
                    session = packet['review_session']
                    review = V3Review(data_call, ref, session, root)
                    units = await review.plan()
                    assert {unit['path'] for unit in units} == {first['file'], second['file']}
                    await review.read(first['file'], end_line=80)
                    await review.read(related, end_line=80)
                    reviewed, history = await review.save_partial([],
                        ['接口与耗时验收的模拟提交；仅检查所请求的源码范围，未观察真实宿主模型语义核查。'])
                    readback = history[0]
                    assert readback['host_review']['coverage'] == 'PARTIAL'
                    assert readback['static']['finding_count'] > 0
                    assert readback['current_version']
                    for i in range(5):
                        stopped,response = await call('handle_stop_event',event='Stop',workspace_path=str(root),session_id='acceptance',
                            stop_hook_active=False,turn_id=f'chat-{i}')
                        assert stopped['execution']['scanner_run'] is False
                        assert json.loads(response.content[0].text) == {}
                    unchanged,_ = await call('begin_security_task',task_key='no-change-task',workspace_path=str(root))
                    nochange,_ = await call('finish_security_task',task_ref=unchanged['task_ref'],workspace_path=str(root))
                    assert nochange['status'] == 'NO_CHANGES' and nochange['development_summary'] == ''
                    results.append(dict(language=project['language'], build_id=info['build_identity']['build_id'],
                        static_finding_count=finished['static']['finding_count'], static_coverage=finished['static']['coverage'],
                        static_scanner_runs=finished['static']['scanner_runs'], changed_file_count=2,
                        hook_risk_static_executed=edited['scanner_run'], quiet_stop_count=5,
                        hook_observations=[{k:h.get(k) for k in ('status','scanner_run','changed_file_count','scanner_skipped_reason')}
                                           for h in (edited,later_edit)],
                        review_protocol=3, review_receipt=reviewed, review_history_pages=history,
                        host_model_observed=False, application_executed=False, business_dependencies_installed=False, timings=timings))
    receipt = dict(contract='task-security-native-acceptance-v1', desktop_events_observed=False, results=results)
    (output/'receipt.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(receipt=str(output/'receipt.json'), results=[dict(language=r['language'],coverage=r['static_coverage'],findings=r['static_finding_count'],timings=r['timings']) for r in results]),ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--executable',type=Path,required=True)
    parser.add_argument('--engine-root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    asyncio.run(accept(args.executable,args.engine_root,args.output))
