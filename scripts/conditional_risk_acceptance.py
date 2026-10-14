"""Replay the two manual order outcomes through native MCP in isolated copies.

Host submissions are explicit fixtures; this is not independent AI discovery or
Desktop dispatch evidence. Never edits the supplied projects or global settings.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import time

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from security_runtime.hook_state import no_links


CHANGES = ('orders/api.py', 'orders/presentation.py', 'tests/test_order_detail.py')


async def accept(executable, engine_root, output, projects):
    output = output.absolute()
    no_links(output)
    if output.exists() or len(projects) != 2:
        raise ValueError('Use a fresh receipt directory and exactly two manual projects')
    output.mkdir(parents=True)
    receipts = []
    for number, original in enumerate(projects, 1):
        original = original.resolve(strict=True)
        no_links(original)
        root = output/f'replay-{number}'
        root.mkdir()
        names = subprocess.check_output(['git', '-C', str(original), 'ls-tree', '-r', '--name-only', 'HEAD']).decode().splitlines()
        for name in names:
            if name not in {'.gitignore', 'README.md', 'orders/__init__.py', 'orders/api.py',
                            'orders/presentation.py', 'orders/service.py', 'orders/repository.py', 'tests/test_order_list.py'}:
                raise ValueError('Unexpected baseline file')
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(subprocess.check_output(['git', '-C', str(original), 'show', 'HEAD:'+name]))
        subprocess.run(['git', '-c', 'init.templateDir=', 'init', '-q', str(root)], check=True)
        env = {k:os.environ[k] for k in ('SystemRoot','PATH','LOCALAPPDATA','APPDATA','TEMP','TMP','USERPROFILE') if k in os.environ}
        env.update(SECURITY_RUNTIME_STATE_DIR=str(output/f'state-{number}'),
                   SECURITY_RUNTIME_DATA_DIR=str(engine_root.resolve()), SECURITY_RUNTIME_WORKSPACE=str(root.resolve()),
                   SECURITY_RUNTIME_OFFLINE='1', SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
        timings = []
        params = StdioServerParameters(command=str(executable.resolve()), args=['mcp'], cwd=root, env=env)
        with (output/f'stderr-{number}.txt').open('w', encoding='utf-8') as stderr:
            async with stdio_client(params, errlog=stderr) as (read, write):
                async with ClientSession(read, write) as client:
                    async def call(name, **arguments):
                        started = time.perf_counter()
                        r = await client.call_tool(name, arguments)
                        timings.append(dict(tool=name, duration_ms=round((time.perf_counter()-started)*1000, 2)))
                        if r.isError:
                            raise AssertionError((name, r.content))
                        data = r.structuredContent or json.loads(r.content[0].text)
                        return data.get('result', data)
                    await client.initialize()
                    info = await call('get_runtime_info')
                    ref = (await call('begin_security_task', task_key=f'conditional-order-{number}', workspace_path=str(root)))['task_ref']
                    for name in CHANGES:
                        source = original/name
                        no_links(source)
                        (root/name).write_bytes(source.read_bytes())
                    static = await call('finish_security_task', task_ref=ref, workspace_path=str(root))
                    assert static['static']['scope_files'] == sorted(CHANGES)
                    assert {'semgrep','gitleaks'} <= {r['scanner'] for r in static['static']['scanner_runs'] if r['status']=='SUCCESS'}
                    packet = await call('prepare_task_security_review', task_ref=ref, workspace_path=str(root))
                    session = packet['review_session']
                    evidence = {}
                    for name, start, end in (('orders/api.py',15,21), ('orders/service.py',11,12),
                                             ('orders/repository.py',29,35)):
                        evidence[name] = (await call('read_task_review_context', task_ref=ref, review_session=session,
                            file_path=name, start_line=start, end_line=end, workspace_path=str(root)))['evidence_id']
                    # Known manual fixtures; no claim of general program analysis.
                    repo = (root/'orders/repository.py').read_text()
                    protected = 'if row["customer_id"] != customer_id:' in repo
                    findings = []
                    if not protected:
                        assert 'order["customer_id"] != current_customer_id' in (root/'orders/api.py').read_text()
                        findings = [dict(title='现有共享订单查询缺少客户归属过滤', category='BROKEN_ACCESS_CONTROL', severity='MEDIUM',
                            risk_scope='RELATED_EXISTING', primary_evidence=evidence['orders/repository.py'],
                            task_evidence=evidence['orders/api.py'], evidence_refs=list(evidence.values()),
                            impact='其他调用方直接查询且无外层归属检查时，可能返回他人订单。',
                            preconditions=['存在接受客户可控订单 ID 且无额外归属校验的其他调用方'],
                            current_protections=['本次详情 API 在返回前检查客户归属；当前新增详情路径受保护'],
                            counterevidence=['列表查询按客户过滤，详情 API 有归属校验'],
                            unknowns=['其他调用方及外部身份认证、部署可达性未验证'],
                            fix_advice='在仓储返回前统一核对订单 customer_id，并验证相关调用及测试。')]
                    result = await call('submit_task_security_review', task_ref=ref, review_session=session, findings=findings,
                        coverage='REVIEWED', limitations=['固定人工场景模拟提交；不是独立AI发现准确率或真实Desktop调度验收。'], workspace_path=str(root))
                    assert len(result['host_review']['findings']) == (0 if protected else 1)
                    assert bool(result['risk_choices']) == (not protected)
                    if findings:
                        assert result['development_summary'].startswith('**有 1 项关联风险需要你决定。**\n\n')
                        assert '\n\n请选择具体风险后回复：**修复** ／ **暂不处理**。\n\n' in result['development_summary']
                        for phrase in ('当前新增详情路径受保护','代码依据','未确认','暂不处理','风险记录保留'):
                            assert phrase in result['development_summary']
                        assert result['host_review']['findings'][0]['file_path'] == 'orders/repository.py'
                    assert not result['repair_authorized']
                    again = await call('get_task_security_review', task_ref=ref, workspace_path=str(root))
                    assert again['current_version'] and again['risk_choices'] == result['risk_choices']
                    receipts.append(dict(original_project=str(original), build_identity=info['build_identity'],
                        static=static['static'], result=result, timings=timings,
                        host_review_is_fixture=True, desktop_dispatch_observed=False, original_project_modified=False))
    (output/'receipt.json').write_text(json.dumps(receipts, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'status':'PASS','receipt':str(output/'receipt.json'),
                      'scenarios':[{'project':r['original_project'],'risks':len(r['result']['host_review']['findings'])} for r in receipts]},ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--engine-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--project', type=Path, action='append', required=True)
    args = parser.parse_args()
    asyncio.run(accept(args.executable, args.engine_root, args.output, args.project))
