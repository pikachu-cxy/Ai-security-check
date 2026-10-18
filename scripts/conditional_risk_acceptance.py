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
from task_review_v3_acceptance import V3Review, require_v3


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
                    require_v3(info, {tool.name for tool in (await client.list_tools()).tools})
                    ref = (await call('begin_security_task', task_key=f'conditional-order-{number}', workspace_path=str(root)))['task_ref']
                    for name in CHANGES:
                        source = original/name
                        no_links(source)
                        (root/name).write_bytes(source.read_bytes())
                    static = await call('finish_security_task', task_ref=ref, workspace_path=str(root))
                    assert static['static']['scope_files'] == sorted(CHANGES)
                    assert {'semgrep','gitleaks'} <= {r['scanner'] for r in static['static']['scanner_runs'] if r['status']=='SUCCESS'}
                    packet = await call('prepare_task_security_review', task_ref=ref, workspace_path=str(root), protocol_version=3)
                    session = packet['review_session']
                    review = V3Review(call, ref, session, root)
                    await review.plan()
                    evidence = {}
                    for name, start, end in (('orders/api.py',15,21), ('orders/service.py',11,12),
                                             ('orders/repository.py',29,35)):
                        evidence[name] = (await review.read(name, start, end))[0]
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
                    submitted, pages = await review.save_partial(findings,
                        ['固定人工场景模拟提交；仅请求相关片段，未完成全部必读项，不是独立AI发现或真实Desktop调度验收。'])
                    result = pages[0]
                    host = [item['detail'] for page in pages for item in page['findings']
                            if item['source'] == 'HOST_TASK_REVIEW' and item['details_complete']]
                    assert result['host_review']['finding_count'] == len(host) == (0 if protected else 1)
                    assert bool(result['risk_choices']) == (not protected)
                    if findings:
                        finding = host[0]
                        assert finding['file_path'] == 'orders/repository.py'
                        assert finding['risk_scope'] == 'RELATED_EXISTING'
                        for field in ('impact','preconditions','unknowns','current_protections','counterevidence','fix_advice'):
                            assert finding[field] == findings[0][field]
                        assert finding['task_evidence'] == evidence['orders/api.py']
                        assert result['reply_plan']['required_actions'] == [dict(finding_id=finding['id'], actions=['FIX','DEFER'])]
                        assert result['risk_choices'][0]['finding_id'] == finding['id']
                        assert result['risk_choices'][0]['deferred_keeps_risk']
                    else:
                        assert not result['reply_plan']['required_actions']
                    assert not result['repair_authorized'] and not result['reply_plan']['grants_authority']
                    again = (await review.history())[0]
                    assert again['current_version'] and again['risk_choices'] == result['risk_choices']
                    receipts.append(dict(original_project=str(original), build_identity=info['build_identity'],
                        static=static['static'], result=result, review_receipt=submitted, history_pages=pages, timings=timings,
                        host_review_is_fixture=True, desktop_dispatch_observed=False, original_project_modified=False))
    (output/'receipt.json').write_text(json.dumps(receipts, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'status':'PASS','receipt':str(output/'receipt.json'),
                      'scenarios':[{'project':r['original_project'],'risks':r['result']['host_review']['finding_count']} for r in receipts]},ensure_ascii=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--engine-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--project', type=Path, action='append', required=True)
    args = parser.parse_args()
    asyncio.run(accept(args.executable, args.engine_root, args.output, args.project))
