"""Acceptance regressions on isolated signed records; never scan user projects."""
import asyncio
import json
import pytest
from test_development_risks import sample, scanner, observation, submit
from security_runtime.development_risks import review_progress
from security_runtime.development_disposition import input_failure


def test_user_choice_alias_and_errors_do_not_echo_inputs():
    args = dict(check_ref='check', risk_id='risk', disposition='DEFER', user_requested=True, reason='test', expected_seq=2)
    assert input_failure(args) is None
    for values, field in [(dict(args, decision='RESTORE'),'disposition'),
                          (dict(args, user_requested=False),'user_requested'),
                          (dict(args, expected_seq='2'),'expected_seq')]:
        result = input_failure(values)
        assert not result['saved'] and result['field_errors'][0]['field'] == field


def test_disposition_retry_cas_restore_and_changed_source(sample):
    item, _ = submit(sample)
    root, _, _, risks = sample
    args = dict(reason='保留验收样例', request_id='uat-defer-request')
    first = risks.disposition(item['id'], 'DEFER', True, **args)
    second = risks.disposition(item['id'], 'DEFER', True, **args)
    assert first['saved'] and not first['repeated'] and second['repeated']
    assert len(risks.load()['risks'][item['id']]['management']['history']) == 1
    with pytest.raises(ValueError, match='REQUEST_REUSED'):
        risks.disposition(item['id'], 'EXCLUDE', True, **args)
    with pytest.raises(ValueError, match='VERSION_CONFLICT'):
        risks.disposition(item['id'], 'RESTORE', True, expected_revision='stale')
    risks.disposition(item['id'], 'RESTORE', True)
    risk = risks.get()['risks'][0]
    assert not risk['reminder_suppressed'] and risk['decision'] == 'CONFIRMED'
    risks.disposition(item['id'], 'EXCLUDE', True, reason='用户确认样例')
    risk = risks.get()['risks'][0]
    assert risk['decision'] == 'CONFIRMED' and risk['disposition'] == 'EXCLUDE'
    old = risk['management']['source_sha256']
    (root/'query.py').write_text('def query(conn, name):\n    return conn.execute(name + "x")\n')
    result = risks.disposition(item['id'], 'EXCLUDE', True, reason='用户确认样例')
    assert not result['repeated']
    assert risks.load()['risks'][item['id']]['management']['source_sha256'] != old


def test_mcp_accepts_original_uat07_shape(sample):
    from mcp.server.fastmcp import FastMCP
    from types import SimpleNamespace
    from security_runtime.mcp_tools.development_check import register
    item, _ = submit(sample)
    root, service, ref, risks = sample
    server = FastMCP('disposition')
    register(server, SimpleNamespace(harden=lambda _:None), application=SimpleNamespace(
        development_service=lambda *a:service, bound_path=lambda _:root))
    result = asyncio.run(server.call_tool('set_development_risk_disposition', dict(
        check_ref=ref, risk_id=item['id'], disposition='DEFER', reason='保留本地验收样例', user_requested=True, expected_seq=1)))
    data = result[1] if isinstance(result, tuple) else json.loads(result[0].text)
    assert data['saved'] and data['disposition']=='DEFER' and not data['scanner_run']


def test_restore_after_source_change_is_persisted(sample):
    item,_=submit(sample)
    root,_,_,risks=sample
    risks.disposition(item['id'],'DEFER',True,reason='本地样例')
    (root/'query.py').write_text('changed = True\n')
    receipt=risks.disposition(item['id'],'RESTORE',True,reason='本地样例')
    assert receipt['saved'] and not receipt['repeated']
    assert risks.load()['risks'][item['id']]['disposition']=='ACTIVE'


def test_structured_and_inconclusive_report_is_delivered_once(sample, monkeypatch):
    from test_review_delivery import seed
    risks = seed(sample, monkeypatch, 2)
    page = risks.get(limit=None, review_only=True)
    values = [dict(same_issue_as=c['id'], decision='CONFIRMED' if i==0 else 'INCONCLUSIVE',
        rationale='未读取外部调用入口，当前证据不足。' if i else '请求输入直接到达查询执行。', evidence_refs=c['evidence_refs'],
        report_content=dict(title='查询拼接导致 SQL 注入',problem='请求参数直接拼接到 SQL 查询。',impact='攻击者可能读取其他用户的数据。',advice='改为参数化查询。'))
        for i,c in enumerate(page['candidates'])]
    result = risks.submit(values,page['dirty_seq'],scan_id=page['scan_id'],return_risks=True,final_report=True)
    assert result['view']=='final_report' and result['next_action'] is None
    assert '已确认 1 项，待确认 1 项' in result['report_text']
    assert result['report_text'].count('**问题**')==2
    assert result['report_text'].count('### **') == 2
    assert result['report_text'].count('\n\n---\n\n') == 1
    assert result['report_text'].count('**修复／暂不处理**')==1
    assert '未读取外部调用入口' in result['report_text']
    assert not risks.get(review_only=True)['candidates']
    assert len(risks.load()['reviews'])==1


@pytest.mark.parametrize('coverage,limitations,uncovered,expected',[
    ('COMPLETE',['未验证实际部署环境'],[],'COMPLETE'),
    ('PARTIAL',[],['关联鉴权模块无法读取'],'PARTIAL'),
    (None,[],['关联鉴权模块无法读取'],'PARTIAL'),
    (None,['历史限制'],[],'PARTIAL')])
def test_reviewed_files_are_not_pending_files(sample, monkeypatch, coverage, limitations, uncovered, expected):
    scanner(sample, monkeypatch)
    root,service,ref,risks=sample
    with service.store(root).transaction() as db:
        row=service.store(root)._get(db,ref)
        row['effective_config']['values']['agent']['review_scanner_findings']=False
        service.store(root)._put(db,ref,row)
    risks.sync_scanner()
    ev=risks.read('query.py',1,2)['evidence_ref']
    result=risks.submit([],1,business_reviews=[dict(file_path='query.py',rationale='已检查本文件的权限路径',
        evidence_refs=[ev],coverage=coverage,limitations=limitations,uncovered=uncovered)],return_risks=True,final_report=True)
    progress=review_progress(risks.current_check(),risks.load())
    assert not progress['pending_business_paths'] and progress['business_review']==expected
    assert '不能据此声称' not in result['report_text'] and '路径待审' not in result['report_text']
    if uncovered: assert uncovered[0] in result['report_text']
    if coverage=='COMPLETE': assert limitations[0] not in result['report_text']


def test_static_chinese_template_preserves_dependency_details():
    from security_runtime.development_report import render_risk
    item=dict(id='risk',decision='INCONCLUSIVE',finding=dict(category='dependency',title='Package insecure',description='English rule',
        impact='English impact',fix_advice='Upgrade',severity='HIGH',file_path='requirements.txt',line_start=1,
        technical_details=dict(package='PyYAML',installed_version='5.3.1',vulnerability_id='CVE-2020-14343',fixed_versions=['5.4'])))
    report=render_risk(item,'/tmp/project',reviewed=False)
    assert report.startswith('### **')
    assert '依赖漏洞风险' in report and '未经 Agent 确认' in report
    assert 'English rule' not in report and 'PyYAML' in report and 'CVE-2020-14343' in report and '5.4' in report


def test_contradictory_coverage_rejected_before_save(sample):
    risks=sample[3]
    evidence=risks.read('query.py',1,2)['evidence_ref']
    with pytest.raises(ValueError,match='COVERAGE_CONFLICT'):
        risks.submit([],1,business_reviews=[dict(file_path='query.py',rationale='检查',evidence_refs=[evidence],
            coverage='COMPLETE',uncovered=['关键授权分支未审'])])
    assert not risks.load()['reviews']
