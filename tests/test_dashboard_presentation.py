import copy
import json
import pytest
from security_runtime.dashboard_presentation import present, TEMPLATES, _render
from security_runtime.dashboard_export import render

@pytest.mark.parametrize('category',list(TEMPLATES)+['unknown-rule'])
def test_chinese_distinct_and_no_raw_mutation(category):
    row=dict(id='id',category=category,title='English title',description='Raw scanner message',impact='Raw scanner message',decision='DISMISSED',severity='高',advice='',file_path='app.py',line_start=3)
    before=copy.deepcopy(row)
    value=present(row)
    assert row==before
    p=value['presentation']
    assert p['technical_explanation_zh']!=p['plain_impact_zh']
    assert all(any('\u4e00'<=c<='\u9fff' for c in p[k]) for k in ['title_zh','technical_explanation_zh','plain_impact_zh','advice_zh'])
    assert value['decision']=='DISMISSED' and value['description']==before['description']


def test_saved_chinese_report_preferred_and_revision_invalidation():
    row=dict(category='sql',description='相同的问题描述',impact='相同的问题描述',report_text='**SQL 注入风险**\n\n**问题** 参数直接拼接查询。\n\n**可能影响** 可能读取其他账户数据。\n\n**建议修复** 使用参数绑定。\n\n**尚未确认** 尚未确认接口权限。')
    value=present(row)['presentation']
    assert value['technical_explanation_zh']=='参数直接拼接查询。'
    assert value['plain_impact_zh']=='可能读取其他账户数据。'
    assert value['content_source']['plain_impact_zh']=='REVIEW_REPORT'
    row['report_text']=''
    assert present(row)['presentation']['plain_impact_zh']!='相同的问题描述'
    assert present(row)['presentation']['source_revision']!=value['source_revision']


def test_exports_preserve_identifiers_originals_and_chinese():
    row=present(dict(id='risk',title='Raw title',category='dependency',severity='高',description='Raw advisory',impact='Raw advisory',advice='Update package',session_name='修复登录',file_path='app.py',line_start=2))
    result=dict(status='AVAILABLE',partial=False,risks=[row])
    csv=render(result,'csv')[1].decode()
    assert 'technical_explanation_zh' in csv and 'Raw advisory' in csv and '修复登录' in csv
    sarif=json.loads(render(result,'sarif')[1])['runs'][0]['results'][0]
    assert sarif['partialFingerprints']['runtimeRiskId/v1']=='risk'
    assert sarif['properties']['description']=='Raw advisory'
    assert '依赖' in sarif['message']['text']
