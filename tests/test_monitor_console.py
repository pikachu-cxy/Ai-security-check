"""Exercise the shared console renderer with synthetic receipts, never real logs."""
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from security_runtime.model_panel import SCRIPT
from security_runtime.monitor_checks import scan_check
from security_runtime.product_metrics import report


# A deliberately small DOM contract: no HTML parsing, network, timers or product
# callbacks exist. Any accidental HTML insertion or I/O fails the renderer test.
DOM = r'''
class Element {
 constructor(tag){this.tagName=tag;this.children=[];this.attributes={};this._text='';this._open=false;this.id='';this.className='';this.parentNode=null;this.style={}}
 set textContent(value){this._text=String(value??'');this.children=[]}
 get textContent(){return this._text+this.children.map(c=>c.textContent).join('')}
 set innerHTML(value){throw Error('HTML insertion is not allowed')}
 appendChild(child){this.children.push(child);child.parentNode=this;return child}
 insertBefore(child,anchor){const i=this.children.indexOf(anchor);if(i<0)throw Error('Missing anchor');this.children.splice(i,0,child);child.parentNode=this;return child}
 replaceChildren(...children){this.children=[];this._text='';for(const child of children)this.appendChild(child)}
 setAttribute(name,value){this.attributes[name]=String(value)}
 getAttribute(name){return this.attributes[name]??null}
 get childNodes(){return this.children}
 get firstElementChild(){return this.children[0]??null}
 get open(){return this._open}
 set open(value){this._open=!!value}
 querySelectorAll(selector){const out=[];const match=n=>selector==='details[open]'?n.tagName==='details'&&n.open:selector[0]==='.'?n.className.split(' ').includes(selector.slice(1)):selector[0]==='#'?n.id===selector.slice(1):n.tagName===selector;const visit=n=>{for(const c of n.children){if(match(c))out.push(c);visit(c)}};visit(this);return out}
 querySelector(selector){return this.querySelectorAll(selector)[0]??null}
}
const root=new Element('html'),head=root.appendChild(new Element('head')),body=root.appendChild(new Element('body'));
globalThis.document={head,body,createElement:tag=>new Element(tag),getElementById:id=>root.querySelector('#'+id)};
function dump(node){return {tag:node.tagName,id:node.id,classes:node.className,attrs:node.attributes,open:node.open,text:node._text,children:node.children.map(dump)}}
'''


def render(tmp_path, data, after=''):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required to execute the bundled JavaScript renderer')
    path = tmp_path/'render.cjs'
    path.write_text(DOM + SCRIPT + '\nconst value='+json.dumps(data, ensure_ascii=False)+r''';
const original=JSON.stringify(value);
const oldCard=document.body.appendChild(document.createElement('div'));oldCard.className='cards';
renderModelEvidence(value,document.body);
''' + after + r'''
if(original!==JSON.stringify(value))throw Error('Renderer changed the evidence');
process.stdout.write(JSON.stringify(dump(document.body)));
''', encoding='utf-8')
    result = subprocess.run([node, str(path)], capture_output=True, text=True,
                            encoding='utf-8', timeout=15)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def nodes(root):
    yield root
    for child in root['children']:
        yield from nodes(child)


def text(root):
    return '\n'.join(node['text'] for node in nodes(root))


def by_id(root, identity):
    return next(node for node in nodes(root) if node['id'] == identity)


def fixture(*, state='PARTIAL', pending=2, coverage='OBSERVED', findings=7):
    check = dict(status=state, execution_state='EXECUTED', coverage='PARTIAL',
        rule_status='PARTIAL', reason_codes=['VUE_TEMPLATE_NOT_COVERED'], limited=False,
        capabilities=[dict(capability='CODE_SAST',status='PARTIAL')],
        languages=[dict(language='vue',status='PARTIAL',selected_rules=9,executed_rules=9,
            target_files=4,scanned_files=3,scope='SCRIPT_BLOCKS_ONLY',template_status='NOT_COVERED')],
        scope_counts=dict(target_files=4,selected_files=4,skipped_files=1))
    return dict(scope='project',monitoring=dict(mode='basic'),product_metrics=dict(
        scans=3,cumulative_finding_occurrences=findings,findings=findings,
        current_risks=dict(pending=pending,observed_pending=2,coverage=coverage,
            reason_codes=[],resolved=1,false_positive=1,excluded=None,deferred=None),
        check_summary=dict(status_counts={state:3},latest=check),
        rows=[dict(scan='scan-3',source='LIVE',findings=findings,check=check,lines={})]))


def test_cumulative_occurrences_and_current_pending_are_independent(tmp_path):
    tree = render(tmp_path, fixture())
    assert by_id(tree, 'cumulativeFindingCount')['text'] == '7'
    assert by_id(tree, 'pendingRiskCount')['text'] == '2'
    assert by_id(tree, 'retainedCheckCount')['text'] == '3'
    assert by_id(tree, 'latestCheckStatus')['text'] == '部分完成'
    overview = by_id(tree, 'scanOverview')
    assert '同一问题可在多次扫描中重复出现' in text(overview)
    assert '没有再次出现，不会自动记作已解决' in text(overview)
    assert '已排除 未观测' in text(overview)
    assert tree['children'][0]['id'] == 'scanOverview'
    assert not by_id(tree, 'observationDetails')['open']


@pytest.mark.parametrize('state,expected',[
    ('COMPLETED','已执行范围内零发现'),
    ('PARTIAL','已执行部分零发现，其他范围未知'),
    ('FAILED','尚不能判断是否零发现'),
    ('NOT_RUN','尚不能判断是否零发现'),
    ('UNKNOWN','尚不能判断是否零发现')])
def test_zero_is_only_a_finding_result_when_execution_evidence_exists(tmp_path,state,expected):
    tree = render(tmp_path,fixture(state=state,findings=0,pending=None,coverage='UNKNOWN'))
    overview = by_id(tree,'scanOverview')
    assert expected in text(overview)
    assert by_id(tree,'pendingRiskCount')['text']=='未知'
    assert '已观测未关闭候选 2 个' in text(overview)
    if state in {'FAILED','NOT_RUN','UNKNOWN'}:
        assert '已执行范围内零发现' not in text(overview)


def test_vue_scope_reasons_and_counts_are_visible_without_claiming_full_support(tmp_path):
    tree = render(tmp_path,fixture())
    overview = text(by_id(tree,'scanOverview'))
    assert 'Vue：仅脚本，模板未覆盖' in overview
    assert '仅脚本块；模板未覆盖' in overview
    assert '9 / 9' in overview and '3 / 4' in overview
    assert '1 个文件被跳过' in overview
    assert '代码规则检查' in overview
    assert '模板和样式仍需单独检查' in overview


def test_partial_handling_evidence_does_not_contradict_known_retained_pending(tmp_path):
    tree = render(tmp_path,fixture(coverage='PARTIAL'))
    overview = text(by_id(tree,'scanOverview'))
    assert by_id(tree,'pendingRiskCount')['text']=='2'
    assert '统计仅代表已观测状态' in overview
    assert '当前待处理总量未知' not in overview


def test_legacy_and_off_state_preserve_unknown_without_creating_actions(tmp_path):
    tree = render(tmp_path,dict(monitoring=dict(mode='off'),product_metrics=dict(
        scans=0,findings=0,rows=[])))
    overview = by_id(tree,'scanOverview')
    assert by_id(tree,'pendingRiskCount')['text']=='未知'
    assert by_id(tree,'latestCheckStatus')['text']=='尚无结果'
    assert '产品观测已关闭' in text(overview)
    assert '只有你主动选择' in text(overview)
    assert '开启观测不会发起检查' in text(overview)
    assert not any(node['tag'] in {'button','a','iframe','script'} for node in nodes(tree))


def test_refresh_preserves_expanded_scan_and_count_details(tmp_path):
    tree = render(tmp_path,fixture(),after=r'''
const overview=document.getElementById('scanOverview');
for(const detail of overview.querySelectorAll('details'))if(detail.getAttribute('data-detail-key'))detail.open=true;
document.getElementById('observationDetails').open=true;
renderModelEvidence(value,document.body);
''')
    keyed = [node for node in nodes(by_id(tree,'scanOverview')) if node['attrs'].get('data-detail-key')]
    assert len(keyed)==3 and all(node['open'] for node in keyed)
    assert by_id(tree,'observationDetails')['open']
    assert len([node for node in nodes(tree) if node['id']=='scanOverview'])==1


def test_unknown_codes_and_labels_are_inert_text(tmp_path):
    data=fixture()
    attack='<img src=x onerror="globalThis.pwned=true">'
    data['product_metrics']['rows'][0]['scan']=attack
    data['product_metrics']['rows'][0]['check']['reason_codes']=[attack]
    tree=render(tmp_path,data)
    assert attack in text(tree)
    assert not any(node['tag'] in {'img','script','iframe'} for node in nodes(tree))
    assert '诊断编号在下方技术详情中保留' in text(tree)


def test_real_projection_contract_explains_timeout_and_retains_unknown_risk(tmp_path):
    check=scan_check(dict(execution_state='TIMEOUT',status='PARTIAL',coverage='PARTIAL',
        scanner_runs=[dict(status='TIMEOUT')]))
    fact=dict(kind='SCAN',reference='one',source='LIVE',total=0,omitted=0,items=[],check=check,
        lines=dict(status='UNKNOWN',target_lines=None,confirmed_file_lines=None))
    metrics=report([dict(product_fact=fact,workspace_hash='project',finished_at=100)])
    tree=render(tmp_path,dict(product_metrics=metrics,monitoring=dict(mode='basic')))
    assert by_id(tree,'latestCheckStatus')['text']=='执行失败'
    assert by_id(tree,'pendingRiskCount')['text']=='未知'
    assert '扫描器执行超时' in text(tree)
    assert '尚不能判断是否零发现' in text(tree)


def test_task_only_check_keeps_review_gaps_separate_from_scan_counts(tmp_path):
    check=dict(status='PARTIAL',execution_state='EXECUTED',coverage='PARTIAL',
        rule_status='UNKNOWN',reason_codes=['SNAPSHOT_FILE_LIMIT','TASK_REVIEW_INCOMPLETE'],
        capabilities=[],languages=[],limited=False,scope_counts=dict(changed_files=49,
            unverified_files=15,review_units=34,reviewed_units=34,unread_ranges=0))
    fact=dict(kind='CHECK',reference='task-one',source='LIVE',total=0,omitted=0,items=[],
        check=check,revision=1)
    metrics=report([dict(product_fact=fact,workspace_hash='project',finished_at=100)])
    tree=render(tmp_path,dict(product_metrics=metrics,monitoring=dict(mode='basic')))
    overview=text(by_id(tree,'scanOverview'))
    assert by_id(tree,'retainedCheckCount')['text']=='1'
    assert '扫描 0 次 · 开发核查 1 项' in overview
    assert '15 个文件尚未完成比较' in overview
    assert '已复核 / 变更单元 34 / 34' in overview
    assert '项目文件数量达到检查上限' in overview
    assert '当前范围还没有检查结果' not in overview
    assert '零发现' not in overview
    assert '开发核查 #1' in overview


def test_all_backend_reason_codes_have_readable_explanations(tmp_path):
    from security_runtime.monitor_checks import REASONS
    from security_runtime.monitor_risks import RISK_REASONS
    data=fixture()
    data['product_metrics']['check_summary']['latest']['reason_codes']=sorted(REASONS)
    data['product_metrics']['current_risks']['reason_codes']=sorted(RISK_REASONS)
    tree=render(tmp_path,data)
    assert '检查记录存在尚未解释的缺口' not in text(tree)


def test_live_and_offline_use_same_renderer_and_scripts_are_valid(tmp_path):
    from security_runtime.context_report import HTML as offline
    from security_runtime.monitoring.page import page
    live=page('synthetic-test-nonce')
    assert SCRIPT in live and SCRIPT in offline
    assert live.index('id="scanOverview"') < live.index('id="consumptionDetails"')
    assert 'id="consumptionDetails" class="consumption-details" open' not in live
    node=shutil.which('node')
    if not node:
        pytest.skip('Node is required for JavaScript syntax verification')
    for index,html in enumerate((live,offline)):
        scripts=re.findall(r'<script(?![^>]*application/json)[^>]*>(.*?)</script>',html,re.S)
        path=tmp_path/f'page-{index}.js'
        path.write_text('\n'.join(scripts),encoding='utf-8')
        result=subprocess.run([node,'--check',str(path)],capture_output=True,text=True,timeout=15)
        assert result.returncode==0,result.stderr
