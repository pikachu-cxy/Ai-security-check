"""Order control contrasts and version-bound registration, not AI accuracy tests."""
import importlib.util
from pathlib import Path

import pytest

from test_task_security import service, prepared, candidate


def related_review(sample):
    s, root, _ = sample
    ref, session, packet = prepared(sample)
    entry = s.read(root, ref, session, 'routes.py', 1, 2)
    control = s.read(root, ref, session, 'auth.py', 1, 2)
    value = candidate(control['evidence_id'], entry['evidence_id'])
    value.update(risk_scope='RELATED_EXISTING', task_evidence=entry['evidence_id'],
                 current_protections=['新入口已有归属检查；未覆盖其他调用方。'])
    return s, root, ref, session, value


def test_existing_conditional_risk_has_actual_location_and_pending_choices(service):
    s, root, ref, session, value = related_review(service)
    result = s.submit(root, ref, session, [value], 'REVIEWED', [])
    risk = result['host_review']['findings'][0]
    assert risk['file_path'] == 'auth.py' and risk['risk_scope'] == 'RELATED_EXISTING'
    assert {v['path'] for v in risk['evidence_locations']} == {'routes.py', 'auth.py'}
    assert risk['validation'] == 'STRUCTURE_AND_VERSION_VALIDATED'
    summary = result['development_summary']
    for text in ('现有条件性风险', '不等于新增入口仍有漏洞', '代码依据',
                 '当前防护', '未确认', '条件', '建议', '修复', '暂不处理', '风险记录保留'):
        assert text in summary
    assert '本次未发现安全线索' not in summary
    assert summary.startswith('**发现 1 项关联风险：订单读取缺少所有者检查**\n\n📍 `auth.py:1`')
    for label in ('问题', '可能影响', '建议修复', '尚未确认', '检查范围'):
        assert '\n\n**'+label+'**\n' in summary
    assert summary.count('**回复「修复」或「暂不处理」即可。**') == 1
    assert summary.index('**尚未确认**') < summary.index('**检查范围**') < summary.index('**回复「修复」')
    for fact in (value['impact'], value['fix_advice'], *value['preconditions'],
                 *value['unknowns'], *value['current_protections'], *value['counterevidence']):
        assert fact in summary
    assert result['risk_choices'][0]['options'] == ['修复', '暂不处理']
    assert result['risk_choices'][0]['deferred_keeps_risk'] is True
    assert result['repair_authorized'] is False
    assert s.get(root, ref)['current_version'] is True
    assert s.get(root, ref)['risk_choices'] == result['risk_choices']


@pytest.mark.parametrize('missing', ['task_evidence', 'current_protections', 'preconditions', 'unknowns'])
def test_related_risk_cannot_omit_task_link_or_conditions(service, missing):
    s, root, ref, session, value = related_review(service)
    if missing in ('preconditions', 'unknowns'):
        value[missing] = []
    else:
        value.pop(missing)
    with pytest.raises(ValueError):
        s.submit(root, ref, session, [value], 'REVIEWED', [])


def test_unissued_anchor_or_changed_primary_cannot_masquerade_as_existing(service):
    s, root, ref, session, value = related_review(service)
    value['task_evidence'] = 'unissued'
    with pytest.raises(ValueError, match='task-changed'):
        s.submit(root, ref, session, [value], 'REVIEWED', [])
    value['task_evidence'] = value['evidence_refs'][1]
    value['primary_evidence'] = value['task_evidence']
    with pytest.raises(ValueError, match='current read related'):
        s.submit(root, ref, session, [value], 'REVIEWED', [])


def test_related_source_change_invalidates_risk_and_choices(service):
    s, root, ref, session, value = related_review(service)
    (root/'auth.py').write_text('def owns(user, order):\n    return True\n')
    with pytest.raises(ValueError, match='stale'):
        s.submit(root, ref, session, [value], 'REVIEWED', [])


def test_no_candidate_has_no_processing_choices(service):
    s, root, ref, session, _ = related_review(service)
    result = s.submit(root, ref, session, [], 'REVIEWED', ['未验证外部身份认证'])
    assert result['risk_choices'] == []
    assert '暂不处理' not in result['development_summary']


def test_completed_risk_cannot_offer_stale_processing_choices(service):
    s, root, ref, session, value = related_review(service)
    s.submit(root, ref, session, [value], 'REVIEWED', [])
    (root/'auth.py').write_text('def owns(user, order):\n    return True\n')
    result = s.get(root, ref)
    assert result['status'] == 'STALE' and result['risk_choices'] == []


@pytest.mark.parametrize('protected_repository', [True, False])
def test_order_scenarios_register_only_surviving_shared_risk(tmp_path, protected_repository):
    # Same baseline code as the manual pair, in fresh isolated directories.
    spec = importlib.util.spec_from_file_location('order_lab', Path(__file__).resolve().parents[1]/'scripts/new_blind_order_lab.py')
    lab = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab)
    from security_runtime.hook_state import HookStateStore
    from security_runtime.task_security import TaskSecurityService
    from test_task_security import LedgerRuntime
    import subprocess
    root = tmp_path/'orders-project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    for name, content in lab.COMMON.items():
        if name == 'orders/repository.py':
            check = '        if row["customer_id"] != customer_id:\n            return None' if protected_repository else ''
            content = content.replace('__LOOKUP_BODY__', check)
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
    runtime = LedgerRuntime()
    s = TaskSecurityService(runtime, HookStateStore(tmp_path/'state'))
    ref = s.begin(root, 'order-detail')['task_ref']
    # In both cases the new API is protected, as in the actual manual outcomes.
    api = root/'orders/api.py'
    api.write_text(api.read_text()+'''\n\ndef get_order_detail(current_customer_id, order_id):
    if not current_customer_id:
        return {"status": 401}
    order = _service.lookup_order(current_customer_id, order_id)
    if order is None or order["customer_id"] != current_customer_id:
        return {"status": 404}
    return {"status": 200, "body": order}
''')
    result = s.finish(root, ref)
    assert result['static']['finding_count'] == 0
    packet = s.prepare(root, ref)
    session = packet['review_session']
    evidence = {name:s.read(root, ref, session, name, 1, 70)['evidence_id']
                for name in ('orders/api.py', 'orders/service.py', 'orders/repository.py')}
    findings = []
    if not protected_repository:
        findings = [dict(title='现有共享订单查询缺少归属过滤', category='authorization', severity='MEDIUM',
            primary_evidence=evidence['orders/repository.py'], evidence_refs=list(evidence.values()),
            risk_scope='RELATED_EXISTING', task_evidence=evidence['orders/api.py'],
            impact='其他调用方直接使用查询接口且无归属检查时，可能读取他人订单。',
            preconditions=['存在允许客户控制订单 ID 且无外层检查的其他调用方'],
            unknowns=['其他调用方、外部认证与部署可达性未验证'],
            current_protections=['本次 API 返回前检查 customer_id，当前详情路径受保护'],
            counterevidence=['列表路径过滤客户，新详情 API 有归属检查'],
            fix_advice='在共享仓储查询返回前统一过滤 customer_id，并验证相关调用。')]
    result = s.submit(root, ref, session, findings, 'REVIEWED', ['外部身份认证未验证'])
    assert len(result['host_review']['findings']) == (0 if protected_repository else 1)
    assert bool(result['risk_choices']) is (not protected_repository)
    if findings:
        assert 'orders/repository.py' in result['development_summary']
        assert '当前详情路径受保护' in result['development_summary']
    assert not result['repair_authorized']
    assert len(runtime.calls) == 1
