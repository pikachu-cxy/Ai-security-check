"""One product authority for core, complete methods and installed guidance."""
import hashlib
from pathlib import Path

import pytest

from security_runtime import guidance_catalog
from security_runtime.compatibility import requirements
from security_runtime.host_guidance import HOST_INSTRUCTIONS,RUNTIME_WORKFLOW,runtime_info
from security_runtime.review_skill import ReviewSkillManager,skill_files


def test_core_is_short_but_keeps_non_optional_safety_boundaries_and_intent_routing():
    core=HOST_INSTRUCTIONS
    assert len(core.encode()) < len(RUNTIME_WORKFLOW.encode())/3
    assert len(core.splitlines()) < 100
    for required in ('普通聊天、只读和普通 Stop', '不开始、恢复或派发检查', '必读方法，并非可跳过',
        'task-review-plan-v3', '真实 build_identity', '九项必需工具子集', '不回退旧协议',
        '第一次编辑前 begin_security_task', '不以 Git HEAD', '不按最近任务猜测',
        '旧 v1/v2/缺协议任务仅供历史查询', '不追认旧改动', '即使静态零发现',
        '未读、脱敏或缺失语义如实保留', '证据与累计额度', 'prepared 不等于发送',
        '不证明代码推理', '任务风险只能沿原风险', '准备受阻不能用普通 begin_security_task 绕过',
        '只有 ready_for_host_fix=true 才编辑', '已有授权不重复确认', '处置不可读说明缺口',
        '完整呈现用户提示或 user_feedback.message', '位置、问题、条件性影响、建议、未知、已有防护和反证',
        '修复／稍后处理', '不伪造用户选择', '静态', '同一构建/版本/摘要的完整本地 reference'):
        assert required in core
    assert '用户明确要求或当前开发任务包含的测试、构建与验收照常执行' in core
    assert '检查异常本身不新增这些权限' in core
    for topic in guidance_catalog.TOPICS[1:]:
        assert 'topic='+topic in core
    assert 'prepare_functional_verification' not in core and 'When remediation.action ==' not in core
    assert 'When remediation.action == AUTO_FIX:' in RUNTIME_WORKFLOW
    assert 'When remediation.action == CONFIRM_REQUIRED:' in RUNTIME_WORKFLOW


def test_fixed_topics_match_generated_and_installed_bytes(tmp_path):
    files=skill_files()
    service=ReviewSkillManager(tmp_path/'home/skills',tmp_path/'state')
    assert service.execute('install')['status']=='INSTALLED'
    source=Path(guidance_catalog.__file__).parent/'skills/ai-security-review'
    for topic in guidance_catalog.TOPICS:
        result=guidance_catalog.get_runtime_guidance(topic)
        assert result['status']=='READY' and result['source']=='BUNDLED'
        content=result['content'].encode('utf-8')
        assert result['sha256']==hashlib.sha256(content).hexdigest() and result['bytes']==len(content)
        name=result['local_reference']
        assert content==files[name]
        assert content==(source/name).read_bytes()
        assert content==(service.root/name).read_bytes()
        assert not any(result['execution'].values())
        assert result['authority']==dict(guidance_is_not_authorization=True,repair_authorized=False,scanner_proof=False)


def test_existing_task_and_deep_methods_keep_the_same_version_and_digest():
    from security_runtime.task_security import method
    from security_runtime.professional_guidance import get_professional_guidance
    task=guidance_catalog.get_runtime_guidance('task-review');original=method(3)
    assert (task['version'],task['sha256'],task['content'])==(original['version'],original['sha256'],original['content'])
    deep=guidance_catalog.get_runtime_guidance('deep-audit');original=get_professional_guidance()
    assert (deep['version'],deep['sha256'],deep['content'])==(original['version'],original['content_sha256'],original['content'])


def test_full_methods_distinguish_saved_choice_from_released_workflow():
    content=guidance_catalog.get_runtime_guidance('repair-impact')['content']
    assert '仅原意图释放返回 APPLIED 才可称工作流已解除' in content
    assert '选择已保存、解除待恢复' in content
    assert '不重复索取同一选择、不取消后建意图' in content
    assert 'DEFER／EXCLUDE 保存成功会自动解除同一修复意图' not in content
    assert 'never ask users for a manual' in RUNTIME_WORKFLOW
    assert 'The agent still verifies v3, actual build identity' in RUNTIME_WORKFLOW


@pytest.mark.parametrize('topic',['../private-source','https://private.invalid/secret',None,{},'task-review-v2','CORE'])
def test_unknown_topics_never_become_file_or_network_requests(topic,monkeypatch):
    monkeypatch.setattr(guidance_catalog,'_content',lambda value:pytest.fail('unvalidated topic read'))
    with pytest.raises(ValueError) as caught:guidance_catalog.get_runtime_guidance(topic)
    assert str(caught.value)=='Unsupported runtime guidance topic'


def test_manifest_is_metadata_only_and_info_skill_status_share_requirements(tmp_path,monkeypatch):
    from security_runtime.storage import SQLiteStore
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(tmp_path/'private'))
    monkeypatch.setattr(SQLiteStore,'default_path',staticmethod(lambda:tmp_path/'private/scans.db'))
    manifest=guidance_catalog.manifest()
    for topic,item in manifest['topics'].items():
        delivered=guidance_catalog.get_runtime_guidance(topic)
        assert item=={key:delivered.get(key) for key in ('status','version','sha256','bytes','local_reference')}
        assert 'content' not in item
    assert not manifest['legacy_protocol_fallback'] and not manifest['security_proof']
    service=ReviewSkillManager(tmp_path/'home/skills',tmp_path/'private/skills')
    status=service.status()
    assert status['compatibility_requirements']==requirements()
    assert status['requirements_scope']=='DECLARATION_NOT_HOST_TOOL_DISCOVERY'
    assert status['status']=='NOT_INSTALLED' and not (tmp_path/'private').exists()
    info=runtime_info()
    assert info['guidance_catalog']==manifest and info['features']['runtime_guidance'].startswith(guidance_catalog.CONTRACT)
    assert not any(info['execution'].values()) and not (tmp_path/'private').exists()


def test_unavailable_guidance_stays_a_gap_without_authority_or_fallback(monkeypatch):
    monkeypatch.setattr(guidance_catalog,'_content',lambda topic: (_ for _ in ()).throw(OSError('private path')))
    result=guidance_catalog.get_runtime_guidance('runtime-workflow')
    assert result['status']=='UNAVAILABLE' and result['content'] is None and result['sha256'] is None
    assert 'private path' not in str(result) and not result['authority']['repair_authorized']
