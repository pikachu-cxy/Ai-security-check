"""One product authority for core, complete methods and installed guidance."""
import hashlib
from pathlib import Path

import pytest

from security_runtime.guidance import guidance_catalog
from security_runtime.compatibility import requirements
from security_runtime.guidance.host_guidance import (
    HOST_INSTRUCTIONS, REPAIR_IMPACT_GUIDANCE, RUNTIME_WORKFLOW, runtime_info,
)
from security_runtime.review_skill import ReviewSkillManager,skill_files


def test_core_is_short_but_keeps_non_optional_safety_boundaries_and_intent_routing():
    core=HOST_INSTRUCTIONS
    assert len(core.encode()) < 10_000
    assert len(RUNTIME_WORKFLOW.encode()) < 20_000
    assert len(core.splitlines()) < 100
    for required in ('普通聊天、只读和普通 Stop', '不开始、恢复或派发检查', '必读方法，并非可跳过',
        'task-review-plan-v3', '真实 build_identity', '九项必需工具子集', '不回退旧协议',
        '第一次编辑前 begin_security_task', '不以 Git HEAD', '不按最近任务猜测',
        '旧 v1/v2/缺协议任务仅供历史查询', '不追认旧改动', 'observed-development-check-v1',
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
    assert 'When remediation.action == AUTO_FIX:' in REPAIR_IMPACT_GUIDANCE
    assert 'When remediation.action == CONFIRM_REQUIRED:' in REPAIR_IMPACT_GUIDANCE


def test_fixed_topics_match_generated_and_installed_bytes(tmp_path):
    files=skill_files()
    service=ReviewSkillManager(tmp_path/'home/skills',tmp_path/'state')
    assert service.execute('install')['status']=='INSTALLED'
    source=Path(guidance_catalog.__file__).resolve().parents[1]/'skills/ai-security-review'
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


def test_quiet_development_and_requested_security_reports_have_distinct_guidance():
    files = skill_files()
    core = files['SKILL.md'].decode('utf-8')
    workflow = files['references/runtime-workflow.md'].decode('utf-8')
    for content in (HOST_INSTRUCTIONS, core):
        assert '当前任务核查完整、零发现且无检查或处置缺口时静默' in content
        assert '扫描项、覆盖范围或“未发现风险”尾注' in content
        assert '显式安全检查或安全状态/历史查询即使零发现也报告' in content
        assert '风险、检查缺口及需报告的原问题复查不静默' in content
    # Scan guidance routes development to its complete method rather than
    # duplicating that method's quiet-summary and delivery requirements.
    assert 'references/quick-task-review-v3.md' in workflow
    assert 'topic=task-review' in workflow
    method = files['references/quick-task-review-v3.md'].decode('utf-8')
    for required in ('Merge a nonempty development_summary', 'current and complete, zero',
                     'no check or handling gaps remain', 'zero-finding footer',
                     'security status/history queries still report actual scope',
                     'verification results remain visible'):
        assert required in method


def test_existing_task_and_deep_methods_keep_the_same_version_and_digest():
    from security_runtime.tasks.security import method
    from security_runtime.professional_guidance import get_professional_guidance
    task=guidance_catalog.get_runtime_guidance('task-review');original=method(3)
    assert (task['version'],task['sha256'],task['content'])==(original['version'],original['sha256'],original['content'])
    deep=guidance_catalog.get_runtime_guidance('deep-audit');original=get_professional_guidance()
    assert (deep['version'],deep['sha256'],deep['content'])==(original['version'],original['content_sha256'],original['content'])


def test_scan_workflow_loads_only_the_needed_topics_and_preserves_full_repair_methods():
    from security_runtime.guidance.host_guidance import RISK_DECISION_WORKFLOW
    from security_runtime.guidance.risk_decision_guidance import RISK_DECISION_GUIDANCE
    workflow = guidance_catalog.get_runtime_guidance('runtime-workflow')
    risk = guidance_catalog.get_runtime_guidance('risk-decisions')['content']
    repair = guidance_catalog.get_runtime_guidance('repair-impact')['content']
    assert workflow['version'] == 'runtime-workflow-v3'
    assert RISK_DECISION_GUIDANCE not in workflow['content']
    assert RISK_DECISION_WORKFLOW not in workflow['content']
    assert REPAIR_IMPACT_GUIDANCE not in workflow['content']
    assert 'When remediation.action ==' not in workflow['content']
    assert RISK_DECISION_WORKFLOW in risk and REPAIR_IMPACT_GUIDANCE in repair
    for required in ('topic=risk-decisions', 'topic=repair-impact', '同一份内容',
                     'force_rescan=true', 'scan_files', 'files', 'summary=true',
                     '必要复核', 'Runtime cannot invoke the host', '对话总耗时'):
        assert required in workflow['content']
    assert '不重复加载已读的同版本主题' in HOST_INSTRUCTIONS
    assert '只有存在待呈现的风险或实际保存用户处置时才读取' in workflow['content']
    assert '零发现不加载该主题' in workflow['content']
    assert 'scan_context.full_project_reusable=true' not in workflow['content']
    assert 'execution.result_reused=true' in workflow['content']


def test_full_methods_distinguish_saved_choice_from_released_workflow():
    content=guidance_catalog.get_runtime_guidance('repair-impact')['content']
    assert '仅原意图释放返回 APPLIED 才可称工作流已解除' in content
    assert '选择已保存、解除待恢复' in content
    assert '不重复索取同一选择、不取消后建意图' in content
    assert 'DEFER／EXCLUDE 保存成功会自动解除同一修复意图' not in content
    assert 'never ask users for a manual' in RUNTIME_WORKFLOW
    assert 'The agent verifies the selected workflow, actual build identity' in RUNTIME_WORKFLOW
    assert 'existing strict tasks retain v3' in RUNTIME_WORKFLOW


def test_default_development_is_observed_scope_without_project_baseline():
    from security_runtime.compatibility import DEVELOPMENT_CHECK_TOOLS, tool_requirements
    from security_runtime.tasks.ownership import session_context

    method = guidance_catalog.get_runtime_guidance('development-check')
    assert method['version'] == 'development-check-v1'
    assert method['local_reference'] == 'references/development-check.md'
    for content in (HOST_INSTRUCTIONS, method['content']):
        for name in DEVELOPMENT_CHECK_TOOLS:
            assert name in content
        assert '不建立全项目' in content
        assert 'scope_unknown' in method['content']
    assert '不强制读取所有文件的全部改前/改后窗口' in method['content']
    assert '不扫描、不唤醒后台进程' in method['content']
    assert '不自动扫描下一版' in method['content']
    assert 'host_review_completed=false' in method['content']
    assert '不能断言问题由本次 AI 编辑新增' in method['content']
    assert '旧任务不迁移为轻量记录，不重建基线' in method['content']
    for name in DEVELOPMENT_CHECK_TOOLS:
        assert tool_requirements(name)['workflow'] == 'DEVELOPMENT_CHECK'
    routing = session_context('synthetic-token')
    assert 'begin_development_check' in routing
    assert '首次编辑前 begin_security_task' not in routing
    assert '已有严格审计或原生修复沿原 task_ref' in routing
    info = runtime_info()
    assert info['features']['operating_mode'] == 'AI_DEVELOPMENT_EDIT_CHECK'
    assert 'NO_PROJECT_BASELINE' in info['features']['development_check']
    assert 'HOOK_RECORD_ONLY' in info['features']['development_check']
    assert 'BACKGROUND_ON_FINISH' in info['features']['development_check']
    assert 'DEFAULT_V3' not in info['features']['task_security_review_protocol']


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
