"""Compact discovery routes to complete methods without losing guard rails."""
from security_runtime.guidance.guidance_catalog import get_runtime_guidance
from security_runtime.guidance.host_guidance import HOST_INSTRUCTIONS
from security_runtime.guidance.mcp_guidance import MCP_INSTRUCTIONS
from security_runtime.mcp_server import create_server
from security_runtime.review_skill import skill_entrypoint


def test_discovery_is_compact_but_full_core_remains_available(monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_WORKSPACE', '')
    server = create_server(global_mode=False)
    assert server._mcp_server.instructions == MCP_INSTRUCTIONS
    assert len(MCP_INSTRUCTIONS.encode()) < len(HOST_INSTRUCTIONS.encode()) * .5
    canonical = get_runtime_guidance('core')
    assert canonical['content'].encode() == skill_entrypoint()
    assert HOST_INSTRUCTIONS in canonical['content']
    for required in ('不开始、恢复或派发检查', '必读方法', 'build_identity', 'SHA-256',
                     'task-review-plan-v3', 'task-result-delivery-v1',
                     'begin_development_check', 'finish_development_check',
                     'record_development_changes', 'get_development_check', '无全项目基线',
                     '不在编辑后补建基线', 'owner', '累计额度', '不用轻量结果替代严格审计',
                     '明确授权', 'ready_for_host_fix=true', '不以新任务绕过'):
        assert required in MCP_INSTRUCTIONS
    for topic in ('core', 'development-check', 'task-review', 'runtime-workflow', 'risk-decisions', 'repair-impact', 'deep-audit'):
        assert topic in MCP_INSTRUCTIONS
