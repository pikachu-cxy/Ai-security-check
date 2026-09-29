from security_runtime.capabilities import Capability
from security_runtime.models import ScanContext, ScanMode, TargetProfile
from security_runtime.planner import ScannerPlanner
from security_runtime.scanners import ScannerRegistry


class PluginAdapter:
    name = scanner_id = "future-ai-skill"
    capabilities = frozenset({Capability.AI_SKILL_SECURITY})

    def supports(self, profile, context):
        return True


class DynamicAdapter:
    name = scanner_id = "future-dynamic-mcp"
    capabilities = frozenset({Capability.MCP_SECURITY_DYNAMIC})

    def supports(self, profile, context):
        return True


def test_new_capabilities_need_no_core_edit_and_dynamic_is_not_quick():
    registry = ScannerRegistry(adapters=[PluginAdapter(), DynamicAdapter()])
    planner = ScannerPlanner(registry)
    profile = TargetProfile("C:/sample")
    _, quick = planner.plan(profile, ScanContext(profile.path, ScanMode.QUICK, ("app.py",)))
    assert [adapter.scanner_id for adapter in quick] == ["future-ai-skill"]
    _, feature = planner.plan(profile, ScanContext(profile.path, ScanMode.FEATURE, ("app.py",)))
    assert {adapter.scanner_id for adapter in feature} == {"future-ai-skill", "future-dynamic-mcp"}
