from .capabilities import CapabilityRegistry, requested_capabilities
from .models import ScanContext, ScanPlan, TargetProfile
from .scanners import ScannerAdapter, ScannerRegistry


class ScannerPlanner:
    def __init__(self, registry: ScannerRegistry):
        self.registry = registry

    def plan(self, profile: TargetProfile, context: ScanContext) -> tuple[ScanPlan, list[ScannerAdapter]]:
        available = {capability for adapter in self.registry.adapters for capability in adapter.capabilities}
        wanted = requested_capabilities(profile, context.mode, context.files, available)
        capabilities = CapabilityRegistry(self.registry)
        selected = [adapter for adapter in self.registry.adapters
                    if any(adapter in capabilities.get_scanners(capability) for capability in wanted)
                    and adapter.supports(profile, context)]
        return ScanPlan(tuple(adapter.name for adapter in selected), context.files, tuple(sorted(wanted))), selected
