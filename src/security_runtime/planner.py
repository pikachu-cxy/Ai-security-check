from .models import ScanContext, ScanPlan, TargetProfile
from .scanners import ScannerAdapter, ScannerRegistry


class ScannerPlanner:
    def __init__(self, registry: ScannerRegistry):
        self.registry = registry

    def plan(self, profile: TargetProfile, context: ScanContext) -> tuple[ScanPlan, list[ScannerAdapter]]:
        selected = self.registry.plan(profile, context)
        return ScanPlan(tuple(adapter.name for adapter in selected), context.files), selected
