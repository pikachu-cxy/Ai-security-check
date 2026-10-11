"""Detection never authorizes repair; explicit user consent is mandatory."""
from dataclasses import asdict, dataclass
import json
from pathlib import Path

from .hook_state import atomic_bytes, no_links
from .storage import SQLiteStore

RULE = 'ai-security.java.trust-all-hostname'
MODES = ('smart_auto', 'ask_before_fix', 'report_only')
ACTIONS = ('NONE', 'ADVISE', 'AUTO_FIX', 'CONFIRM_REQUIRED', 'MANUAL_ONLY', 'ESCALATE')


@dataclass(frozen=True)
class RemediationDecision:
    action: str
    reason_code: str
    finding_family: str | None = None
    category: str = 'code'
    finding_policy: str = 'REVIEW'
    policy_source: str = 'REMEDIATION_POLICY_V2_USER_CONSENT'
    max_attempts: int = 2
    verification_required: bool = True

    def to_dict(self):
        return asdict(self)


class RemediationConfig:
    """User-state configuration only. Invalid configuration disables automation."""
    def __init__(self, path: Path | None = None):
        self.path = path or SQLiteStore.default_path().parent / 'remediation.json'

    def read(self):
        no_links(self.path)
        if not self.path.exists():
            return 'ask_before_fix'
        if self.path.stat().st_size > 4096:
            raise ValueError('Invalid remediation configuration')
        with self.path.open('rb') as stream:
            content = stream.read(4097)
        if len(content) > 4096:
            raise ValueError('Invalid remediation configuration')
        data = json.loads(content)
        if (not isinstance(data, dict) or set(data) != {'remediation'} or
                not isinstance(data['remediation'], dict) or set(data['remediation']) != {'mode'} or
                data['remediation']['mode'] not in MODES):
            raise ValueError('Invalid remediation configuration')
        mode = data['remediation']['mode']
        # Read legacy preferences without rewriting any global user state.
        return 'ask_before_fix' if mode == 'smart_auto' else mode

    def write(self, mode):
        if mode not in MODES:
            raise ValueError('Invalid remediation mode')
        effective = 'ask_before_fix' if mode == 'smart_auto' else mode
        atomic_bytes(self.path, json.dumps({'remediation': {'mode': effective}}).encode())

    def managed_paths(self):
        """Policy storage locations, never a transport or workspace locator."""
        return (self.path,)

    def revision(self):
        no_links(self.path)
        return self.path.stat().st_mtime_ns if self.path.exists() else None


class RemediationPolicy:
    def decide(self, *, family=None, rule=None, category='code', priority='REVIEW',
               coverage=False, deterministic=False, mode='ask_before_fix', attempts=0):
        action, reason = 'ADVISE', 'NOT_ELIGIBLE'
        if priority in {'SUPPRESSED', 'BEST_PRACTICE'}:
            action, reason = 'NONE', 'QUIET_POLICY'
        elif category != 'code':
            action, reason = 'MANUAL_ONLY', 'PROTECTED_CATEGORY'
        elif priority != 'ACTIONABLE':
            reason = 'REVIEW_REQUIRED'
        elif rule == RULE and coverage and deterministic:
            if attempts >= 2:
                action, reason = 'ESCALATE', 'EPISODE_ATTEMPT_BUDGET_EXCEEDED'
            elif mode in {'smart_auto', 'ask_before_fix'}:
                action, reason = 'CONFIRM_REQUIRED', 'EXPLICIT_USER_CONSENT_REQUIRED'
            else:
                reason = 'REPORT_ONLY_MODE'
        return RemediationDecision(action, reason, family, category, priority)
