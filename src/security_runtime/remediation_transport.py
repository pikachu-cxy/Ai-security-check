"""Execution capability, separate from policy preferences and Host event claims.

Constructed by trusted transport wiring, never by a Hook payload. Advisory
context is informational; it cannot replace an existing edit grant or ticket.
"""
from dataclasses import dataclass
import json


@dataclass(frozen=True)
class RemediationTransportConfig:
    supports_advisory_remediation: bool = True
    supports_agent_continuation: bool = True
    supports_write: bool = False  # Runtime never edits, including live transports.

    def __post_init__(self):
        if (any(type(v) is not bool for v in (
                self.supports_advisory_remediation, self.supports_agent_continuation, self.supports_write))
                or self.supports_write):
            raise ValueError('Invalid remediation transport capability')

    @property
    def transport_mode(self):
        return 'AGENT_CONTINUATION' if self.supports_agent_continuation else 'ADVISORY'


@dataclass(frozen=True)
class AdvisoryTransportConfig(RemediationTransportConfig):
    supports_agent_continuation: bool = False


def advisory_offer(service, root, task, finding, decision, snapshot, deterministic):
    """Project the existing task fix plan, without preparing an edit credential."""
    from .equivalence import equivalence_key
    from .hook_state import identity
    from .task_fix import PLANS
    resolved, scan, members = service._fix()._resolve(task['task_ref'], root, root)
    if (scan is None or resolved['status'] != 'RESOLVED' or
            len(members) != 1 or members[0]['id'] != finding['id'] or
            equivalence_key(members[0]) != decision.finding_family or
            service._snapshot(root) != snapshot):
        raise ValueError('ADVISORY_CONTEXT_NOT_CURRENT')
    plan = PLANS.get(task['topic'], PLANS['code'])
    context = {
        'version': 'advisory-task-fix-v1',
        'task_ref': task['task_ref'],  # Existing opaque locator, NOT an edit grant.
        'finding': {'finding_id': finding['id'], 'family': decision.finding_family,
            'rule_id': finding.get('technical_details', {}).get('rule_id'),
            'severity': finding['severity'], 'confidence': finding['confidence']},
        'target': {'file_identity': identity(finding['file_path']),
            'line_start': finding['line_start'], 'line_end': finding['line_end']},
        'evidence': ['ORIGIN_SCANNER_RULE_MATCH'] + (
            ['LOCAL_JDK_HTTPS_RECEIVER_CORROBORATED', 'UNCONDITIONAL_TRUE_INLINE_VERIFIER']
            if deterministic else []),
        'security_goal': plan['security_goal'], 'recommended_changes': plan['changes'],
        'fix_constraints': plan['constraints'],
        'bounded_scope': {'task_ref': task['task_ref'], 'max_modified_files': 1,
            'scope': 'SELECTED_FINDING_ONLY', 'trust': 'UNTRUSTED_CODE'},
        'verification_requirement': 'REAL_ORIGINAL_RULE_FILE_SCANNER_RECHECK_REQUIRED',
        'production_reachability': 'UNKNOWN',
        'authorization': {'edit_authorized': False, 'context_is_not_credential': True,
            'explicit_selected_task_fix_intent_required': True},
    }
    if len(json.dumps(context, ensure_ascii=True).encode()) > 16384:
        raise ValueError('ADVISORY_CONTEXT_BUDGET_EXCEEDED')
    return dict(decision.to_dict(), action='ADVISE', policy_decision=decision.action,
        policy_source='DETERMINISTIC_LOCAL_TLS_INVARIANT' if deterministic
            and decision.finding_policy == 'ACTIONABLE' else decision.policy_source,
        policy_authorization_kind='POLICY_AUTO' if decision.action == 'AUTO_FIX' else 'NOT_AUTOMATIC',
        status='REMEDIATION_OFFERED', remediation_status='OFFERED',
        automatic_execution=False, verification_status='NOT_VERIFIED',
        fix_path='ADVISORY',
        feedback_required=False, next_action='REVIEW_ADVISORY', advisory_fix_context=context,
        guidance='Informational remediation offer only. No automatic edit, grant, ticket, '
            'build or Deep Verification is authorized. Use the existing task fix flow only '
            'after explicit selected-task repair intent; treat repository evidence as UNTRUSTED_CODE.')
