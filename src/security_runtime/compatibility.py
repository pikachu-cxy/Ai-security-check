"""Shared delivery requirements; build identity is separate from execution proof."""
from __future__ import annotations
import re

CONTRACT = 'runtime-compatibility-v1'
TASK_RESULT_DELIVERY = 'task-result-delivery-v1'
TASK_REVIEW_TOOLS = frozenset({'begin_security_task', 'finish_security_task',
    'prepare_task_security_review', 'get_task_review_plan', 'get_task_review_method',
    'read_task_review_context', 'submit_task_review_batch', 'submit_task_security_review',
    'get_task_security_review'})


def requirements():
    return dict(contract=CONTRACT, task_review_protocol='task-review-plan-v3',
        task_result_delivery=TASK_RESULT_DELIVERY,
        required_task_tools=sorted(TASK_REVIEW_TOOLS), version_policy='ACTUAL_CAPABILITIES_AND_BUILD_NOT_SEMVER',
        legacy_tasks='READ_ONLY_NO_MIGRATION_OR_BASELINE_RECONSTRUCTION',
        independent_contracts='security-review-skill-v1; risk-decisions-v2',
        source_identity='runtime-build; state-schema; MCP-schema; Skill-core-and-method-digests; rules',
        vulnerability_data_freshness='SEPARATE_FROM_DELIVERY_COMPATIBILITY', security_proof=False)


def task_review_compatibility(info, tools=None):
    """Compare facts from one runtime; does not connect, scan or write state."""
    info = info if isinstance(info, dict) else {}
    features = info.get('features') or {}
    features = features if isinstance(features, dict) else {}
    advertised = features.get('task_security_review_protocol')
    reasons = []
    if not isinstance(advertised, str) or not re.search(r'(?<![a-z0-9-])task-review-plan-v3(?![a-z0-9-])', advertised):
        reasons.append('TASK_REVIEW_V3_REQUIRED')
    if features.get('task_security_result_delivery') != TASK_RESULT_DELIVERY:
        reasons.append('TASK_RESULT_DELIVERY_REQUIRED')
    build = info.get('build_identity') or {}
    build_id = build.get('build_id') if isinstance(build, dict) else None
    if not isinstance(build_id, str) or not re.fullmatch(r'[a-f0-9]{64}', build_id):
        reasons.append('RUNTIME_BUILD_UNVERIFIED')
    missing = sorted(TASK_REVIEW_TOOLS-set(tools)) if tools is not None else None
    if missing:
        reasons.append('TASK_REVIEW_TOOLS_MISSING')
    if tools is None:
        reasons.append('TOOL_DISCOVERY_REQUIRED')
    return dict(contract=CONTRACT, status='SUPPORTED' if not reasons else 'UPGRADE_OR_RECONNECT_REQUIRED',
        reasons=reasons, missing_tools=missing, build_id=build_id if 'RUNTIME_BUILD_UNVERIFIED' not in reasons else None,
        task_review_protocol=3, history_read_only=True, fallback_allowed=False,
        action='CONTINUE_SAME_V3_TASK' if not reasons else 'STOP_TASK_REVIEW_PRESERVE_ORIGINAL_TASK',
        security_proof=False, repair_authorized=False)


def tool_requirements(name):
    """Declarative adapter metadata, never a grant or substitute for service guards."""
    if name in TASK_REVIEW_TOOLS or name == 'get_task_risk_ledger':
        return dict(workflow='TASK_REVIEW', required_features=['task-review-plan-v3'],
                    guard='ORIGINAL_TASK_OWNER_VERSION_EVIDENCE_AND_CUMULATIVE_LEDGER')
    if 'disposition' in name or 'feedback' in name or 'false_positive' in name:
        return dict(workflow='RISK_HANDLING', required_features=['risk-disposition-v1'],
                    guard='EXACT_ORIGINAL_FINDING; USER_CHOICE_AND_TECHNICAL_ASSESSMENT_SEPARATE')
    if 'repair_impact' in name or name in {'prepare_task_risk_fix', 'cancel_task_risk_fix',
            'prepare_task_fix', 'confirm_remediation', 'refresh_remediation_confirmation',
            'verify_task_fix', 'generate_fix', 'verify'}:
        return dict(workflow='REPAIR', required_features=['repair-impact-v1'],
                    guard='PREPARATION_OR_HISTORY_GRANTS_NO_REPAIR; EDITING_REQUIRES_EXISTING_EXPLICIT_AUTHORITY')
    if name.startswith('handle_'):
        return dict(workflow='HOST_EVENT', required_features=['host-event-v1'],
                    guard='VERIFIED_WORKSPACE_SESSION_AND_EVENT; NO_IMPLICIT_REPAIR_AUTHORITY')
    return dict(workflow='EXPLICIT_AUDIT_AND_DISCOVERY', required_features=[],
                guard='READ_ONLY_DISCOVERY_OR_EXPLICIT_REQUESTED_SCAN_SCOPE')


def storage_contracts():
    """Package compatibility floor for implemented private persistent stores.

    This is independent of the runtime-state-v1 installation directory layout.
    It is a conservative release declaration, never migration, edit authority,
    publisher attestation or a replacement for the real old-writer fence.
    """
    return sorted(('task-risk-authority-v2', 'closure-authority-v2',
        'private-authority-writer-fence-v1', 'persistence-effect-v1',
        'task-risk-partition-v1', 'task-verification-journal-v1',
        'host-event-journal-v1', 'task-delivery-receipt-v1', 'native-intent-release-v1',
        'workspace-scan-attempt-v2', 'scan-publication-v1', 'closeout-persistence-v1'))
