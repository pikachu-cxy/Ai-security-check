"""User-invoked regression gate and fresh Windows candidate build.

Never installs into or restarts a running host. Run explicitly after installing
the repository's test/build dependencies into the selected Python environment.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime
import uuid

from dependency_notices import preflight


TESTS = (
    'tests/test_acceptance_review_history.py',
    'tests/test_acceptance_review_windows.py',
    'tests/test_acceptance_session_routing.py',
    'tests/test_acceptance_bootstrap_concurrency.py',
    'tests/test_acceptance_task_start_lock.py',
    'tests/test_finding_feedback.py',
    'tests/test_finding_feedback_mcp.py',
    'tests/test_feedback_contract_v2.py',
    'tests/test_finding_disposition.py',
    'tests/test_finding_disposition_dependency.py',
    'tests/tasks/test_task_risk_dispositions.py',
    'tests/guidance/test_risk_decision_experience.py',
    'tests/tasks/test_task_fix.py',
    'tests/test_fix_context.py',
    'tests/tasks/test_task_triage.py',
    'tests/tasks/test_task_risk_feedback.py',
    'tests/test_distribution.py',
    'tests/test_finding_quality.py',
    'tests/test_hook_user_feedback.py',
    'tests/test_hook_advice_feedback.py',
    'tests/test_hook_runtime.py',
    'tests/test_hook_dispositions.py',
    'tests/test_remediation.py',
    'tests/test_remediation_episodes.py',
    'tests/test_dependency_remediation.py',
    'tests/test_advisory_remediation.py',
    'tests/test_dependency_codex_advisory_integration.py',
    'tests/test_confirmation.py',
    'tests/test_codex_code_mode_contract.py',
    'tests/test_host_orchestration.py',
    'tests/test_review_mcp.py',
    'tests/test_professional_guidance.py',
    'tests/guidance/test_host_feedback_contract.py',
    'tests/test_codex_mcp_hook.py',
    'tests/test_cli_json_encoding.py',
    'tests/test_bootstrap_recovery.py',
    'tests/test_global_startup_wait.py',
    'tests/test_global_integration.py',
    'tests/test_hook_readiness_feedback.py',
    'tests/tasks/test_task_security.py',
    'tests/tasks/test_task_preimages.py',
    'tests/tasks/test_task_preimage_fingerprints.py',
    'tests/task_review/test_task_review_plan.py',
    'tests/task_review/test_task_review_adaptive_windows.py',
    'tests/task_review/test_task_review_adaptive_budget.py',
    'tests/task_review/test_task_review_transport_v3.py',
    'tests/task_review/test_task_review_redacted_changes.py',
    'tests/task_review/test_task_review_v3_state.py',
    'tests/task_review/test_task_review_invariants.py',
    'tests/task_review/test_task_review_completion_budget.py',
    'tests/task_review/test_task_review_protocol_mcp.py',
    'tests/tasks/test_task_context_global_transport.py',
    'tests/tasks/test_task_ownership.py',
    'tests/tasks/test_task_freshness_measurement.py',
    'tests/tasks/test_task_security_inventory.py',
    'tests/tasks/test_task_conditional_risks.py',
    'tests/tasks/test_task_measurement_report.py',
    'tests/tasks/test_task_hook_deferred_feedback.py',
    'tests/test_closeout_gaps.py',
    'tests/task_review/test_task_review_results.py',
    'tests/test_local_evidence_comments.py',
    'tests/test_review_evidence.py',
    'tests/guidance/test_review_skill.py',
    'tests/test_cursor_permissions.py',
    'tests/test_cursor_automatic.py',
    'tests/test_codex_host_claims.py',
    'tests/test_python_manifest.py',
    'tests/test_dependency_notices.py',
    'tests/test_dependency_fallback.py',
    'tests/test_trivy_capabilities.py',
    'tests/test_quick_dependency_runtime.py',
    'tests/test_dependency_hook_feedback.py',
    'tests/test_preparation_recovery_messages.py',
    'tests/test_preparation_download.py',
    'tests/test_adaptive_preparation_budget.py',
    'tests/test_background_preparation.py',
    'tests/test_standalone_documents.py',
    'tests/test_compliance.py::ComplianceTests::test_all_builtin_engines_have_reviewed_metadata_and_notices',
)


def main():
    if os.name != 'nt':
        raise SystemExit('This candidate workflow targets Windows; use the platform release workflow on other systems.')
    root = Path(__file__).resolve().parents[1]
    preflight()
    candidate = 'dependency-fix-' + datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    # A test repository must not inherit the product checkout's parent Git root.
    with tempfile.TemporaryDirectory(prefix='ai-security-fix-tests-') as temporary:
        subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '--basetemp',
                        str(Path(temporary) / 'cases'), *TESTS], cwd=root, check=True)
    subprocess.run([sys.executable, str(root / 'scripts/build_standalone.py'),
                    '--output-dir', 'dist/' + candidate,
                    '--work-dir', 'build/' + candidate], cwd=root, check=True)
    bundle = root / 'dist' / candidate / 'security-check'
    metadata = json.loads((bundle / 'version.json').read_text(encoding='utf-8'))
    receipt = {'bundle': str(bundle), 'executable': str(bundle / 'security-check.exe'),
               'build_id': metadata['build_id'], 'source_commit': metadata['source_commit'],
               'source_dirty': metadata['source_dirty'], 'tests': list(TESTS),
               'installed': False}
    # This pointer is informational. Installation still validates bundle hashes.
    output = root / 'artifacts' / 'dependency-fix-latest.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    print('Candidate built. Close the host before explicitly running install codex or install cursor.')


if __name__ == '__main__':
    main()
