"""Comparison readiness is distinct from a claim of full security coverage."""
from .models import RunStatus
from .rule_coverage import SASTRulePlan


def comparison_usable(result, observation):
    """Accept localized code gaps, never failed engines or missing rule proof.

    Coverage/capability values remain PARTIAL/NOT_COVERED in the stored baseline.
    Only the supported rule/file comparison is usable; absence in unsupported
    files cannot resolve a family or authorize a repair.
    """
    if (result['status'] == 'SCANNED' and result['coverage'] in {'FULL', 'SCOPED'}
            and all(v in {'EXECUTED', 'NOT_APPLICABLE'} for v in result['capabilities'].values())):
        return True
    states = result['capabilities']
    if (result['status'] != 'PARTIAL' or result['coverage'] != 'PARTIAL'
            or states.get('CODE_SAST') not in {'PARTIAL', 'NOT_COVERED'}
            or any(v not in {'EXECUTED', 'NOT_APPLICABLE'} for k, v in states.items() if k != 'CODE_SAST')):
        return False
    plan = (observation['plans'].get('opengrep') or observation['plans'].get('semgrep'))
    run = next((r for r in observation['runs'] if r.scanner == getattr(plan, "engine_id", "opengrep")), None)
    if not isinstance(plan, SASTRulePlan) or run is None or run.coverage_contract != 'FULL':
        return False
    recognized = {name for names in plan.language_files.values() for name in names}
    unsupported = recognized - set(plan.files)
    if (not (unsupported or plan.errored_files) or plan.unscoped_error or plan.skipped_files
            or not plan.errored_files.issubset(plan.files)):
        return False
    if not plan.rules:
        return not plan.files and run.status == RunStatus.NOT_COVERED
    return (run.status == RunStatus.SUCCESS
            and bool(set(plan.files) - plan.errored_files)
            and (set(plan.files) - plan.errored_files).issubset(plan.scanned_files)
            and {r.rule_id for r in plan.rules}.issubset(plan.confirmed_rules))


def unproven_files(observation):
    """Paths without SAST absence/attribution proof, never source or logs."""
    plan = (observation['plans'].get('opengrep') or observation['plans'].get('semgrep'))
    if not isinstance(plan, SASTRulePlan):
        return []
    recognized = {name for names in plan.language_files.values() for name in names}
    return sorted((recognized - set(plan.files)) | plan.errored_files)
