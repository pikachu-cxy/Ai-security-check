from .models import Finding


class RiskEngine:
    def assess(self, findings: list[Finding], complete: bool = True) -> str:
        if any(f.severity in {"HIGH", "CRITICAL"} and f.confidence == "HIGH" and (f.evidence or len(f.scanner_sources) > 1) for f in findings):
            return "BLOCKED"
        if findings or not complete:
            return "REVIEW"
        return "NO_FINDINGS"


NO_FINDINGS_MESSAGE = "本次已执行规则范围内未发现候选安全问题；这不能证明项目安全。"
MESSAGES = {"NO_FINDINGS": NO_FINDINGS_MESSAGE,
            "REVIEW": "建议确认以下问题", "BLOCKED": "建议先处理以下问题再继续"}


def presentation_status(release_status, *, finding_count, status, execution_state, coverage):
    """Translate historical SAFE snapshots without rewriting persisted policy.

    An empty completed scan means only that the executed rules found no
    candidates. Missing execution or coverage cannot become a clean result.
    """
    if release_status != "SAFE":
        return release_status
    if status in {"NO_CHANGES", "NOT_APPLICABLE"} or execution_state in {"NO_CHANGES", "NOT_APPLICABLE"}:
        return "NOT_ASSESSED"
    if finding_count or status != "COMPLETED" or execution_state != "EXECUTED" or coverage not in {"FULL", "SCOPED"}:
        return "REVIEW"
    return "NO_FINDINGS"
