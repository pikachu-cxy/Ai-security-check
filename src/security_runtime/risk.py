from .models import Finding


class RiskEngine:
    def assess(self, findings: list[Finding], complete: bool = True) -> str:
        if any(f.severity in {"HIGH", "CRITICAL"} and f.confidence == "HIGH" and (f.evidence or len(f.scanner_sources) > 1) for f in findings):
            return "BLOCKED"
        if findings or not complete:
            return "REVIEW"
        return "SAFE"


MESSAGES = {"SAFE": "当前未发现阻止提交的问题", "REVIEW": "建议确认以下问题", "BLOCKED": "建议先处理以下问题再继续"}
