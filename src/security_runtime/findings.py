from __future__ import annotations

import hashlib
from pathlib import Path

from .models import Finding
from .redactor import SecretRedactor
from .equivalence import equivalence_key


class FindingNormalizer:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.redactor = SecretRedactor()

    def make(self, *, scanner: str, category: str, title: str, description: str, severity: str, confidence: str, file_path: str, line: int, evidence: str = "", rule_id: str = "") -> Finding:
        title = self.redactor.redact(title)[:160]
        path = Path(file_path)
        if path.is_absolute():
            try:
                path = path.resolve().relative_to(self.root)
            except ValueError:
                path = Path("[outside workspace]")
        relative = path.as_posix()
        category = category.lower()
        if category == "secret":
            plain, impact, advice = "代码中包含一个可能有效的密钥", "密钥泄露可能让他人访问系统或数据。", "立即撤销密钥，并改用环境变量或密钥管理服务。"
        elif category == "command-injection":
            plain, impact, advice = "用户输入可能被用于执行系统命令", "攻击者可能通过构造输入执行服务器命令。", "避免拼接命令；使用安全 API 并验证输入。"
        else:
            plain, impact, advice = title or "发现潜在安全问题", self.redactor.redact(description)[:400], "检查受影响代码并修复后重新扫描。"
        discriminator = rule_id if category in {"dependency", "configuration"} else ""
        fingerprint = hashlib.sha256(f"{self.root}|{category}|{relative}|{line}|{discriminator}".encode()).hexdigest()[:24]
        finding = Finding(fingerprint, category, title, plain, self.redactor.redact(description)[:400], impact, severity.upper(), confidence.upper(), relative, line, line, self.redactor.redact(evidence)[:160], advice, [scanner], fingerprint, technical_details={"rule_id": rule_id})
        finding.equivalence_key = equivalence_key(finding)
        return finding

    def dependency(self, *, scanner, package, version, ecosystem, manifest,
                   vulnerability_id, aliases=(), severity='UNKNOWN', title='', description='', source=''):
        from .diagnostics import sanitize
        package,version,ecosystem,vulnerability_id = (sanitize(value,200) for value in (package,version,ecosystem,vulnerability_id))
        aliases=sorted({sanitize(value,100) for value in aliases if isinstance(value,str)})
        canonical=next((value for value in sorted({vulnerability_id,*aliases}) if value.startswith('CVE-')),vulnerability_id)
        normalized_ecosystem={'pip':'pypi','python':'pypi','node-pkg':'npm','jar':'maven','pom':'maven','gomod':'go'}.get(ecosystem.lower(),ecosystem.lower())
        severity={'MODERATE':'MEDIUM','IMPORTANT':'HIGH'}.get(str(severity).upper(),str(severity).upper())
        if severity not in {'CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'}:
            severity='UNKNOWN'
        finding=self.make(scanner=scanner,category='dependency',title=title or canonical,description=description,
                          severity=severity,confidence='MEDIUM',file_path=manifest,line=1,rule_id=vulnerability_id)
        fingerprint=hashlib.sha256(f'{self.root}|dependency|{normalized_ecosystem}|{package}|{version}|{canonical}|{finding.file_path}'.encode()).hexdigest()[:24]
        finding.id=finding.fingerprint=fingerprint
        finding.technical_details.update(package=package,package_version=version,installed_version=version,ecosystem=normalized_ecosystem,
            manifest=finding.file_path,vulnerability_id=vulnerability_id,canonical_vulnerability_id=canonical,
            aliases=aliases,severity=severity,source=source)
        finding.equivalence_key = equivalence_key(finding)
        return finding


def deduplicate(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        if finding.fingerprint in merged:
            old = merged[finding.fingerprint]
            old.scanner_sources = sorted(set(old.scanner_sources + finding.scanner_sources))
            old.equivalence_key = equivalence_key(old)
            if old.category=='dependency':
                old.technical_details['aliases']=sorted(set(old.technical_details.get('aliases',[])+finding.technical_details.get('aliases',[])))
                order={'UNKNOWN':0,'LOW':1,'MEDIUM':2,'HIGH':3,'CRITICAL':4}
                if order.get(finding.severity,0)>order.get(old.severity,0):
                    old.severity=finding.severity
                    old.technical_details['severity']=finding.severity
        else:
            merged[finding.fingerprint] = finding
    return list(merged.values())
