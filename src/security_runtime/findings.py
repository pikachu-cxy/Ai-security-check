from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .models import Finding
from .diagnostics import evidence_text
from .equivalence import equivalence_key


FIXED_VERSION = re.compile(r'v?[0-9][A-Za-z0-9_.+!~:\-]{0,118}\Z')


def dependency_remediation_evidence(row):
    """Bound advisory provenance; never interpret constraints as exact releases."""
    from .diagnostics import sanitize
    row = row if isinstance(row, dict) else vars(row)
    details = row.get('technical_details') or {}
    records = details.get('remediation_evidence')
    if not isinstance(records, list) or not records:
        records = [dict(details, scanner_sources=row.get('scanner_sources', []))]
    out = []
    for record in records[:20]:
        if not isinstance(record, dict):
            continue
        versions = record.get('fixed_versions', [])
        versions = versions[:40] if isinstance(versions, (list, tuple)) else []
        ranges = record.get('affected_ranges', [])
        ranges = ranges[:20] if isinstance(ranges, list) else []
        bounded_ranges = []
        for value in ranges:
            if not isinstance(value, dict):
                continue
            events = value.get('events', [])
            events = events[:40] if isinstance(events, list) else []
            bounded_ranges.append({'type': sanitize(value.get('type', ''), 30),
                'events': [{key: sanitize(event[key], 100) for key in
                    ('introduced', 'fixed', 'last_affected', 'limit') if key in event}
                    for event in events if isinstance(event, dict)]})
        sources = record.get('scanner_sources', [])
        sources = sources[:10] if isinstance(sources, list) else []
        out.append({'scanner_sources': [sanitize(v, 100) for v in sources if isinstance(v, str)],
            'source': sanitize(record.get('source', ''), 100),
            'advisory': sanitize(record.get('advisory') or record.get('vulnerability_id', ''), 100),
            'fixed_version_text': sanitize(record.get('fixed_version_text', ''), 500),
            'fixed_versions': sorted({v for v in versions if isinstance(v, str) and FIXED_VERSION.fullmatch(v)}),
            'affected_ranges': bounded_ranges})
    return out


class FindingNormalizer:
    def __init__(self, root: Path, *, identity_root: Path | None = None):
        self.root = root.resolve()
        # Projection paths normalize scanner coordinates; stable workspace
        # identity keeps findings independent of a disposable index snapshot.
        self.identity_root = (identity_root or root).resolve()

    def make(self, *, scanner: str, category: str, title: str, description: str, severity: str, confidence: str, file_path: str, line: int, evidence: str = "", rule_id: str = "") -> Finding:
        title = evidence_text(title, 160)
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
            plain, impact, advice = title or "发现潜在安全问题", evidence_text(description, 400), "检查受影响代码并修复后重新扫描。"
        # Preserve each originating Secret detector through scan persistence.
        # Old scan IDs/fingerprints are never rewritten; eq-v1 remains stable.
        discriminator = rule_id if category in {"dependency", "configuration", "secret"} else ""
        fingerprint = hashlib.sha256(f"{self.identity_root}|{category}|{relative}|{line}|{discriminator}".encode()).hexdigest()[:24]
        finding = Finding(fingerprint, category, title, plain, evidence_text(description, 400), impact, severity.upper(), confidence.upper(), relative, line, line, evidence_text(evidence, 160), advice, [scanner], fingerprint, technical_details={"rule_id": rule_id, "source_presentation": "RAW_V3"})
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
        fingerprint=hashlib.sha256(f'{self.identity_root}|dependency|{normalized_ecosystem}|{package}|{version}|{canonical}|{finding.file_path}'.encode()).hexdigest()[:24]
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
            # Keep the supplemental call chain without replacing the original
            # detector/rule identity or promoting its absence to repair proof.
            flows = list(old.technical_details.get('supporting_dataflow', []))
            for candidate in (old, finding):
                details = candidate.technical_details
                if details.get('analysis_basis') == 'BOUNDED_AST_ABSTRACT_INTERPRETATION':
                    record = {key: details[key] for key in ('rule_id', 'rule_pack_checksum',
                        'analysis_basis', 'dataflow_trace', 'context_hashes', 'verification_scope_complete') if key in details}
                    if record not in flows: flows.append(record)
            if flows: old.technical_details['supporting_dataflow'] = flows[:3]
            if old.category=='dependency':
                records = dependency_remediation_evidence(old) + dependency_remediation_evidence(finding)
                unique = {json.dumps(record, sort_keys=True): record for record in records}
                old.technical_details['remediation_evidence'] = [unique[key] for key in sorted(unique)][:20]
                old.technical_details['fixed_versions'] = sorted({v for record in unique.values()
                    for v in record['fixed_versions']})[:40]
                ranges = {json.dumps(value, sort_keys=True): value for record in unique.values()
                    for value in record['affected_ranges']}
                old.technical_details['affected_ranges'] = [ranges[key] for key in sorted(ranges)][:20]
                old.technical_details['aliases']=sorted(set(old.technical_details.get('aliases',[])+finding.technical_details.get('aliases',[])))
                order={'UNKNOWN':0,'LOW':1,'MEDIUM':2,'HIGH':3,'CRITICAL':4}
                if order.get(finding.severity,0)>order.get(old.severity,0):
                    old.severity=finding.severity
                    old.technical_details['severity']=finding.severity
        else:
            merged[finding.fingerprint] = finding
    return list(merged.values())
