"""Product-owned Chinese risk reports from saved, version-checked facts."""
from pathlib import Path
from urllib.parse import quote
from pydantic import BaseModel, ConfigDict, Field
from .dashboard_presentation import present, section, chinese
from .redactor import SecretRedactor


class ReportContent(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    title: str = Field(default='', max_length=200)
    problem: str = Field(default='', max_length=2000)
    impact: str = Field(default='', max_length=2000)
    advice: str = Field(default='', max_length=2000)
    unknowns: str = Field(default='', max_length=2000)
    function_name: str = Field(default='', max_length=200)


def render_risk(item, workspace, *, reviewed):
    finding, assessment = item['finding'], item.get('assessment') or {}
    content = assessment.get('report_content') or {} if reviewed else {}
    legacy = assessment.get('report_text', '') if reviewed else ''
    display = dict(finding, advice=finding.get('fix_advice', ''), report_text=legacy)
    for field, target in [('title','title'), ('problem','description'), ('impact','impact'), ('advice','advice')]:
        if content.get(field):
            display[target] = content[field]
    # Structured fields take precedence over legacy prose, without changing saved facts.
    if content:
        display['report_text'] = ''
    p = present(display)['presentation']
    redact = SecretRedactor().redact
    details = finding.get('technical_details') or {}
    metadata = []
    for label, value in [('依赖', details.get('package')), ('版本', details.get('package_version') or details.get('installed_version')),
                         ('漏洞编号', details.get('vulnerability_id') or details.get('canonical_vulnerability_id')),
                         ('修复版本', details.get('fixed_version_text') or ', '.join(details.get('fixed_versions') or []))]:
        if value:
            metadata.append(f'{label}：{redact(str(value))[:500]}')
    severity = {'CRITICAL':'严重', 'HIGH':'高危', 'MEDIUM':'中危', 'LOW':'低危', 'INFO':'提示', 'UNRATED':'未评级'}.get(finding.get('severity'), '未评级')
    state = ('Agent 已确认' if item['decision'] == 'CONFIRMED' else 'Agent 复核后待确认') if reviewed else '扫描发现，未经 Agent 确认'
    path, line = finding['file_path'], finding['line_start']
    location = quote(str(Path(workspace) / path), safe='/:')
    label = path.replace('[', '\\[').replace(']', '\\]')
    function = content.get('function_name', '')
    parts = [f"**{p['title_zh']}**", f'{severity} · {state} · 风险编号 {item["id"]}',
             f'位置：[{label}:{line}]({location}:{line})' + (f' · 函数：{redact(function)}' if function else '')]
    if metadata:
        parts.append('；'.join(metadata))
    parts.extend([f"**问题**\n{p['technical_explanation_zh']}", f"**可能影响**\n{p['plain_impact_zh']}",
                  f"**建议修复**\n{p['advice_zh']}"])
    unknowns = content.get('unknowns') or section(legacy, '尚未确认')
    if reviewed and item['decision'] == 'INCONCLUSIVE':
        unknowns = assessment.get('rationale') or unknowns or '证据不足，尚未形成确定结论。'
    if unknowns:
        parts.append('**尚未确认**\n' + (redact(unknowns) if chinese(unknowns) else '存在待确认事项；原始说明保存在漏洞详情。'))
    return '\n\n'.join(parts)


def business_coverage(review):
    """Legacy limitations are retained as unknown coverage, not unreviewed work."""
    if review.get('uncovered'):
        return 'PARTIAL'
    return review.get('coverage') or ('UNKNOWN' if review.get('limitations') else 'COMPLETE')
