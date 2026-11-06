"""Compact MCP projections; never change saved risks or review requirements."""
from copy import deepcopy
from pydantic import BaseModel, ConfigDict, Field


class EvidenceWindow(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    file_path: str
    start_line: int = Field(default=1, ge=1)
    end_line: int = Field(default=80, ge=1)
    related: bool = False


def read_contexts(service, windows):
    from .development_risks import require
    check = service.current_check()
    version = (check['dirty_seq'], check.get('scan_id'))
    evidence, seen = [], set()
    for window in windows:
        key = (window.file_path, window.start_line, window.end_line, window.related)
        if key in seen:
            continue
        seen.add(key)
        # Sequential reads preserve the existing evidence transaction semantics.
        item = service.read(window.file_path, window.start_line, window.end_line,
                            related=window.related)
        require(item['dirty_seq'] == version[0], 'DEVELOPMENT_RISK_VERSION_STALE')
        evidence.append(item)
    current = service.current_check()
    require((current['dirty_seq'], current.get('scan_id')) == version,
            'DEVELOPMENT_RISK_VERSION_STALE')
    return dict(dirty_seq=version[0], scan_id=version[1], evidence=evidence,
                scanner_run=False, trust='UNTRUSTED_SOURCE', review_saved=False)


def pending_review_context(risks, page):
    """Collect bounded evidence for pending candidates visible on this page."""
    work = page['review_progress']
    candidates = []
    for risk in page['risks']:
        if risk['id'] in work['pending_scanner_ids']:
            finding = risk['finding']
            candidates.append(dict(id=risk['id'], **{k: finding[k] for k in
                ('title', 'severity', 'file_path', 'line_start', 'line_end')}))
    return candidates, pending_evidence(risks, candidates, work['pending_business_paths'])


def pending_evidence(risks, candidates, business_paths):
    windows = {}
    for finding in candidates:
        start = max(1, finding['line_start'] - 12)
        key = (finding['file_path'], start)
        windows[key] = max(windows.get(key, 0), min(start + 79, finding['line_end'] + 12))
    for path in business_paths:
        windows[(path, 1)] = 80
    evidence = []
    remaining = 16000
    for (path, start), end in list(windows.items())[:8]:
        try:
            item = risks.read(path, start, end)
        except (ValueError, OSError):
            continue  # Agent can request another window or record a coverage gap.
        size = len(item['content'].encode('utf-8'))
        if size > remaining:
            continue
        remaining -= size
        evidence.append({k: item[k] for k in ('file_path', 'line_start', 'line_end', 'content', 'evidence_ref')})
    return evidence


def review_page(service, check, row, progress, offset, limit):
    """Page the fixed scan scope so saving a batch cannot shift later offsets."""
    from .development_risks import require
    seq, scan = check['dirty_seq'], check.get('scan_id')
    require(scan and seq == check['scanned_seq'], 'DEVELOPMENT_RISK_VERSION_STALE')
    pending = set(progress['pending_scanner_ids'])
    scope = []
    if progress['scanner_review'] != 'SKIPPED_BY_CONFIG':
        for risk in row['risks'].values():
            original = next((o for o in risk['observations']
                             if o['source'] == 'SCANNER' and o.get('scan_id') == scan), None)
            if original:
                scope.append((risk['id'], original['finding']))
    result = check.get('result') or {}
    if progress['business_review'] != 'SKIPPED_BY_CONFIG':
        excluded = result.get('generated_outputs', {}).get('excluded_paths', [])
        scope.extend((path, None) for path in sorted(set(check['observed_paths']) - set(excluded)))
    candidates, paths = [], []
    for key, finding in scope[offset:offset+limit]:
        if finding is None:
            if key in progress['pending_business_paths']:
                paths.append(key)
        elif key in pending:
            item = {k: finding[k] for k in ('title', 'severity', 'file_path', 'line_start', 'line_end')}
            if finding.get('description') and finding['description'] != finding['title']:
                item['description'] = finding['description']
            details = finding.get('technical_details') or {}
            item.update(id=key, same_issue_as=key, scanner_sources=finding.get('scanner_sources', []),
                        disposition=row['risks'][key].get('disposition', 'ACTIVE'))
            for k in ('rule_id', 'rule_severity'):
                if details.get(k):
                    item[k] = details[k]
            candidates.append(item)
    explicit = set(check.get('explicit_paths', ()))
    for item in candidates:
        if check.get('file_watch') and item['file_path'] not in explicit:
            item['edit_attribution'] = 'OBSERVED_ONLY_WRITER_UNKNOWN'
    from .performance_trace import review_mark
    review_mark('evidence_start')
    evidence = pending_evidence(service, candidates, paths)
    review_mark('evidence_ready')
    for candidate in candidates:
        candidate['evidence_refs'] = [w['evidence_ref'] for w in evidence
            if w['file_path'] == candidate['file_path'] and w['line_start'] <= candidate['line_start']
            and w['line_end'] >= candidate['line_end']][:1]
    current = service.current_check()
    require((current['dirty_seq'], current.get('scan_id')) == (seq, scan), 'DEVELOPMENT_RISK_VERSION_STALE')
    return dict(view='review', check_ref=service.ref, dirty_seq=seq, scan_id=scan, candidates_ready=True,
                scanner_review=progress['scanner_review'], business_review=progress['business_review'],
                submission_hint='已有候选直接复制该项 same_issue_as（非空字符串）及 evidence_refs，'
                                '在提交顶层传一次本页 scan_id，逐项填写 decision、rationale；确认项另填 report_text。重复命中传 DISMISSED 和 duplicate_of（同批确认项 id）。',
                candidates=candidates, business_paths=paths, evidence=evidence, trust='UNTRUSTED_SOURCE',
                gaps=result.get('gaps', []), scope_unknown=check.get('scope_unknown', False), total=len(scope),
                next_offset=offset+limit if offset+limit < len(scope) else None)


def risk_summary(result):
    result = deepcopy(result)
    for item in result.get('risks', []):
        assessment = item.get('assessment')
        if assessment:
            # The current finding is already present at item.finding.
            assessment.pop('finding', None)
            assessment.pop('source_hashes', None)
    result['view'] = 'summary'
    result['detail_access'] = dict(tool='get_development_risks',
                                 arguments=dict(check_ref=result['check_ref'], view='full'))
    return result


def batch_report_page(result, check):
    """Only reuse saved prose after checking this version's decisions and dispositions."""
    page = risk_summary(result)
    page['view'] = 'batch'
    page['gaps'] = (check.get('result') or {}).get('gaps', [])
    page['scope_unknown'] = check.get('scope_unknown', False)
    if page['next_action']:
        page['next_action']['arguments'].update(view='batch', expected_seq=page['dirty_seq'], scan_id=page['scan_id'])
    sections, dismissed, duplicates = [], 0, 0
    explicit = set(check.get('explicit_paths', ()))
    unverified_writer = False
    complete = page['review_progress']['host_review_completed']
    for item in page['risks']:
        assessment = item.get('assessment') or {}
        current = (assessment.get('dirty_seq'), assessment.get('scan_id')) == (page['dirty_seq'], page['scan_id'])
        if item['decision'] == 'DISMISSED' and item['disposition'] == 'ACTIVE' and current:
            if assessment.get('duplicate_of'):
                duplicates += 1
            else:
                dismissed += 1
        if item['reminder_suppressed']:
            continue
        if current and assessment.get('report_text') and item['decision'] == 'CONFIRMED':
            sections.append(assessment['report_text'])
            if check.get('file_watch') and item['finding']['file_path'] not in explicit:
                unverified_writer = True
        else:
            complete = False
    if unverified_writer:
        sections.append('以上经 Shell 监听发现的风险仅能定位到工作区文件，写入会话未经确认。')
    if duplicates:
        sections.append(f'{duplicates} 条重复告警已关联到同批确认项。')
    if dismissed:
        sections.append(f'经复核，{dismissed} 条扫描告警为误报，无需处理。')
    if complete:
        if page['next_offset'] is None:
            if page['scope_unknown']:
                sections.append('本次检查仅覆盖已记录的路径，部分改动范围未知。')
            if page['gaps']:
                sections.append('本次检查的覆盖缺口：' + '、'.join(page['gaps']) + '。')
        return dict(report_text='\n\n'.join(sections), **page)
    return page


def final_report_receipt(page):
    if (page.get('view') != 'batch' or not page.get('review_saved')
            or not page.get('post_commit_read') or page['reread_required']
            or page['next_offset'] is not None or page['next_action']
            or not page['review_progress']['host_review_completed'] or not page.get('report_text', '').strip()
            or any(r['disposition'] != 'ACTIVE' or r['decision'] not in {'CONFIRMED', 'DISMISSED'}
                   or r['status'] == 'CODE_REVIEWED_RESOLVED'
                   or (r.get('assessment') or {}).get('dirty_seq') != page['dirty_seq']
                   or (r.get('assessment') or {}).get('scan_id') != page['scan_id']
                   for r in page['risks'])):
        return page
    keys = ('check_ref', 'scan_id', 'dirty_seq', 'review_saved', 'post_commit_read',
            'reread_required', 'next_action', 'next_offset', 'total', 'gaps', 'scope_unknown', 'report_text')
    return dict(view='final_report', contract='development-final-report-v1', host_review_completed=True,
                **{key: page[key] for key in keys})


def review_receipt(result):
    # A preview cannot replace the required post-submit read. Return only the
    # saved version/progress and its issued next action, not the same risks twice.
    keys = ('contract', 'check_ref', 'scan_id', 'dirty_seq', 'review_progress',
            'next_action', 'review_version_count', 'scanner_run', 'source_freshness',
            'repair_authorized', 'decision_policy')
    receipt = {key: result[key] for key in keys if key in result}
    receipt.update(review_saved=True, reread_required=True, host_report_submitted=False)
    return receipt
