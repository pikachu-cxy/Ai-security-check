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
    from .business_audit import fast_delivery
    deferred = fast_delivery(check)
    if progress['business_review'] != 'SKIPPED_BY_CONFIG' and not deferred:
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
                deferred_business_paths=progress['pending_business_paths'] if deferred else [],
                business_delivery='FAST_HOST_BACKGROUND' if deferred else 'WAIT_CURRENT_AUDIT',
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
    if not page.get('scan_id') or check['scanned_seq'] != page['dirty_seq']:
        # Development-time audit saves are durable, but are not a completed
        # static batch. Keep item reports in the ledger; avoid generating the
        # same final report both before and after the native Stop scan.
        from .dashboard_service import session_url
        page['session_url'] = session_url(check['workspace'], check['owner'])
        page['delivery_status'] = 'WAITING_FOR_STATIC_SCAN'
        page['delivery_instruction'] = ('业务审计结果已保存，静态扫描尚未发布。这是开发期保存回执，不是最终报告。'
            '本回合先只回复开发结果和实际验证，并说明安全报告待收尾；不要提前展开漏洞段落或复制子 Agent 报告。'
            '正常结束本回合以触发 Stop，不轮询、不重提、不主动启动扫描；Stop 续接后统一交付完整风险报告和链接。')
        return page
    sections, dismissed, duplicates = [], 0, 0
    explicit = set(check.get('explicit_paths', ()))
    unverified_writer = False
    from .business_audit import fast_delivery, status as audit_status
    progress = page['review_progress']
    deferred_business = bool(fast_delivery(check) and progress['pending_business_paths'])
    complete = progress['host_review_completed'] or (deferred_business and
        progress['scanner_review'] in {'COMPLETE', 'SKIPPED_BY_CONFIG'})
    scanner_skipped = progress['scanner_review'] == 'SKIPPED_BY_CONFIG'
    if scanner_skipped and progress['business_review'] == 'SKIPPED_BY_CONFIG':
        complete = True
    for item in page['risks']:
        assessment = item.get('assessment') or {}
        current = (assessment.get('dirty_seq'), assessment.get('scan_id')) == (page['dirty_seq'], page['scan_id'])
        audit = check.get('parallel_audit') or {}
        current = current or bool(assessment.get('audit_id') and assessment['audit_id'] == audit.get('audit_id')
            and audit.get('status') in {'COMPLETE', 'PARTIAL'} and audit.get('dirty_seq') == page['dirty_seq']
            and assessment.get('dirty_seq') == page['dirty_seq'])
        if item['decision'] == 'DISMISSED' and item['disposition'] == 'ACTIVE' and current:
            if assessment.get('duplicate_of'):
                duplicates += 1
            else:
                dismissed += 1
        if item['reminder_suppressed']:
            continue
        if scanner_skipped and item['decision'] not in {'CONFIRMED', 'DISMISSED'}:
            from pathlib import Path
            f = item['finding']
            location = str(Path(check['workspace']) / f['file_path'])
            sections.append(f"**{f['title']}**\n\n{f['severity']}（扫描器评级，未经 Agent 确认） · "
                f"[{f['file_path']}:{f['line_start']}]({location}:{f['line_start']})\n\n"
                f"**问题**\n{f.get('description') or '扫描器未提供详细说明。'}\n\n"
                f"**可能影响**\n{f.get('impact') or '尚未确认。'}\n\n"
                f"**建议修复**\n{f.get('fix_advice') or '需结合实际调用与防护确定修复方案。'}\n\n"
                '**尚未确认**\n本项仅为扫描候选，业务可达性、现有防护和利用条件未经 Agent 复核。')
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
    if deferred_business:
        labels = {'READY':'待派发','RUNNING':'进行中','UNSUPPORTED':'宿主不支持并行审计','NOT_STARTED':'尚未开始',
                  'PARTIAL':'已提交，但有覆盖限制','INTERRUPTED':'已中断','NEEDS_REVIEW':'源码更新，需补审','CANCELLED':'已取消','FAILED':'失败'}
        state = audit_status(check)['status']
        sections.append('业务逻辑审计'+labels.get(state, '尚未完成')+'；仍有 '+str(len(progress['pending_business_paths']))+
                        ' 个路径待审。本次先交付已保存的静态检查和复核结果，不能据此声称业务审计完成。')
    if complete:
        if page['next_offset'] is None:
            if page['scope_unknown']:
                sections.append('本次检查仅覆盖已记录的路径，部分改动范围未知。')
            if page['gaps']:
                sections.append('本次检查的覆盖缺口：' + '、'.join(page['gaps']) + '。')
        from .dashboard_service import session_url
        url = session_url(check['workspace'], check['owner'])
        page['session_url'] = url
        if url and (deferred_business or any((r['decision'] == 'CONFIRMED' or scanner_skipped) and not r['reminder_suppressed']
                       for r in page['risks'])):
            sections.append(f'[本会话风险管理]({url})')
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


def closeout_page(service, offset, limit, *, expected_seq=None, scan_id=None):
    """Resolve the saved Stop handoff without scanning, waiting or changing mode."""
    from .development_risks import require
    from .dashboard_service import session_url
    check = service.current_check()
    marker = check.get('stop_closeout_notice') or {}
    # A worker may finish between the short notice and this first read. Adopt
    # only the same edit sequence, never a later edit or a different page.
    if (marker.get('mode') == 'INCOMPLETE' and offset == 0 and expected_seq is None
            and scan_id is None and marker.get('seq') == check['dirty_seq']
            and check['scanned_seq'] == check['dirty_seq']
            and check['state'] in {'RESULTS_READY', 'PARTIAL'}
            and check.get('security_result', {}).get('imported_scan_id') == check.get('scan_id')
            and check.get('risk_import_status', 'AVAILABLE') == 'AVAILABLE'):
        from .development_risks import review_progress
        from .business_audit import fast_delivery
        work = review_progress(check, check['security_result'])
        review = work['pending_scanner_ids'] or (work['pending_business_paths'] and not fast_delivery(check))
        updated = dict(seq=check['dirty_seq'], scan_id=check.get('scan_id'), mode='REVIEW' if review else 'REPORT')
        with service.checks.transaction() as db:
            current = service.checks._get(db, service.ref)
            require(current.get('stop_closeout_notice') == marker and
                    (current['dirty_seq'], current.get('scan_id')) == (check['dirty_seq'], check.get('scan_id')),
                    'DEVELOPMENT_RISK_VERSION_STALE')
            service.checks._put(db, service.ref, dict(current, stop_closeout_notice=updated))
        marker = updated
    seq, scan = marker.get('seq'), marker.get('scan_id')
    require(expected_seq is not None or scan_id is None, 'DEVELOPMENT_RISK_INPUT_INVALID')
    require(marker.get('mode') in {'REVIEW', 'REPORT', 'INCOMPLETE'} and
            seq == check['dirty_seq'] and (marker['mode'] == 'INCOMPLETE' or scan == check.get('scan_id')) and
            (expected_seq is None or (expected_seq, scan_id) == (seq, scan)),
            'DEVELOPMENT_RISK_VERSION_STALE')
    require(type(offset) is int and offset >= 0 and type(limit) is int and 1 <= limit <= 20,
            'DEVELOPMENT_RISK_PAGE_INVALID')
    mode = marker['mode']
    if mode == 'REVIEW':
        page = service.get(offset, limit, include_history=False, review_only=True)
    elif mode == 'REPORT':
        page = service.get(offset, limit, include_history=False, batch_version=(seq, scan))
    else:
        job = check.get('parallel_audit') or {}
        items = [r for r in (check.get('security_result') or {}).get('risks', {}).values()
                 if (r.get('assessment') or {}).get('dirty_seq') == seq
                 and (r.get('assessment') or {}).get('audit_id') == job.get('audit_id')
                 and job.get('audit_id') and r.get('decision') == 'CONFIRMED'
                 and r.get('disposition', 'ACTIVE') == 'ACTIVE'
                 and r.get('status') != 'CODE_REVIEWED_RESOLVED']
        selected = items[offset:offset+limit]
        text = '\n\n'.join((r.get('assessment') or {}).get('report_text') or
                           f"已保存业务风险：{r['finding']['title']}（完整报告尚不可用）" for r in selected)
        text += '\n\n静态扫描尚未取得本轮完整结果，不能判定本轮没有其他漏洞。'
        if check['state'] == 'FAILED':
            text += '本批扫描已失败，失败记录保留，未自动重试。'
        if check.get('file_watch_gaps'):
            text += '文件变更收集存在缺口，尚未确认全部变更范围。'
        from .business_audit import status as audit_status
        audit = audit_status(check)
        if audit['status'] not in {'COMPLETE', 'DISABLED'}:
            label = {'FAILED':'失败', 'UNSUPPORTED':'宿主不支持', 'NOT_STARTED':'尚未开始',
                     'PARTIAL':'存在覆盖限制', 'INTERRUPTED':'已中断', 'NEEDS_REVIEW':'源码更新，需补审',
                     'CANCELLED':'已取消', 'READY':'待派发', 'RUNNING':'进行中'}.get(audit['status'], '未完成')
            text += '\n\n业务逻辑审计'+label+'；本次仅交付已保存的发现，不能据此声称业务审计完成。'
        page = dict(check_ref=service.ref, dirty_seq=seq, scan_id=scan,
                    report_text=text.strip(), scanner_run=False, risks=selected,
                    gaps=['STATIC_SCAN_INCOMPLETE', *check.get('file_watch_gaps', [])], scan_status=check['state'],
                    next_offset=offset+limit if offset+limit < len(items) else None,
                    total=len(items), next_action=None)
        page['business_audit'] = dict(status=audit['status'])
    page['closeout_mode'] = mode
    page['session_url'] = session_url(check['workspace'], check['owner'])
    if mode == 'INCOMPLETE' and page['session_url']:
        page['report_text'] += '\n\n[本会话风险管理]('+page['session_url']+')'
    if page.get('next_offset') is not None:
        page['next_action'] = dict(tool='get_development_risks', arguments=dict(
            workspace_path=str(service.root), check_ref=service.ref, view='closeout',
            offset=page['next_offset'], limit=limit, expected_seq=seq, scan_id=scan))
    elif mode == 'INCOMPLETE':
        page['next_action'] = None
    current = service.current_check()
    require(current.get('stop_closeout_notice') == marker and
            current['dirty_seq'] == seq and (mode == 'INCOMPLETE' or current.get('scan_id') == scan),
            'DEVELOPMENT_RISK_VERSION_STALE')
    return page
