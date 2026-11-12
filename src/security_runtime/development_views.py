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
    from .review_delivery import merge_windows, json_bytes, response_budget
    from .performance_trace import review_mark
    review_mark('evidence_plan_start')
    planned = merge_windows((w.file_path, w.start_line, w.end_line, w.related) for w in windows)
    review_mark('evidence_plan_done')
    evidence, errors = [], []
    remaining = response_budget(check) - 8192
    for path, start, end, related in planned:
        try:
            item = service.read(path, start, end, related=related)
            require(item['dirty_seq'] == version[0], 'DEVELOPMENT_RISK_VERSION_STALE')
            size = json_bytes(item)
            if size > remaining:
                errors.append(dict(file_path=path, start_line=start, end_line=end,
                                   related=related, reason_code='RESPONSE_BUDGET_EXCEEDED'))
                continue
            evidence.append(item)
            remaining -= size
        except (ValueError, OSError) as error:
            if getattr(error, 'reason_code', '') == 'DEVELOPMENT_RISK_VERSION_STALE':
                raise
            errors.append(dict(file_path=path, start_line=start, end_line=end,
                               related=related, reason_code=getattr(error, 'reason_code', 'EVIDENCE_READ_FAILED')))
    review_mark('evidence_ready')
    current = service.current_check()
    require((current['dirty_seq'], current.get('scan_id')) == version,
            'DEVELOPMENT_RISK_VERSION_STALE')
    return dict(dirty_seq=version[0], scan_id=version[1], evidence=evidence, errors=errors,
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
    from .development_risks import current_assessment
    confirmed = {}
    for risk in row['risks'].values():
        proof = risk.get('assessment') or {}
        finding = risk['finding']
        if (proof.get('stream_batch_id') and proof.get('decision') == 'CONFIRMED'
                and current_assessment(check, proof, finding['file_path'])):
            confirmed.setdefault(finding['file_path'], []).append(dict(id=risk['id'],
                **{k: finding[k] for k in ('title', 'category', 'line_start', 'line_end', 'description')}))
    scope = []
    if progress['scanner_review'] != 'SKIPPED_BY_CONFIG':
        for risk in row['risks'].values():
            original = next((o for o in risk['observations']
                             if o['source'] == 'SCANNER' and o.get('scan_id') == scan), None)
            if original:
                scope.append((risk['id'], original['finding']))
    result = check.get('result') or {}
    from .business_audit import fast_delivery, streaming, continuation
    deferred = fast_delivery(check)
    if progress['business_review'] != 'SKIPPED_BY_CONFIG' and not deferred and not streaming(check):
        excluded = result.get('generated_outputs', {}).get('excluded_paths', [])
        scope.extend((path, None) for path in sorted(set(check['observed_paths']) - set(excluded)))
    from .review_delivery import response_budget, json_bytes, collect_evidence
    budget = response_budget(check)
    evidence_budget = min(16384, (budget - 8192) // 2)
    available = budget - 8192 - evidence_budget
    candidates, paths = [], []
    consumed = 0
    positions = []
    for key, finding in scope[offset:offset+limit if limit is not None else len(scope)]:
        if finding is None:
            if key in progress['pending_business_paths']:
                if consumed and json_bytes(key) > available:
                    break
                paths.append(key)
                positions.append((offset+consumed, 'path', key))
                available -= json_bytes(key)
        elif key in pending:
            item = {k: finding[k] for k in ('title', 'severity', 'file_path', 'line_start', 'line_end')}
            if finding.get('description') and finding['description'] != finding['title']:
                item['description'] = finding['description']
            details = finding.get('technical_details') or {}
            item.update(id=key, same_issue_as=key, scanner_sources=finding.get('scanner_sources', []),
                        disposition=row['risks'][key].get('disposition', 'ACTIVE'))
            if confirmed.get(finding['file_path']):
                item['related_confirmed'] = confirmed[finding['file_path']][:8]
            for k in ('rule_id', 'rule_severity'):
                if details.get(k):
                    item[k] = details[k]
            cost = json_bytes(item) + 256
            if consumed and cost > available:
                break
            candidates.append(item)
            positions.append((offset+consumed, 'candidate', key))
            available -= cost
        consumed += 1
    explicit = set(check.get('explicit_paths', ()))
    for item in candidates:
        if check.get('file_watch') and item['file_path'] not in explicit:
            item['edit_attribution'] = 'OBSERVED_ONLY_WRITER_UNKNOWN'
    from .performance_trace import review_mark
    review_mark('evidence_start')
    evidence, evidence_errors, delivery_metrics = collect_evidence(service, candidates, paths, evidence_budget)
    review_mark('evidence_ready')
    for candidate in candidates:
        candidate['evidence_refs'] = [w['evidence_ref'] for w in evidence
            if w['file_path'] == candidate['file_path'] and w['line_start'] <= candidate['line_start']
            and w['line_end'] >= candidate['line_end']][:1]
        candidate['evidence_status'] = 'READY' if candidate['evidence_refs'] else 'MISSING'
    current = service.current_check()
    require((current['dirty_seq'], current.get('scan_id')) == (seq, scan), 'DEVELOPMENT_RISK_VERSION_STALE')
    next_offset = offset+consumed if offset+consumed < len(scope) else None
    page = dict(view='review', check_ref=service.ref, dirty_seq=seq, scan_id=scan, candidates_ready=True,
                scanner_review=progress['scanner_review'], business_review=progress['business_review'],
                submission_hint='已有候选直接复制该项 same_issue_as（非空字符串）及 evidence_refs，'
                                '在提交顶层传一次本页 scan_id，逐项填写 decision、rationale；确认项另填 report_text。'
                                'related_confirmed 是当前版本已保存的同文件审计发现，不是重复判定。证据确认同一问题时传 DISMISSED 和 duplicate_of（同批确认项或该已保存审计项 id），不同问题分别报告。',
                candidates=candidates, business_paths=paths, evidence=evidence, evidence_errors=evidence_errors,
                delivery_metrics=delivery_metrics, response_budget_bytes=budget, trust='UNTRUSTED_SOURCE',
                deferred_business_paths=progress['pending_business_paths'] if deferred else [],
                business_delivery='FAST_HOST_BACKGROUND' if deferred else 'WAIT_CURRENT_AUDIT',
                gaps=result.get('gaps', []), scope_unknown=check.get('scope_unknown', False), total=len(scope),
                next_offset=next_offset, next_action=None)
    from .review_delivery import fit_review_page
    page = fit_review_page(page, positions, budget)
    audit = continuation(check)
    if audit:
        page['audit_continuation'] = audit
        if not candidates and page['next_offset'] is None:
            page['next_action'] = audit['next_action']
    if page['next_offset'] is not None:
        page['next_action'] = dict(tool='get_development_risks', arguments=dict(
            workspace_path=str(service.root), check_ref=service.ref, view='review',
            expected_seq=seq, scan_id=scan, offset=page['next_offset'], limit=limit))
    return page


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
    from .performance_trace import review_mark
    review_mark('report_render_start')
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
        page['session_url'] = session_url(check['workspace'], check['owner'],
                                          check_ref=page.get('check_ref'), seq=page.get('dirty_seq'))
        page['link_in_report'] = False
        page['delivery_status'] = 'WAITING_FOR_STATIC_SCAN'
        page['delivery_instruction'] = ('业务审计结果已保存，静态扫描尚未发布。这是开发期保存回执，不是最终报告。'
            '本回合先只回复开发结果和实际验证，并说明安全报告待收尾；不要提前展开漏洞段落或复制子 Agent 报告。'
            '正常结束本回合以触发 Stop，不轮询、不重提、不主动启动扫描；Stop 续接后统一交付完整风险报告和链接。')
        return page
    from .business_audit import fast_delivery, status as audit_status
    from .development_report import render_risk
    from .dashboard_service import session_url
    progress = page['review_progress']
    scanner_skipped = progress['scanner_review'] == 'SKIPPED_BY_CONFIG'
    deferred = bool(progress['pending_business_paths'])
    complete = (progress['host_review_completed'] or
        (deferred and progress['scanner_review'] in {'COMPLETE', 'SKIPPED_BY_CONFIG'}) or
        (scanner_skipped and progress['business_review'] == 'SKIPPED_BY_CONFIG'))
    if not complete:
        return page  # Actual unsubmitted work still has a bounded continuation.
    sections = []
    totals = page.get('report_totals', {})
    if page.get('offset', 0) == 0 and (totals.get('confirmed') or totals.get('inconclusive')):
        scan_state = '本批已记录文件的扫描已完成。' if not page['gaps'] else '本批扫描结果已保存，存在扫描覆盖限制。'
        sections.append(scan_state + (' 扫描候选未经 Agent 复核。' if scanner_skipped else
            f" 已确认 {totals.get('confirmed', 0)} 项，待确认 {totals.get('inconclusive', 0)} 项。"))
    rendered_risks = 0
    for item in page['risks']:
        if item['reminder_suppressed']:
            continue
        assessment = item.get('assessment') or {}
        from .development_risks import current_assessment
        current = current_assessment(check, assessment, item['finding']['file_path'])
        if current or scanner_skipped:
            if rendered_risks:
                sections.append('---')
            sections.append(render_risk(item, check['workspace'], reviewed=current))
            rendered_risks += 1
    needs_link = bool(rendered_risks or totals.get('confirmed') or totals.get('inconclusive')
                      or totals.get('false_positives') or totals.get('duplicates') or page['gaps'])
    url = session_url(check['workspace'], check['owner'], check_ref=page['check_ref'],
                      scan_id=page['scan_id'], seq=page['dirty_seq'])
    page['session_url'] = url
    page['link_in_report'] = False
    if page['next_offset'] is None:
        if totals.get('duplicates'):
            sections.append(f"{totals['duplicates']} 条重复告警已关联到同批确认项。")
        if totals.get('false_positives'):
            sections.append(f"经复核，{totals['false_positives']} 条扫描告警为误报，无需处理。")
        if deferred:
            labels = {'READY':'待派发', 'RUNNING':'进行中', 'UNSUPPORTED':'当前宿主不支持', 'NOT_STARTED':'尚未开始',
                      'INTERRUPTED':'已中断', 'NEEDS_REVIEW':'源码更新，需补审', 'CANCELLED':'已取消', 'FAILED':'失败'}
            state = audit_status(check)['status']
            sections.append('业务逻辑审计'+labels.get(state, '尚未完成')+'；待审文件：'+
                            '、'.join(progress['pending_business_paths'])+'。')
        for gap in progress.get('business_coverage_gaps', []):
            reasons = '；'.join(gap['reasons']) or '未提供具体范围'
            label = '审计未覆盖' if gap['coverage'] == 'PARTIAL' else '历史审计覆盖范围待确认'
            sections.append(f"{label}：{gap['file_path']} — {reasons}")
        if page['gaps'] and page['total']:
            if url:
                sections.append('本次扫描存在覆盖限制，具体原因见本会话风险管理。')
            else:
                from .redactor import SecretRedactor
                reasons = '；'.join(SecretRedactor().redact(str(gap)) for gap in page['gaps'])
                sections.append('本次扫描存在覆盖限制：' + reasons + '。')
        if page['total'] == 0:
            sections.insert(0, '本批已记录文件的扫描已完成，未发现扫描候选漏洞。' if not page['gaps'] else
                            '本批扫描未发现扫描候选漏洞，但存在扫描覆盖限制。')
        if totals.get('actionable_confirmed'):
            sections.append('你可以选择：**修复／暂不处理**。可指定风险编号分别处理。')
        if needs_link:
            if url:
                sections.append(f'[本会话风险管理]({url})')
                page['link_in_report'] = True
            else:
                sections.append('本会话风险管理链接暂不可用；可请求打开风险管理页面查看连接诊断，检查结果已保留。')
    review_mark('report_render_done')
    return dict(report_text='\n\n'.join(sections), **page)


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
    if (marker.get('mode') in {'INCOMPLETE', 'REVIEW'} and offset == 0 and expected_seq is None
            and scan_id is None and marker.get('seq') == check['dirty_seq']
            and check['scanned_seq'] == check['dirty_seq']
            and check['state'] in {'RESULTS_READY', 'PARTIAL'}
            and check.get('scan_id')
            and check.get('security_result', {}).get('imported_scan_id') == check.get('scan_id')
            and check.get('risk_import_status', 'AVAILABLE') == 'AVAILABLE'):
        from .development_risks import review_progress
        from .business_audit import fast_delivery, streaming
        work = review_progress(check, check['security_result'])
        review = work['pending_scanner_ids'] or (work['pending_business_paths'] and
                                                not streaming(check) and not fast_delivery(check))
        updated = dict(seq=check['dirty_seq'], scan_id=check.get('scan_id'), mode='REVIEW' if review else 'REPORT')
        if updated != marker:
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
    require(type(offset) is int and offset >= 0 and (limit is None or type(limit) is int and 1 <= limit <= 20),
            'DEVELOPMENT_RISK_PAGE_INVALID')
    mode = marker['mode']
    if mode == 'REVIEW':
        from .development_risks import review_progress
        work = review_progress(check, check.get('security_result') or service.load())
        if not work['pending_scanner_ids'] and work['pending_business_paths']:
            page = service.get(offset, limit, include_history=False, batch_version=(seq, scan),
                               whole_report=limit is None)
        else:
            page = service.get(offset, limit, include_history=False, review_only=True)
    elif mode == 'REPORT':
        page = service.get(offset, limit, include_history=False, batch_version=(seq, scan), whole_report=limit is None)
    else:
        from .development_risks import current_assessment
        items = [r for r in (check.get('security_result') or {}).get('risks', {}).values()
                 if current_assessment(check, r.get('assessment'), r['finding']['file_path'])
                 and r.get('decision') == 'CONFIRMED'
                 and r.get('disposition', 'ACTIVE') == 'ACTIVE'
                 and r.get('status') != 'CODE_REVIEWED_RESOLVED']
        limit = limit or 20
        selected = items[offset:offset+limit]
        from .development_report import render_risk
        text = '\n\n---\n\n'.join(render_risk(r, check['workspace'], reviewed=True) for r in selected)
        reason = marker.get('reason')
        if reason == 'HOST_WAIT_LIMIT_REACHED':
            text += '\n\n已到达当前宿主允许的收尾等待上限，后台检查仍在继续；结果保存后沿本检查补交。'
        elif reason == 'RECOVERY_PENDING':
            text += '\n\n此前开发的安全检查正在沿原任务恢复；已保存的结果会直接复用，尚未完成的任务由后台继续。当前尚无完整结果，不能判定没有漏洞；结果保存后将在下一次收尾或会话输入时补交。'
        elif reason == 'RECOVERY_START_FAILED':
            text += '\n\n原安全检查未完成，后台恢复进程启动失败；原任务已保留，尚不能判定是否存在漏洞。'
        elif reason == 'RECOVERY_FAILED':
            text += '\n\n原安全检查恢复失败，已停止自动重试；原任务和已保存数据保留，尚不能判定是否存在漏洞。请检查产品连接、配置及本地文件访问状态后处理原任务。'
        elif reason == 'STOP_HANDOFF_INTERRUPTED':
            text += '\n\n此前开发的静态扫描未完成，不能判定此前修改没有其他漏洞。本次仅恢复原检查的未完成提示，不是对当前聊天发起安全扫描，没有自动补扫。'
        else:
            text += '\n\n静态扫描尚未取得本轮完整结果，不能判定本轮没有其他漏洞。'
        if reason == 'STOP_CLOSEOUT_FAILED':
            text += '收尾处理发生异常，原检查及已保存结果保留，没有重新提交扫描。'
        if check['state'] == 'FAILED':
            text += '本批扫描已失败，失败记录保留，未自动重试。'
        from .business_audit import status as audit_status
        audit = audit_status(check)
        if audit['status'] not in {'COMPLETE', 'DISABLED'}:
            label = {'FAILED':'失败', 'UNSUPPORTED':'宿主不支持', 'NOT_STARTED':'尚未开始',
                     'PARTIAL':'存在覆盖限制', 'INTERRUPTED':'已中断', 'NEEDS_REVIEW':'源码更新，需补审',
                     'CANCELLED':'已取消', 'READY':'待派发', 'RUNNING':'进行中'}.get(audit['status'], '未完成')
            text += '\n\n业务逻辑审计'+label+'；本次仅交付已保存的发现，不能据此声称业务审计完成。'
        page = dict(check_ref=service.ref, dirty_seq=seq, scan_id=scan,
                    report_text=text.strip(), scanner_run=False, risks=selected,
                    gaps=['STATIC_SCAN_INCOMPLETE', *([reason] if reason in {'STOP_HANDOFF_INTERRUPTED', 'STOP_CLOSEOUT_FAILED'} else [])],
                    observation_notes=list(check.get('file_watch_gaps', [])), scan_status=check['state'],
                    next_offset=offset+limit if offset+limit < len(items) else None,
                    total=len(items), next_action=None)
        page['business_audit'] = dict(status=audit['status'])
    page['closeout_mode'] = mode
    page['session_url'] = session_url(check['workspace'], check['owner'],
                                      check_ref=page.get('check_ref') or service.ref,
                                      scan_id=scan, seq=seq)
    if (mode == 'INCOMPLETE' and page['session_url']
            and page['session_url'] not in page.get('report_text', '')):
        page['report_text'] += '\n\n[本会话风险管理]('+page['session_url']+')'
        page['link_in_report'] = True
    if page.get('next_offset') is not None and page.get('view') != 'final_report':
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
