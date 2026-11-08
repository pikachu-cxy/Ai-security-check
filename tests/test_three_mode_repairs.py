"""Regressions from real host acceptance: version isolation and complete delivery."""
from test_development_risks import sample, scanner
from security_runtime.audit_stream_service import manage, process


def scanner_review(sample, monkeypatch, decision):
    root, service, ref, risks = sample
    scanner(sample, monkeypatch)
    risks.sync_scanner()
    risk_id = risks.get()['review_progress']['pending_scanner_ids'][0]
    evidence = risks.read('query.py', 1, 2)['evidence_ref']
    observation = dict(same_issue_as=risk_id, scan_id='scan-1', decision=decision,
                       rationale='Validated this fixture input boundary.', evidence_refs=[evidence])
    risks.submit([observation], risks.current_check()['dirty_seq'])
    return risk_id


def test_previous_dismissal_does_not_suppress_new_unreviewed_hit(sample, monkeypatch):
    root, service, ref, risks = sample
    risk_id = scanner_review(sample, monkeypatch, 'DISMISSED')
    (root/'query.py').write_text('def query(conn, new_name):\n    return conn.execute(new_name)\n')
    service.record(root, ref, ['query.py'])
    with risks.checks.transaction() as db:
        check = risks.checks._get(db, ref)
        check.update(scan_id='scan-2', scanned_seq=check['dirty_seq'])
        check['effective_config']['values']['agent'].update(review_scanner_findings=False, audit_business_logic=False)
        risks.checks._put(db, ref, check)
    risks.sync_scanner()
    item = next(r for r in risks.get()['risks'] if r['id'] == risk_id)
    assert item['decision'] == 'INCONCLUSIVE' and not item['reminder_suppressed']
    assert risks.load()['risks'][risk_id]['decision'] == 'DISMISSED', 'history must not be rewritten'
    page = risks.get(batch_version=(check['dirty_seq'], 'scan-2'), whole_report=True)
    assert '未经 Agent 复核' in page['report_text'] and '误报，无需处理' not in page['report_text']
    assert 'query.py' in page['report_text']


def test_saved_static_report_survives_pending_business_audit(sample, monkeypatch):
    root, service, ref, risks = sample
    scanner_review(sample, monkeypatch, 'CONFIRMED')
    token = manage(risks, 'prepare')['audit_token']
    manage(risks, 'started', agent_ref='real-child', audit_token=token)
    check = risks.current_check()
    page = risks.get(batch_version=(check['dirty_seq'], 'scan-1'), whole_report=True)
    assert not page['host_review_completed']
    assert page['delivery_status'] == 'STATIC_REPORT_READY_AUDIT_PENDING'
    assert page['audit_continuation']['agent_ref'] == 'real-child'
    assert page['audit_continuation']['next_action'] is None
    assert page['next_action'] is None, 'small saved report must not require another static read'
    assert all(x in page['report_text'] for x in ['query.py', '**问题**', '**可能影响**', '**建议修复**'])


def test_product_handoff_direct_save_without_extra_read(sample):
    root, service, ref, risks = sample
    prepared = manage(risks, 'prepare')
    registered = manage(risks, 'started', agent_ref='real-child', audit_token=prepared['audit_token'])
    call = registered['child_call']
    assert call['arguments']['check_ref'] == ref and call['arguments']['workspace_path'] == str(root)
    assert call['arguments']['agent_ref'] == 'real-child'
    args = {k: call['arguments'][k] for k in ['audit_token', 'agent_ref']}
    claimed = process(risks, 'claim', **args)
    assert claimed['context']['evidence']
    evidence = claimed['context']['evidence'][0]['evidence_ref']
    result = process(risks, 'submit', batch_id=claimed['batch']['batch_id'], request_id='direct-save-first',
                     business_reviews=[dict(file_path='query.py', rationale='Reviewed fixed source and input boundary.',
                         evidence_refs=[evidence], coverage='COMPLETE', limitations=[])], **args)
    assert result['review_saved'] and result['next_batch']['batch']['batch_id'] is None
    assert len(risks.load()['reviews']) == 1


def test_failed_executor_status_keeps_pending_paths(sample):
    risks = sample[3]
    token = manage(risks, 'prepare')['audit_token']
    manage(risks, 'started', agent_ref='child', audit_token=token)
    result = manage(risks, 'failed', agent_ref='child')
    assert result['status'] == 'FAILED' and result['pending_paths'] == ['query.py']
    from security_runtime.business_audit import status
    assert status(risks.current_check())['status'] == 'FAILED'


def test_static_review_links_current_business_finding_without_extra_read(sample, monkeypatch):
    from test_audit_stream_service import child
    risks, args, batch, review = child(sample)
    finding = dict(issue_key='same-query', file_path='query.py', line_start=1, line_end=1,
        category='sql-injection', title='查询注入', description='请求输入进入拼接查询',
        impact='可能读取其他记录', fix_advice='绑定查询参数', severity='HIGH', decision='CONFIRMED',
        rationale='固定证据包含输入和执行位置。', evidence_refs=review['evidence_refs'])
    process(risks, 'submit', batch_id=batch['batch_id'], request_id='business-first',
            observations=[finding], business_reviews=[review], **args)
    primary = next(iter(risks.load()['risks']))
    scanner(sample, monkeypatch)
    risks.sync_scanner()
    page = risks.get(review_only=True)
    candidate = page['candidates'][0]
    assert candidate['related_confirmed'][0]['id'] == primary
    result = risks.submit([dict(same_issue_as=candidate['id'], decision='DISMISSED',
        duplicate_of=primary, rationale='同一输入至同一查询执行，业务审计已保存。',
        evidence_refs=candidate['evidence_refs'])], page['dirty_seq'], scan_id=page['scan_id'], return_risks=True, final_report=True)
    assert result['review_saved']
    report = risks.get(batch_version=(page['dirty_seq'], page['scan_id']), whole_report=True)
    assert report['report_text'].count('**查询注入**') == 1
    assert '重复告警' in report['report_text']
    assert '误报，无需处理' not in report['report_text']


def test_old_business_finding_is_not_offered_as_current_duplicate(sample, monkeypatch):
    from test_audit_stream_service import child
    risks, args, batch, review = child(sample)
    process(risks, 'submit', batch_id=batch['batch_id'], request_id='old-business',
        observations=[dict(issue_key='old', file_path='query.py', line_start=1, line_end=1,
          category='sql-injection', title='旧问题', description='旧版本问题', impact='旧影响',
          fix_advice='绑定参数', severity='HIGH', decision='CONFIRMED', rationale='旧证据',
          evidence_refs=review['evidence_refs'])], business_reviews=[review], **args)
    (sample[0]/'query.py').write_text('def query(conn, value):\n    return conn.execute(value + "changed")\n')
    sample[1].record(sample[0], sample[2], ['query.py'])
    scanner(sample, monkeypatch)
    risks.sync_scanner()
    assert not risks.get(review_only=True)['candidates'][0].get('related_confirmed')
