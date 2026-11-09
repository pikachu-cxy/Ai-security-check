"""Terminal reports must remain usable without a saved dashboard endpoint."""
import pytest

from security_runtime.development_views import batch_report_page


@pytest.mark.parametrize('url', [None, 'http://127.0.0.1:12345/risks?session=fixture'])
def test_false_positive_report_with_coverage_gap_and_optional_dashboard(monkeypatch, url):
    from security_runtime import dashboard_service
    monkeypatch.setattr(dashboard_service, 'session_url', lambda *a: url)
    monkeypatch.setattr(dashboard_service, 'ensure', lambda: pytest.fail('closeout must not start or wait for dashboard'))
    page = batch_report_page(dict(
        check_ref='fixture', risks=[], dirty_seq=1, scan_id='fixture-scan',
        next_action=None, next_offset=None, total=2,
        review_progress=dict(scanner_review='COMPLETE', pending_business_paths=[],
                             host_review_completed=True, business_review='SKIPPED_BY_CONFIG'),
        report_totals=dict(false_positives=2)), dict(
        workspace='fixture', owner=dict(host='cursor', session='fixture'),
        scanned_seq=1, result=dict(gaps=['SCANNER_COVERAGE_LIMITED'])))
    report = page['report_text']
    assert '2 条扫描告警为误报' in report
    assert page['session_url'] == url
    assert 'session_url: null' not in report
    if url:
        assert f'[本会话风险管理]({url})' in report
    else:
        assert 'SCANNER_COVERAGE_LIMITED' in report
        assert '链接暂不可用' in report
        assert '具体原因见本会话风险管理' not in report


def test_command_host_does_not_print_null_link():
    from security_runtime.host_development import session_context
    assert '不要输出 session_url: null' in session_context('fixture', 'fixture')


@pytest.mark.parametrize('host', ['codex', 'cursor'])
def test_global_dashboard_requires_no_workspace_or_scan(tmp_path, monkeypatch, host):
    import asyncio
    from security_runtime.global_mcp import create_global_server
    from security_runtime.monitoring import mcp
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'state'))
    monkeypatch.setattr(mcp, 'risk_dashboard_status', lambda: dict(status='AVAILABLE', url='http://127.0.0.1:12345/', scanner_run=False))
    server = create_global_server(host=host)
    try:
        monkeypatch.setattr(server.global_workspaces, 'admit', lambda *a, **kw: pytest.fail('dashboard must not admit a workspace'))
        tools = asyncio.run(server.list_tools())
        schema = next(t.inputSchema for t in tools if t.name == 'start_risk_dashboard')
        assert 'workspace_path' not in schema.get('required', [])
        result = asyncio.run(server.call_tool('start_risk_dashboard', {}))
        assert result.structuredContent['status'] == 'AVAILABLE'
        assert result.structuredContent['scanner_run'] is False
    finally:
        server.global_workspaces.close()
