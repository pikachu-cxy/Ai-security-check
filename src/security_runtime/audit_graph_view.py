"""Read-only projections of the saved, version-bound local audit graphs."""
from collections import Counter
from contextlib import closing
import hashlib
import os
from pathlib import Path
import re


GAPS = {
    'SOURCE_UNREADABLE': '文件不可读，未生成源码片段',
    'EMPTY_FILE': '文件没有可取证源码行',
    'CHANGED_LINES_UNKNOWN': '未定位到变更行，使用文件前 80 行',
    'CHECK_PATH_DIFF_NOT_SESSION_ATTRIBUTED': '片段由已记录路径的 HEAD 差异定位，行级编辑归属未知',
    'INITIAL_PATH_BUDGET': '初始取证文件数达到上限',
    'INITIAL_EVIDENCE_WINDOW_LIMIT': '部分源码片段未取得同版本证据',
    'ASSET_GRAPH_RESPONSE_LIMIT': '达到资产首包的响应容量上限',
    'RESPONSE_BUDGET_EXCEEDED': '证据读取超出响应容量',
    'EVIDENCE_READ_FAILED': '证据读取失败',
    'DEVELOPMENT_RISK_RANGE_INVALID': '证据行范围超出文件',
    'DEVELOPMENT_RISK_PATH_NOT_OBSERVED': '路径不在本轮已记录范围',
}


def graphs(check):
    from .incremental_audit import progress

    stream = check.get('audit_stream') or {}
    round_id = progress(check).get('round_id')
    job = check.get('deep_audit')
    if job and job['dirty_seq'] == check['dirty_seq'] and job['round_id'] == round_id:
        nodes = []
        for task in job['tasks']:
            result = task.get('result', {})
            nodes.append(dict(id=task['id'], kind='TASK', title=task['direction'],
                question=task['question'], acceptance=task['acceptance'], state=task['state'],
                planner_decision=task.get('planner_decision', 'PENDING'), wave=task['wave'],
                asset_ids=task['asset_ids'], depends_on=task['depends_on'],
                conclusion=result.get('conclusion'), hypotheses=result.get('hypotheses', []),
                evidence_refs=result.get('evidence_refs', []), gaps=result.get('gaps', [])))
        return dict(round_id=round_id, dirty_seq=check['dirty_seq'], asset_graph=job['asset_graph'],
                    board=(job.get('board') or {}).get('entries', []),
                    audit_graph=dict(tasks=nodes, status=job['stage'], stop_reason=job.get('stop_reason'),
                                     gaps=job.get('gaps', []), reviewed_paths=job.get('reviewed_paths', [])))
    assets, links, gaps, tasks = {}, [], [], []
    result = progress(check)
    for batch in stream.get('batches', {}).values():
        graph = batch.get('asset_graph')
        if not graph or batch['round_id'] != round_id or batch.get('asset_graph_seq') != check['dirty_seq']:
            continue
        assets.update((node['id'], node) for node in graph['nodes'])
        links.extend(graph['edges'])
        gaps.extend(graph['gaps'])
        receipt = stream.get('receipts', {}).get(batch.get('request_id'), {})
        reviews = receipt.get('payload', {}).get('business_reviews', [])
        for item in reviews:
            if item['file_path'] not in receipt.get('applied_paths', []):
                continue
            tasks.append(dict(id=batch['batch_id'] + ':' + item['file_path'], kind='TASK',
                title=item['file_path'], state=item.get('coverage') or 'UNKNOWN',
                asset_ids=[n['id'] for n in graph['nodes'] if n['file_path'] == item['file_path']],
                depends_on=[], conclusion=item['rationale'], evidence_refs=item['evidence_refs'],
                gaps=item.get('uncovered', []), hypotheses=[]))
    return dict(round_id=round_id, dirty_seq=check['dirty_seq'],
                asset_graph=dict(nodes=list(assets.values())[:128], edges=links[:192], gaps=gaps[:60]),
                audit_graph=dict(tasks=tasks[:50], status=result['status'], gaps=[]))


def report_lines(check):
    if not check.get('audit_stream'):
        return []
    data = graphs(check)
    audit = data['audit_graph']
    assets = data['asset_graph']
    job = check.get('deep_audit') or {}
    active = job.get('dirty_seq') == check['dirty_seq']
    lines = []
    fallback = check.get('audit_mode_fallback') or {}
    if not active and fallback.get('dirty_seq') == check['dirty_seq']:
        why = '宿主未提供并行子任务能力' if fallback['reason'] == 'HOST_PARALLEL_UNAVAILABLE' else '首包未定位到受支持的资产'
        lines.append(f'本轮使用标准单 Worker 审计，原因为{why}。')
    if active:
        terminal = audit['status'] in {'COMPLETE', 'PARTIAL'}
        label = '本轮计划范围已完成' if audit['status'] == 'COMPLETE' else '部分完成'
        lines.append(f'深度业务审计{label}。')
        if audit.get('reviewed_paths'):
            lines.append('已审文件为' + '、'.join(audit['reviewed_paths']) + '。')
        covered = [t['title'] for t in audit['tasks'] if t.get('planner_decision') == 'ACCEPTED']
        if covered:
            prefix = '历史证据回执的方向为' if job.get('evidence_stale') else '已接受的方向为'
            lines.append(prefix + '、'.join(covered) + '。')
        why = audit.get('stop_reason') or ('达到共享时间预算' if audit['status'] == 'INTERRUPTED'
                                          else '收尾时仍有任务待核验')
        lines.append('停止原因为' + why + '。')
        pending = audit['gaps'] if terminal else [
            t['title'] for t in audit['tasks'] if t.get('planner_decision') != 'ACCEPTED']
        if pending:
            lines.append('未审或待补证范围包括' + '；'.join(pending[:12]) + '。')
    reasons = Counter(g['reason'] for g in assets['gaps'])
    if reasons:
        lines.append('局部资产提取的覆盖限制包括' +
                     '；'.join(GAPS.get(reason, '部分初始证据未取得') for reason in reasons) + '。')
    return lines


def dashboard_view(query):
    from .dashboard_history import HistoryRecords
    from .hook_state import identity, native_io_path, no_links
    from .risk_dashboard import SOURCES, STATE, open_readonly

    folders = {editor: folder for editor, _, folder in SOURCES}
    required = {'editor', 'workspace', 'check', 'seq'}
    if (not required <= query.keys() or query.keys() - required - {'evidence', 'asset'}
            or query['editor'] not in folders or not re.fullmatch('[a-f0-9]{64}', query['workspace'])
            or not re.fullmatch('[A-Za-z0-9_.-]{1,180}', query['check'])
            or not re.fullmatch('[0-9]{1,18}', query['seq'])):
        raise ValueError('AUDIT_GRAPH_QUERY_INVALID')
    wid = query['workspace']
    path = native_io_path(STATE / folders[query['editor']] / wid / 'hooks' / wid / 'development-checks.db')
    no_links(path)
    if not path.is_file():
        raise ValueError('AUDIT_GRAPH_UNAVAILABLE')
    with closing(open_readonly(path)) as db:
        entry = db.execute("SELECT json_extract(data, '$.workspace') FROM records WHERE key=?",
                           (query['check'],)).fetchone()
    if not entry or not isinstance(entry[0], str) or not Path(entry[0]).is_absolute():
        raise ValueError('AUDIT_GRAPH_UNAVAILABLE')
    root = Path(entry[0])
    if identity(os.path.normcase(str(root))) != wid:
        raise ValueError('AUDIT_GRAPH_WORKSPACE_MISMATCH')
    check = HistoryRecords(path, root).read(query['check'])
    if (not check or check['owner']['host'] != query['editor']
            or check['dirty_seq'] != int(query['seq'])):
        raise ValueError('AUDIT_GRAPH_VERSION_CHANGED')
    view = graphs(check)
    ref = query.get('evidence')
    asset = query.get('asset')
    if ref is None and asset is None:
        view['asset_graph'] = dict(view['asset_graph'], gaps=[
            dict(gap, label=GAPS.get(gap['reason'], '部分初始证据未取得'))
            for gap in view['asset_graph']['gaps']])
        return view
    refs = {item['evidence_ref'] for item in [*view['asset_graph']['nodes'], *view['asset_graph']['edges']]}
    refs.update(ref for task in view['audit_graph']['tasks'] for ref in task['evidence_refs'])
    item = (check.get('security_result') or {}).get('evidence', {}).get(ref)
    if ref not in refs or not item:
        raise ValueError('AUDIT_GRAPH_EVIDENCE_UNAVAILABLE')
    if asset is not None:
        node = next((n for n in view['asset_graph']['nodes'] if n['id'] == asset and n['evidence_ref'] == ref), None)
        if not node:
            raise ValueError('AUDIT_GRAPH_EVIDENCE_UNAVAILABLE')
        item = dict(item, line_start=node['line_start'], line_end=node['line_end'])
    return evidence_view(root, item)


def evidence_view(root, item):
    from .dashboard_detail import code_lines
    from .local_evidence import WorkspaceReader, safe_source

    name, first, last = (item[k] for k in ('file_path', 'line_start', 'line_end'))
    output = dict(file_path=name, absolute_path=str(root / name), line_start=first, line_end=last)
    try:
        raw, source = WorkspaceReader(root).read(name)
        if hashlib.sha256(raw).hexdigest() == item['sha256']:
            lines = safe_source(source, source_path=name, redaction_version=2, max_line_chars=None)
            output['current'] = dict(label='当前代码与证据摘要一致', matches_record=True,
                                     lines=code_lines('\n'.join(lines[first - 1:last]), first, first, last))
    except (OSError, ValueError):
        pass
    if 'current' not in output:
        output['unavailable'] = '当前代码无法读取或证据版本已变化，已保留原位置。'
    return output
