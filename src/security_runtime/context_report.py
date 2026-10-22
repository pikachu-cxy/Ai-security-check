"""Offline, metadata-only consumption reports. No scanner or model execution."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path

from .hook_state import no_links


def phase_for(tool):
    """A tool category, never a claim about scanner internals or model time."""
    if tool.startswith('scan_'):
        return 'scan'
    if tool in {'read_task_review_context', 'get_task_review_plan', 'get_task_review_method',
                'get_runtime_guidance', 'read_repair_impact_context'}:
        return 'evidence'
    if tool.startswith('submit_'):
        return 'submission'
    if tool.startswith(('prepare_', 'begin_', 'finish_')):
        return 'handoff'
    if tool.startswith(('verify', 'run_closeout')):
        return 'verification'
    if tool.startswith('handle_'):
        return 'event'
    return 'query'


def percentile(values, fraction):
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def association_data(events, *, limit=1000, model_requests=(), product_facts=()):
    """Report-local aliases preserve links without exporting private store keys."""
    aliases, rows, producers, counts = {}, [], {}, {}
    linked = limited = legacy = 0

    def alias(kind, value):
        key = (kind, value)
        if key not in aliases:
            counts[kind] = counts.get(kind, 0) + 1
            aliases[key] = kind + '_' + str(counts[kind])
        return aliases[key]

    for event in events:
        evidence = event.get('correlation') or {}
        links = evidence.get('links', [])
        linked += bool(links)
        legacy += not bool(evidence)
        limited += bool(evidence.get('limited') or evidence.get('chat_conflict'))
        if len(rows) < limit:
            row = dict(call_id=event.get('call_id'), tool=event['tool'],
                state='PARTIAL' if evidence.get('limited') or evidence.get('chat_conflict')
                else 'LINKED' if links else 'UNLINKED',
                links=[dict(kind=link['kind'], subject=alias(link['kind'], link['reference_hash']),
                            relation=link['relation'], evidence='SAME_OBSERVED_CALL') for link in links])
            if evidence.get('trigger_invocation_hash'):
                row['host_trigger'] = dict(subject=alias('host_tool', evidence['trigger_invocation_hash']),
                    relation='TRIGGERED_BY_HOST_TOOL', evidence='BINDING_CONSISTENT_NOT_HOST_ATTESTATION')
            if evidence.get('turn_hash'):
                row['host_turn'] = alias('host_turn', evidence['turn_hash'])
            rows.append(row)
        collection = event.get('collection') or {}
        if collection.get('producer_id'):
            previous = producers.setdefault(collection['producer_id'], dict(dropped=0, errors=0))
            previous['dropped'] = max(previous['dropped'], collection.get('dropped_before', 0))
            previous['errors'] = max(previous['errors'], collection.get('write_errors_before', 0))
    request_links = []
    for event in model_requests[:limit]:
        evidence = event.get('correlation') or {}
        request_links.append(dict(attempt_id=event['model_request']['attempt_id'],
            links=[dict(kind=link['kind'], subject=alias(link['kind'], link['reference_hash']),
                relation=link['relation'], evidence='SAME_OBSERVED_REQUEST') for link in evidence.get('links', [])]))
    outcomes = []
    for event in product_facts[:limit]:
        fact = event['product_fact']
        outcomes.append(dict(kind=fact['kind'], source=fact['source'], parent_call_id=event.get('call_id'),
            subject=alias('outcome_scope', fact['reference']),
            links=[dict(kind=link['kind'], subject=alias(link['kind'], link['reference_hash']),
                relation=link['relation']) for link in event.get('correlation', {}).get('links', [])]))
    return dict(observed_calls=len(events), linked_calls=linked, unlinked_calls=len(events)-linked,
        limited_calls=limited, legacy_calls=legacy, calls=rows,
        details_omitted=max(0, len(events)-len(rows)),
        producer_drops_reported=sum(item['dropped'] for item in producers.values()),
        producer_write_errors_reported=sum(item['errors'] for item in producers.values()),
        loss_counter_scope='PRODUCER_LIFETIME_WATERMARKS; NOT_SELECTED_RUN_TOTALS',
        coverage='INSTRUMENTED_MCP_WORKSPACE_HOOK_CALLS; UNFLUSHED_TAIL_UNKNOWN',
        identity_scope='REPORT_LOCAL_ALIASES; NOT_AUTHORITY_OR_CROSS_REPORT_IDENTITIES',
        request_links=request_links,
        product_outcomes=outcomes, product_outcomes_omitted=max(0,len(product_facts)-len(outcomes)),
        model_usage_link='EXPLICIT_BYOK_EXCHANGES' if model_requests else 'UNAVAILABLE')


def timing(events):
    intervals = sorted((item['started_at'] * 1000, item['finished_at'] * 1000)
                       for item in events if item.get('started_at') is not None
                       and item.get('finished_at') is not None)
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return dict(timed_calls=len(intervals), untimed_calls=len(events) - len(intervals),
                observed_window_ms=round(max(end for _, end in intervals) - intervals[0][0], 3) if intervals else None,
                tool_active_wall_ms=round(sum(end - start for start, end in merged), 3) if intervals else None,
                task_wall_ms=None, model_time_ms=None, queue_wait_ms=None,
                timing_scope='OBSERVED_TOOL_INTERVALS_NOT_END_TO_END_TASK',
                clock_basis='WALL_CLOCK_INTERVALS; ELAPSED_USES_MONOTONIC')


def report_data(store, run=None, *, limit=2000):
    if type(limit) is not int or not 1 <= limit <= 10_000:
        raise ValueError('CONTEXT_REPORT_LIMIT_INVALID')
    snapshot = store.snapshot(run)
    if snapshot['status'] != 'AVAILABLE':
        return dict(status='UNAVAILABLE', monitoring=store.monitoring())
    events = snapshot['events']
    summary = store._summary(events, snapshot['reports'], snapshot['label'], snapshot['invalid'])
    groups = {}
    for event in events:
        group = groups.setdefault(event['tool'], dict(tool=event['tool'], phase=phase_for(event['tool']),
                                                     calls=0, failed_calls=0, wire_bytes=0, elapsed_ms=0, samples=[]))
        group['calls'] += 1
        group['failed_calls'] += not event['succeeded']
        group['wire_bytes'] += event['wire_bytes']
        group['elapsed_ms'] += event['elapsed_ms']
        group['samples'].append(event['elapsed_ms'])
    for group in groups.values():
        values = group.pop('samples')
        group.update(p50_ms=percentile(values, .5), p95_ms=percentile(values, .95), max_ms=max(values))
    # Only this allowlist is exported; no source, raw refs or keyed identities.
    fields = ('tool', 'elapsed_ms', 'wire_bytes', 'text_bytes', 'structured_bytes', 'succeeded',
              'started_at', 'finished_at', 'call_id', 'run_label', 'mode', 'observation_prewrite_ms',
              'duplicate_receipts', 'source_lines_delivered', 'measurement_limited')
    rows = [dict({name: event.get(name) for name in fields}, phase=phase_for(event['tool']))
            for event in events[:limit]]
    for row in rows:
        if row['measurement_limited']:
            row.update(wire_bytes=None, text_bytes=None, structured_bytes=None)
    from .model_report import request_data, latest_attempts
    from .collector_health import health_data
    from .product_metrics import report as product_report
    models = latest_attempts(snapshot.get('model_requests', []))
    associations = association_data(events, limit=limit, model_requests=models, product_facts=snapshot.get('product_facts', []))
    return dict(status=summary['status'], schema_version=1, monitoring=store.monitoring(), summary=summary,
                timing=timing(events), tools=sorted(groups.values(), key=lambda x: x['elapsed_ms'], reverse=True),
                events=rows, associations=associations,
                model_requests=request_data(models, links=associations['request_links'], limit=limit),
                product_metrics=product_report(snapshot.get('product_facts', [])),
                collector_health=health_data(snapshot.get('collector_checkpoints', [])),
                exported_events=len(rows), omitted_events=max(0, len(events) - len(rows)),
                token_scope='WHOLE_SELECTED_RUN; NOT_ATTRIBUTABLE_TO_TOOLS_OR_PHASES',
                phase_scope='TOOL_CATEGORY; NOT_INTERNAL_PHASE_TIMING',
                observation_scope='INSTRUMENTED_PRODUCT_CALLS_AND_BYOK_REQUESTS; NATIVE_MODEL_INPUT_UNKNOWN',
                retention_scope='RETAINED_VALID_RECORDS_ONLY; PRUNED_HISTORY_UNAVAILABLE',
                export_scope='LOCAL_METADATA_SNAPSHOT; NO_LIVE_CONTROL',
                overhead_scope='PREWRITE_ONLY; EXCLUDES_COMMIT_AND_CONFIGURATION_READS')


def write_report(path, data):
    """Create a private new file, never follow links or overwrite an existing file."""
    path = Path(path).absolute()
    no_links(path)
    if path.suffix.lower() not in {'.html', '.json'}:
        raise ValueError('CONTEXT_REPORT_REQUIRES_HTML_OR_JSON')
    if data.get('status') not in {'AVAILABLE', 'PARTIAL'}:
        raise ValueError('CONTEXT_REPORT_DATA_UNAVAILABLE')
    if path.suffix.lower() == '.json':
        content = json.dumps(data, ensure_ascii=False, indent=2)
    else:
        payload = json.dumps(data, ensure_ascii=False, allow_nan=False).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
        content = HTML.replace('__REPORT_DATA__', payload)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        stream.write(content)


HTML = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>Runtime 消耗观察</title><style>
:root{color-scheme:dark;font:15px system-ui,sans-serif;background:#0c1422;color:#e6edf7}*{box-sizing:border-box}
body{max-width:1380px;margin:auto;padding:34px}h1{font-size:32px;margin:8px 0}h2{font-size:20px;margin:28px 0 12px}
p{line-height:1.65;color:#adbbd0}.eyebrow{color:#69dbca;letter-spacing:2px}small{color:#9eafc7}
.panel,.card{background:#142137;border:1px solid #293b55;border-radius:14px;padding:18px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}
.value{font-size:29px;display:block;margin:8px 0}.controls{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
select,input,button{background:#1b2b44;color:#edf4ff;border:1px solid #405874;border-radius:7px;padding:9px;font:inherit}
button{cursor:pointer}button:hover{border-color:#69dbca}code{color:#85e0d4}.warn{color:#ffce83}.scroll{overflow:auto;max-height:430px}
table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:left;padding:11px;border-bottom:1px solid #2a3b53;font-variant-numeric:tabular-nums}
th{color:#a5bbd8;position:sticky;top:0;background:#142137}.bar{height:8px;border-radius:4px;background:#69dbca;min-width:2px;margin-top:6px}
.lane{display:grid;grid-template-columns:280px 1fr;gap:12px;padding:8px 0;border-bottom:1px solid #23344b}.track{position:relative;background:#1c2c42;min-height:22px;border-radius:4px}
.span{position:absolute;background:#70a5fa;height:22px;border-radius:4px;min-width:2px}.muted{color:#a2b1c7}a{color:#69dbca}
@media(max-width:800px){body{padding:18px}.cards{grid-template-columns:repeat(2,1fr)}.lane{grid-template-columns:170px 1fr}.value{font-size:24px}}
</style></head><body>
<div class="eyebrow">AI SECURITY RUNTIME · LOCAL OBSERVABILITY</div><h1>消耗观察</h1>
<p>从真实保留记录查看调用、响应量和时间。此页面为离线快照；token 只采用宿主实际报告，未知不按零计算。</p>
<section class="panel"><div class="controls"><strong id="mode"></strong><button id="download">导出当前快照 JSON</button></div>
<p>采集开关可在终端随时切换，同一统计库的后续调用生效，无需重启。环境变量覆盖时以环境为准；此离线页面不能直接修改运行中的采集开关。</p>
<div class="controls"><label>采集模式 <select id="switch"><option value="debug">详细调试</option><option value="basic">基础统计</option><option value="off">关闭采集</option></select></label><code id="command"></code><button id="copy">复制切换命令</button></div>
<p id="scope"></p></section>
<div class="cards"><div class="card">真实 token · 所选运行整体<span class="value" id="tokens"></span><small id="tokenDetail"></small></div>
<div class="card">工具返回量<span class="value" id="bytes"></span><small>字节不是模型 token</small></div>
<div class="card">工具累计耗时<span class="value" id="duration"></span><small>并发调用可能重叠</small></div>
<div class="card">调用次数<span class="value" id="calls"></span><small id="failures"></small></div></div>
<section class="panel"><strong>时间覆盖与数据质量</strong><p id="quality"></p><p class="warn">端到端任务用时、模型处理及锁/队列等待：未知。阶段按工具类别归组，不代表内部阶段计时。监控预写入耗时不包括配置读取、提交和完整监控开销。</p><p id="builds"></p></section>
<h2>调用明细与流程筛选</h2><div class="controls"><label>工具 <select id="tool"><option value="">全部</option></select></label><label>阶段 <select id="phase"><option value="">全部</option></select></label><label>状态 <select id="state"><option value="">全部</option><option value="ok">成功返回</option><option value="error">错误/中断</option></select></label><input id="search" placeholder="筛选工具名" aria-label="筛选工具名"></div>
<p id="filterNote"></p><h2>主要消耗 · 完整保留样本</h2><label>排序 <select id="sort"><option value="elapsed_ms">累计耗时</option><option value="wire_bytes">返回量</option><option value="calls">调用次数</option></select></label>
<div class="scroll panel"><table><thead><tr><th>工具 / 类别</th><th>调用 / 错误</th><th>返回量</th><th>累计耗时</th><th>P50 / P95 / 最大</th></tr></thead><tbody id="ranking"></tbody></table></div>
<h2>调用时间线 · 仅详细调试记录</h2><p>每行是一项调用，横向位置表示调用起止；并行调用保留重叠。基础记录没有时间线，调用之间的空隙不能推断为模型或锁等待。</p><div id="timeline" class="panel scroll"></div>
<h2>各次调用 · 最近记录</h2><div class="scroll panel"><table><thead><tr><th>开始时间</th><th>工具 / 类别</th><th>运行标签</th><th>状态</th><th>响应耗时</th><th>返回量</th><th>预写入监控耗时</th></tr></thead><tbody id="events"></tbody></table></div>
<script id="data" type="application/json">__REPORT_DATA__</script><script>
'use strict';const data=JSON.parse(document.getElementById('data').textContent),s=data.summary,$=id=>document.getElementById(id);
const phases={scan:'检查',evidence:'证据读取',submission:'提交',handoff:'准备与交接',verification:'复查',event:'事件',query:'查询'};
const fmt=n=>n==null?'未知':Number(n).toLocaleString('zh-CN'),ms=n=>n==null?'未知':(n/1000).toFixed(3)+' 秒';
const bytes=n=>n>=1048576?(n/1048576).toFixed(2)+' MiB':n>=1024?(n/1024).toFixed(1)+' KiB':fmt(n)+' B';
const text=(tag,value)=>{const e=document.createElement(tag);e.textContent=value;return e};
$('mode').textContent='快照采集模式：'+data.monitoring.mode+' · '+data.monitoring.source;
$('switch').value=data.monitoring.mode;$('switch').onchange=()=>{$('command').textContent='security-check context-usage monitor --mode '+$('switch').value};$('switch').onchange();
$('copy').onclick=async()=>{try{await navigator.clipboard.writeText($('command').textContent);$('copy').textContent='已复制'}catch{window.getSelection().selectAllChildren($('command'));$('copy').textContent='请复制已选命令'}};
$('scope').textContent='运行范围：'+(s.run_label??'全部保留运行')+'；保留 '+s.retention_days+' 天 / 最多 '+fmt(s.event_limit)+' 条。关闭后保留历史。重新生成报告才能刷新。';
const u=s.actual_model_tokens;$('tokens').textContent=u?fmt(u.total_tokens):'未知';
$('tokenDetail').textContent=u?'输入 '+fmt(u.input_tokens)+'（缓存 '+fmt(u.cached_input_tokens)+'）/ 输出 '+fmt(u.output_tokens)+'（推理 '+fmt(u.reasoning_output_tokens)+'） · '+s.actual_model_tokens_status:'尚未显式导入宿主 usage；不推算费用';
$('bytes').textContent=bytes(s.wire_bytes);$('duration').textContent=ms(s.elapsed_ms);$('calls').textContent=fmt(s.calls);$('failures').textContent='错误/中断 '+fmt(s.failed_calls)+' · 按实际保留记录';
$('quality').textContent='有时间线 '+fmt(data.timing.timed_calls)+' / 无时间线 '+fmt(data.timing.untimed_calls)+'；观测窗口 '+ms(data.timing.observed_window_ms)+'；工具区间并集 '+ms(data.timing.tool_active_wall_ms)+'。无效记录 '+fmt(s.invalid_records)+'，测量受限 '+fmt(s.limited_measurements)+'，明细省略 '+fmt(data.omitted_events)+'。历史可能已按保留期/数量上限清理；未观测调用不可恢复。';
$('builds').textContent='构建：'+s.builds.map(b=>b.version+' / '+(b.build_id??b.build_status)).join('；')+'。覆盖已接入的 MCP、直接调用与 Hook；BYOK 请求另列。宿主原生工具与完整模型过程仍不在此范围。';
for(const v of [...new Set(data.events.map(e=>e.tool))].sort())$('tool').appendChild(new Option(v,v));for(const p of Object.keys(phases))$('phase').appendChild(new Option(phases[p],p));
function matches(e){return (!$('tool').value||e.tool===$('tool').value)&&(!$('phase').value||e.phase===$('phase').value)&&e.tool.includes($('search').value)&&(!$('state').value||e.succeeded===($('state').value==='ok'))}
function render(){const rows=data.events.filter(matches);$('events').replaceChildren();for(const e of rows){const tr=document.createElement('tr');for(const v of [e.started_at==null?'未知':new Date(e.started_at*1000).toLocaleString(),e.tool+' / '+phases[e.phase],e.run_label??'旧版未记录',e.succeeded?'成功返回':'错误/中断',ms(e.elapsed_ms),bytes(e.wire_bytes),e.observation_prewrite_ms==null?'未知':e.observation_prewrite_ms+' ms'])tr.appendChild(text('td',v));$('events').appendChild(tr)}
$('filterNote').textContent='明细匹配 '+fmt(rows.length)+' / 已导出 '+fmt(data.events.length)+' 条。筛选仅影响明细与时间线；顶部总览及排名始终为所选运行完整保留样本，宿主累计 token 不按调用分摊；BYOK 明确请求的用量单独展示。';
const key=$('sort').value,groups=[...data.tools].sort((a,b)=>b[key]-a[key]);$('ranking').replaceChildren();for(const g of groups){const tr=document.createElement('tr'),name=text('td',g.tool+' / '+phases[g.phase]),bar=text('div','');bar.className='bar';bar.style.width=(100*g[key]/Math.max(1,...groups.map(x=>x[key])))+'%';name.appendChild(bar);tr.appendChild(name);for(const v of [fmt(g.calls)+' / '+fmt(g.failed_calls),bytes(g.wire_bytes),ms(g.elapsed_ms),ms(g.p50_ms)+' / '+ms(g.p95_ms)+' / '+ms(g.max_ms)])tr.appendChild(text('td',v));$('ranking').appendChild(tr)}
const timed=rows.filter(e=>e.started_at!=null&&e.finished_at!=null).sort((a,b)=>a.started_at-b.started_at);$('timeline').replaceChildren();if(!timed.length)$('timeline').appendChild(text('p','暂无详细时间线。开启详细调试后，新的调用会记录起止时间。'));
const first=Math.min(...timed.map(e=>e.started_at)),last=Math.max(...timed.map(e=>e.finished_at)),range=Math.max(.001,last-first);for(const e of timed){const lane=text('div','');lane.className='lane';lane.appendChild(text('small',e.tool+' · '+ms(e.elapsed_ms)));const track=text('div','');track.className='track';const span=text('div','');span.className='span';span.style.left=(100*(e.started_at-first)/range)+'%';span.style.width=(100*(e.finished_at-e.started_at)/range)+'%';span.title=e.tool+' · '+ms(e.elapsed_ms);track.appendChild(span);lane.appendChild(track);$('timeline').appendChild(lane)}}
for(const id of ['tool','phase','state','search','sort'])$(id).addEventListener('input',render);render();
$('download').onclick=()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download='runtime-consumption.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)};
</script></body></html>'''

from .model_panel import SCRIPT as _MODEL_SCRIPT
HTML = HTML.replace('</script></body>', _MODEL_SCRIPT + '\nrenderModelEvidence(data, document.body);\n</script></body>')
