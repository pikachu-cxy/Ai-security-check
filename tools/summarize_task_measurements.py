"""Compare source/coverage contracts before reporting timing differences."""
import argparse
import json
from pathlib import Path
import statistics
import math
from collections import Counter

STAGES = ('begin_inventory_hash','hook_static','finish_rescan','finish_idempotent',
          'prepare','context_page','context_repeat_page','host_partial_submission','result_output')
SAMPLES = {'component','full'}


def assess(before, after, snapshots, before_name, after_name):
    """Require successful comparable evidence before assessing local benefit.

    Three task repeats per scale are the minimum. Non-overlapping page ranges
    conservatively reject benefits smaller than the observed timing variation.
    PARTIAL is required: this harness cannot certify host semantic review.
    """
    require(snapshots['status'] == 'PASS', 'Snapshot validation did not pass')
    for key in ('machine','archive_sha256','rules_identity','dependencies','dependency_database','offline'):
        require(before['environment'][key] == after['environment'][key], 'Environment mismatch: '+key)
    require(len(before['rows']) == len(after['rows']), 'Different repetition count')
    counts = []
    for data, name in ((before,before_name),(after,after_name)):
        keys = [(r['project']['sample'],r['iteration']) for r in data['rows']]
        require({s for s,_ in keys} == SAMPLES, 'Required sample scale missing')
        require(len(keys) == len(set(keys)), 'Duplicate task repetitions')
        require(all(type(i) is int and i >= 0 for _,i in keys), 'Invalid iteration')
        count = Counter(s for s,_ in keys)
        counts.append(count)
        require(all(count[s] >= 3 for s in SAMPLES), 'Fewer than three task repetitions')
        side = snapshots['sides'][name]
        require(set(side) == {f'{s}:{i}' for s,i in keys}, 'Snapshot repetition mismatch')
        for row in data['rows']:
            static, result = row['static_record'], row['result']
            hook = row['hook']
            require(hook['status'] == 'BASELINE_ESTABLISHED' and hook['coverage'] in {'FULL','SCOPED'}
                    and hook['execution_state'] == 'EXECUTED', 'Hook execution unsuccessful')
            require(static['status'] in {'SUCCESS','COMPLETED'} and static['coverage'] in {'FULL','SCOPED'}, 'Static execution unsuccessful')
            # Runtime may add an unchanged manifest as dependency context. All
            # requested files must be present; extra context is compared in identity.
            require(static['scope_files'] and set(static['scope_files']) <= set(static['actual_files']), 'Static scope incomplete')
            runs = static['scanner_runs']
            require(any(r['status'] == 'SUCCESS' for r in runs), 'No successful scanner')
            require(all(r['status'] in {'SUCCESS','NOT_APPLICABLE'} and r['coverage_contract'] == 'FULL' for r in runs), 'Provider execution failed or partial')
            require(static['capability_results'] and all(v in {'EXECUTED','NOT_APPLICABLE'} for v in static['capability_results'].values()), 'Capability incomplete')
            require(row['finish']['status'] == 'READY' and row['retry']['status'] == 'READY', 'Task finish unsuccessful')
            require(result['status'] == 'COMPLETE' and result['current_version'] is True and result['unverified_file_count'] == 0, 'Task unsuccessful or stale')
            require(result['host_review']['coverage'] == 'PARTIAL', 'Harness cannot certify semantic review')
            expected = Counter({s:3 if s == 'context_page' else 1 for s in STAGES})
            require(Counter(s['stage'] for s in row['stages']) == expected and len(row['pages']) == 3, 'Missing/duplicate stages or pages')
            require(all(type(s['wall_ms']) in (int,float) and math.isfinite(s['wall_ms']) and s['wall_ms'] > 0 for s in row['stages']), 'Invalid timing')
            snap = side[f"{row['project']['sample']}:{row['iteration']}"]
            require(snap['baseline_complete'] is True and snap['end_complete'] is True and not snap['baseline_limits'] and not snap['end_limits'], 'Task snapshot incomplete')
            require(snap['baseline_files'] == result['baseline_file_count'] and snap['end_files'] > 0, 'Snapshot count mismatch')
    require(counts[0] == counts[1], 'Per-sample repetition count differs')
    require(snapshots['sides'][before_name] == snapshots['sides'][after_name], 'Signed snapshots differ')
    for b,a in zip(before['rows'],after['rows']):
        require((b['project']['sample'],b['iteration']) == (a['project']['sample'],a['iteration']), 'Different sample order')
        require(identity(b) == identity(a), 'Source/scan/coverage mismatch')
        require({k:b['hook'][k] for k in ('status','coverage','execution_state')} ==
                {k:a['hook'][k] for k in ('status','coverage','execution_state')}, 'Hook outcome differs')
    benefits = {}
    for sample in sorted(SAMPLES):
        v = [[s['wall_ms'] for r in data['rows'] if r['project']['sample'] == sample for s in r['stages'] if s['stage'] == 'context_page'] for data in (before,after)]
        percent = (1-statistics.median(v[1])/statistics.median(v[0]))*100
        separated = max(v[1]) < min(v[0])
        benefits[sample] = dict(percent=percent, separated=separated, task_runs=counts[0][sample])
    return dict(passed=all(v['percent'] > 0 and v['separated'] for v in benefits.values()), benefits=benefits)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(row):
    record = row['static_record']
    findings = sorted((f['file_path'], f['line_start'], f['line_end'], f['category'],
        f['severity'], f.get('technical_details', {}).get('rule_id')) for f in record['findings'])
    providers = sorted((s['scanner'],s['version'],s['status'],s['coverage_contract'])
                       for s in record['scanner_runs'])
    return dict(project={k:row['project'][k] for k in ('sample','inventory_files','languages','sample_commit')},
        baseline_files=row['result']['baseline_file_count'],
        unknown_files=row['result']['unverified_file_count'],
        limitations=row['result']['limitations'], findings=findings, providers=providers,
        status=record['status'], coverage=record['coverage'], scope=record['scope_files'],
        actual=record['actual_files'], capability=record['capability_results'],
        final=row['final_file_hashes'], pages=row['pages'],
        host_coverage=row['result']['host_review']['coverage'],
        freshness=row['result']['current_version'])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('before', type=Path); ap.add_argument('after', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--snapshots', type=Path, required=True)
    args = ap.parse_args()
    before, after = [json.loads(p.read_text(encoding='utf-8')) for p in (args.before,args.after)]
    snapshots = json.loads(args.snapshots.read_text(encoding='utf-8'))
    try:
        assessment = assess(before,after,snapshots,args.before.name,args.after.name)
    except (ValueError, KeyError, TypeError) as exc:
        args.output.write_text('验收未通过：输入无效或证据不一致。'+str(exc)+'\n', encoding='utf-8')
        print('Acceptance rejected: '+str(exc))
        return 2
    verdict = '通过有限范围验收' if assessment['passed'] else '未通过有限范围验收'
    summary = '；'.join(f"{sample} 分页中位耗时变化 {value['percent']:+.1f}%（下降为正），范围"
                       + ('不重叠' if value['separated'] else '重叠')
                       for sample,value in assessment['benefits'].items())
    probe_notes = []
    for sample in sorted(SAMPLES):
        b,a = [next(r for r in d['rows'] if r['project']['sample']==sample) for d in (before,after)]
        snap = snapshots['sides'][args.before.name][f"{sample}:{b['iteration']}"]
        probe_notes.append(f"{sample}：{assessment['benefits'][sample]['task_runs']} 次任务重复；实际签名快照 {snap['baseline_files']} 文件/{snap['bytes']} 字节。额外规模探针哈希数前/后 {b['project']['files']}/{a['project']['files']}，探针限制 {b['project']['limitations']}/{a['project']['limitations']}，不参与任务证明。实际任务限制 {snap['limitations']}。")
    lines = ['# 严格顺序对照测量', '',
        f'本地分页处理优化{verdict}：{summary}。其他阶段不作为本地分页提速结论的替代，完整产品/桌面/模型语义与发布验收仍未完成。', '',
        '判定要求：每个规模至少三次不同任务重复、每次三页、执行成功、签名快照与范围一致；两规模分页中位耗时均下降且前后范围不重叠才通过。页读是任务内相关观测，不是独立项目实验。系统文件缓存未清空。', '',
        '前后签名任务 begin/end 完整哈希集合、项目清单、限制、发现集合、provider 版本/状态/覆盖、扫描范围、能力状态及证据页身份全部一致。脚本提交 PARTIAL，明确未调用模型做语义复核。', '',
        '\n\n'.join(probe_notes), '',
        '| 样本/阶段 | 前中位数 ms（范围） | 后中位数 ms（范围） | 中位变化 |',
        '|---|---:|---:|---:|']
    for sample in ('component','full'):
        for stage in ('begin_inventory_hash','hook_static','finish_rescan','finish_idempotent',
                      'prepare','context_page','context_repeat_page','host_partial_submission','result_output'):
            values = [[s['wall_ms'] for r in d['rows'] if r['project']['sample']==sample
                       for s in r['stages'] if s['stage']==stage] for d in (before,after)]
            med = [statistics.median(v) for v in values]
            fmt = [f'{statistics.median(v):.1f} ({min(v):.1f}–{max(v):.1f}; 调用数 {len(v)})' for v in values]
            lines.append(f'| {sample}/{stage} | {fmt[0]} | {fmt[1]} | {(med[1]/med[0]-1)*100:+.1f}% |')
    lines.extend(['', '## 冷暖缓存单列', '',
        '缓存标签是任务的启动状态，不代表该任务每页调用时引擎仍处于冷启动。下表实际列出各状态样本数，不推算稳定冷启动中位数或 P95。实际 provider HIT/MISS 留在原始 scanner_diagnostics；它们是准备信息缓存，不是扫描结果复用。', '',
        '| 样本/阶段/缓存 | 前 ms（中位；范围；n） | 后 ms（中位；范围；n） |', '|---|---:|---:|'])
    for sample in ('component','full'):
        for stage in ('hook_static','finish_rescan','context_page','result_output'):
            for state in ('process_first_os_cache_uncontrolled','process_warm_new_task_state'):
                values = [[s['wall_ms'] for r in d['rows'] if r['project']['sample']==sample and r['cache_state']==state
                           for s in r['stages'] if s['stage']==stage] for d in (before,after)]
                if not all(values): continue
                fmt = [f'{statistics.median(v):.1f}; {min(v):.1f}–{max(v):.1f}; {len(v)}' for v in values]
                lines.append(f'| {sample}/{stage}/{state} | {fmt[0]} | {fmt[1]} |')
    lines.extend(['', '## 实际读取与重复计算', '',
        '| 样本/单页 | 前读取次数/字节/脱敏次数/哈希次数 | 后读取次数/字节/脱敏次数/哈希次数 |', '|---|---:|---:|'])
    for sample in ('component','full'):
        entries = [next(s for r in d['rows'] if r['project']['sample']==sample
                        for s in r['stages'] if s['stage']=='context_page') for d in (before,after)]
        fmt = [f"{s['calls']['read']} / {s['read_bytes']} / {s['calls']['safe_source']} / {s['calls']['hash']}" for s in entries]
        lines.append(f'| {sample} | {fmt[0]} | {fmt[1]} |')
    for label,data in zip(('前','后'),(before,after)):
        observed = Counter(f"{s['scanner']}/{key}/{value}" for row in data['rows'] for s in row['static_record']['scanner_runs'] for key,value in s['scanner_diagnostics'].get('cache',{}).items())
        lines.append(f'{label} provider 准备信息缓存观察：{dict(observed)}。')
    lines.extend(['', '这里的哈希次数也包含 Hook revision 与证据身份元数据摘要。分页每次重读项目仍是剩余成本。总重复读取字节、嵌套函数计时、调用数和实际 provider 缓存观察留在原始 JSON；没有静态字符数冒充真实模型 token，没有估算 P95。', '',
        '早期 Python 单文件阶段的数据与受短暂并发影响的初步 full 观测不用于上述验收。低风险改动确实消除每页一次 raw 哈希，但不能把后续整体阶段变化全部归因于这一微小计算。', '',
        '真实样本只有一个用户自身项目及其组件投影。未覆盖 Java、Go、TypeScript 或超过 1000 支持文件的大项目；.mjs 仅原有 Function/eval 词法 provider，不证明所有 JavaScript 漏洞能力。依赖扫描在此代码范围不适用，未测依赖数据库；OSV 现有版本不符。Agent token、模型推理耗时和桌面端真实 Demo 未测。详见 PERFORMANCE_REVIEW.zh-CN.md。'])
    args.output.write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps(assessment, ensure_ascii=False))
    return 0 if assessment['passed'] else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError) as exc:
        print('Acceptance rejected: '+str(exc))
        raise SystemExit(2)
