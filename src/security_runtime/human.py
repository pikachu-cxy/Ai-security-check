"""Chinese human presentation; machine diagnostics and enums stay stable."""
from .diagnostics import sanitize

CAPABILITY_LABELS = {'CODE_SAST': '代码安全', 'SECRET_SCAN': '敏感信息检测',
                     'DEPENDENCY_VULN': '依赖安全', 'IAC_MISCONFIG': 'IaC 配置安全'}
STATES = {'EXECUTED': '已完成', 'PARTIAL': '部分完成', 'FAILED': '失败', 'UNAVAILABLE': '不可用',
          'NOT_COVERED': '未覆盖',
          'NOT_APPLICABLE': '本次不适用', 'SUCCESS': '完成', 'TIMEOUT': '超时'}
REASONS = {'MAVEN_RATE_LIMITED': '解析项目依赖时 Maven 仓库返回 HTTP 429。',
    'NETWORK_TIMEOUT': '连接或下载超时。', 'CONNECTION_REFUSED': '远端拒绝连接。',
    'DNS_RESOLUTION_FAILED': '远端主机名解析失败。', 'PROXY_CONNECTION_FAILED': '代理连接失败。',
    'TLS_ERROR': 'TLS 连接或证书验证失败。', 'DOWNLOAD_INTERRUPTED': '下载在完成前中断。',
    'OFFLINE_MODE': '离线模式下缺少所需引擎或本地数据。', 'CHECKSUM_MISMATCH': '下载文件校验失败。',
    'UNKNOWN_NETWORK_ERROR': '远端连接或下载失败。', 'PROCESS_TIMEOUT': '扫描器超过执行时限。',
    'OUTPUT_LIMIT_EXCEEDED': '扫描器输出超过大小限制。',
    'VULNERABILITY_DB_UNAVAILABLE': '本地漏洞数据库不可用。',
    'SCANNER_OUTPUT_OR_CONFIG_ERROR': '扫描器输出或本地配置有误。'}


def diagnostic_zh(data, *, retry=''):
    code = data.get('error_code', '')
    reason = REASONS.get(code, f'远端返回 {code.replace("_", " ")}。' if code.startswith('HTTP_') else '检查未能完成。')
    lines = ['原因：' + reason, '错误类别：' + code]
    if data.get('source'):
        lines.append('来源：' + data['source'])
    if data.get('retry_after_seconds') is not None:
        lines.append(f"建议重试：{data['retry_after_seconds']} 秒后")
    for field, label in [('http_proxy', 'HTTP 代理'), ('https_proxy', 'HTTPS 代理')]:
        lines.append(label + '：' + ('已配置' if data.get(field) == 'configured' else '未配置'))
    if code == 'MAVEN_RATE_LIMITED':
        suggestion = '等待限流解除，或准备本地 Maven 缓存 / 配置 Maven 镜像。'
    elif code == 'CHECKSUM_MISMATCH':
        suggestion = '重新下载已固定版本的官方文件，不要跳过校验。'
    elif code == 'OFFLINE_MODE':
        suggestion = '联网准备所需引擎和数据后重试。'
    elif code in {'PROCESS_TIMEOUT', 'OUTPUT_LIMIT_EXCEEDED'}:
        suggestion = '缩小扫描范围，或检查引擎运行环境后重试。'
    elif code.startswith('HTTP_') or code in REASONS:
        suggestion = '检查网络、HTTPS_PROXY、远端服务及本地引擎配置后重试，不要关闭 TLS 验证。'
    else:
        suggestion = '检查本地引擎、规则和配置后重试。'
    lines.append('建议：' + suggestion)
    if retry:
        lines.append('重试：' + retry)
    return sanitize('\n'.join(lines), 2000)


def render_scan(result, *, verbose=False):
    from .target import selection_summary
    selection = selection_summary(result.target_profile)
    exclusions = []
    if selection['excluded_count']:
        exclusions = ['', f"文件范围：{selection['selected_files']} 个目标；排除 {selection['excluded_count']} 个不支持的二进制文档。",
                      '排除的文档内容未检查，不能据此判断其中没有敏感信息。']
        if verbose:
            exclusions += [f"- {row['path']}：{row['reason']}" for row in selection['excluded_files']]
            if selection['exclusions_truncated']:
                exclusions.append('完整排除记录见 CLI JSON 扫描快照。')
    if result.execution_state in {'NO_CHANGES', 'NOT_APPLICABLE'}:
        return f'AI Security Check\n\n{result.summary}\n状态：{result.execution_state}\n耗时：{result.duration_ms} ms' + '\n'.join(exclusions)
    from .triage_models import category, dependency_groups, iac_classification
    raw=[finding.__dict__ for finding in result.findings]
    lines = ['AI Security Check', '', '检查完成。', f'发现 {len(result.findings)} 个候选安全问题。',
        '部分问题需要结合代码和运行环境进一步确认。', '']
    lines += exclusions
    for key,label in [('code','代码安全'),('secret','敏感信息'),('dependency','依赖漏洞'),('iac','配置安全')]:
        count=sum(category(f)==key for f in raw)
        if count or verbose: lines.append(f'{label}：{count}')
    groups=dependency_groups(raw)
    if groups:
        lines += ['', '依赖风险（按包／版本／清单分组；具体 advisory 可在 JSON／Raw Findings 中展开）']
        for group in groups:
            lines.append(f"{group['highest_severity']} · {group['package']} {group['version']} · {len(group['finding_ids'])} 个候选漏洞 · UNTRIAGED · {group['manifest']}")
    for finding in result.findings:
        if finding.category=='dependency' and not verbose:
            continue
        if finding.category=='configuration':
            lines.append('配置分类：'+iac_classification(finding.__dict__))
        lines += [finding.severity, finding.plain_title, f'位置：{finding.file_path}:{finding.line_start}',
                  '为什么危险：' + finding.impact, '建议：' + finding.fix_advice, '']
    summary = result.summary.replace('；Security check completed with limited coverage.', '。部分安全检查未能完成，结果覆盖不完整。')
    lines += ['结果：', summary, f'覆盖范围：{result.coverage}（仅针对计划文件和检查）',
              f'耗时：{result.duration_ms} ms', '', '安全检查']
    for state in ('EXECUTED', 'PARTIAL', 'FAILED', 'UNAVAILABLE', 'NOT_COVERED', 'NOT_APPLICABLE'):
        if state == 'NOT_APPLICABLE' and not verbose:
            continue
        items = [CAPABILITY_LABELS.get(cap, cap) for cap, value in result.capability_results.items() if value == state]
        if items:
            lines += ['', STATES[state], *[label + '：' + STATES[state] for label in items]]
    if result.rule_coverage:
        coverage=result.rule_coverage
        lines += ['', '规则覆盖（仅针对本次 SAST 文件）', f"规则包：{coverage['rule_pack_id']} {coverage['rule_pack_version']}"]
        for language, row in coverage['per_language'].items():
            lines += ['', language + '：' + STATES.get(row['status'],row['status']),
                f"适用规则：{row['selected_rules']}；执行规则：{row['executed_rules']}；计划文件：{row['target_files']}；实际文件：{row['scanned_files']}"]
            if row['status']=='NOT_COVERED':
                lines.append(f"检测到 {language} 源码，但当前规则包没有适用规则，未启动该语言的扫描。")
            elif row['status']=='EXECUTED':
                lines.append(f"已执行 {row['executed_rules']} 条规则；结果仅表示这些规则的匹配情况，不代表项目没有安全漏洞。")
    for cap, detail in result.capability_details.items():
        if detail.get('provider_role') == 'FALLBACK':
            lines += ['', CAPABILITY_LABELS.get(cap,cap)+'：'+STATES.get(detail['status'],detail['status'])
                +f"（{detail['active_provider']} 回退；覆盖 {detail['coverage']}）"]
            if detail['status']=='EXECUTED':
                lines.append('本次计划中的依赖检查已由回退完成。')
            else:
                lines.append('回退已执行，但未证明完整依赖图覆盖；依赖安全仍为部分完成。')
            if verbose:
                lines.extend(detail.get('coverage_notes',[]))
    if result.status == 'PARTIAL':
        lines += ['', '为什么覆盖不完整？', f'已完成检查发现的 {len(result.findings)} 个候选问题仍保留。',
                  '失败或不可用的检查可能导致其他问题未被发现。']
    from dataclasses import asdict
    for run in result.scanner_runs:
        if run.status in {'SUCCESS', 'SKIPPED', 'NOT_APPLICABLE', 'NOT_COVERED'}:
            continue
        resolved_by_fallback = any(result.capability_results.get(cap)=='EXECUTED' and
            result.capability_details.get(cap,{}).get('provider_role')=='FALLBACK' for cap in run.capabilities)
        if resolved_by_fallback and not verbose:
            continue
        lines += ['', f'{run.scanner} {run.version}', '状态：' + STATES.get(run.status, run.status)]
        affected = [CAPABILITY_LABELS.get(cap, cap) + ('仅部分完成' if result.capability_results[cap] == 'PARTIAL' else '未完成')
                    for cap in run.capabilities if result.capability_results.get(cap) in {'PARTIAL', 'FAILED', 'UNAVAILABLE'}]
        if affected:
            lines += [f'{run.scanner} 未完成，因此：', *['- ' + label for label in affected]]
        if run.error_code:
            retry = f'security-check tools install {run.scanner}' if run.status == 'UNAVAILABLE' and run.scanner in {'semgrep', 'gitleaks', 'trivy'} else f'security-check scan --mode {result.mode}'
            lines.append(diagnostic_zh(asdict(run), retry=retry))
    return '\n'.join(lines)


def render_triage(view):
    coverage=view['triage_coverage']
    lines=['AI Risk Validation', '', f"候选问题：{coverage['total_candidates']}",
        f"已完成 AI 审阅：{coverage['triaged']}；尚无有效审阅：{coverage['total_candidates']-coverage['triaged']}",
        'VALID 仅表示记录通过 Runtime 校验，非人工验证、漏洞复现或线上可利用证明。',
        f"优先处理：{coverage['actionable']}",f"需要确认：{coverage['review']}",
        f"低优先级：{coverage['lower_priority']}",f"已降噪：{coverage['suppressed']}（原始 Finding 保留）",
        f"失败：{coverage['failed']}；过期：{coverage['stale']}",f"Scan Coverage：{view['scan_coverage']}"]
    for priority,label in [('ACTIONABLE','优先处理'),('REVIEW','需要确认'),('LOWER_PRIORITY','低优先级'),('SUPPRESSED','已降噪 Findings')]:
        items=[row for row in view['findings'] if row['triage_status']=='VALID' and row['triage']['priority']==priority]
        if not items: continue
        lines += ['',label]
        for row in items:
            triage=row['triage']
            lines += [f"{row['severity']} · {triage['verdict']} · {row['title']}",
                f"位置：{row['file']}:{row['line']}",f"原因：{triage['reason']}",
                f"Exploitability：{triage['exploitability']}"]
            lines += [f"证据：{ref['file']}:{ref['start_line']}-{ref['end_line']}" for ref in triage['evidence_refs']]
    if view['dependency_groups']:
        lines += ['', '依赖风险（Raw advisories 按包分组）']
        rows={row['finding_id']:row for row in view['findings']}
        for group in view['dependency_groups']:
            states={rows[fid]['triage']['verdict'] if rows[fid]['triage_status']=='VALID' else rows[fid]['triage_status'] for fid in group['finding_ids']}
            lines.append(f"{group['package']} {group['version']} · 最高 {group['highest_severity']} · {len(group['finding_ids'])} 个候选漏洞 · {' / '.join(sorted(states))}")
    iac=[row for row in view['findings'] if row['category']=='iac']
    if iac:
        lines += ['', 'IaC 未进行 AI Triage']
        for classification in ('SECURITY_MISCONFIGURATION','HARDENING','BEST_PRACTICE'):
            lines.append(f"{classification}：{sum(row['classification']==classification for row in iac)}")
    lines += ['', 'Raw Findings 仍可通过 get_findings 或 security-check triage --raw 查看。',
        'Agent-native 验证：prepare_triage → 宿主模型分析 → submit_triage。普通 scan 不调用 AI。']
    return '\n'.join(lines)


def render_security_summary(result):
    import shlex
    if result['status']=='NEEDS_SCAN':
        command='security-check '+shlex.join(result['next_step']['cli_args'])
        return '\n'.join(['开发者安全任务',result['message'],f'可选下一步：{command}',
                          '尚未执行扫描；首次扫描可能需要准备引擎和联网解析依赖。'])
    c=result['triage_coverage']
    lines=['开发者安全任务',f"扫描覆盖：{result['scan_coverage']}；原扫描发布状态：{result['release_status']}",
           f"原始候选 {c['total_candidates']}；已完成 AI 审阅 {c['triaged']}/{c['eligible_for_triage']} 个适用候选。",
           f"适用候选未审阅 {c['eligible_untriaged']}；审阅失败 {c['failed']}；过期/无法核对 {c['stale']}；不适用 AI {c['not_eligible']}（含 IaC）。",
           f"优先处理 {c['actionable']}；待复核 {c['review']}；低优先级 {c['lower_priority']}；降噪 {c['suppressed']}。",
           'VALID 是 Runtime 接受的 AI 审阅，非人工验证、复现或线上可利用证明；0 个优先处理项不表示安全。',
           '来源：扫描器候选 + 已接受的 AI 审阅；宿主补充核查未导入。']
    lines.append('检查状态：'+'；'.join(CAPABILITY_LABELS.get(cap,cap)+' '+STATES.get(state,state)
                                      for cap,state in result['capability_results'].items()))
    if result.get('dependency_health'):
        lines.append('依赖检查：'+result['dependency_health']['message'])
    if result.get('rule_coverage'):
        rule=result['rule_coverage']
        lines.append(f"本次 SAST 规则：可用 {rule.get('total_available',0)}，选中 {rule.get('total_selected',0)}，执行 {rule.get('total_executed',0)}；不等于完整 OWASP 覆盖。")
    if result.get('review_progress',{}).get('pending'):
        lines.append('这是候选复核进度，尚未完成深度审计；剩余候选及未覆盖区域须继续检查。')
    tasks=result['tasks'] if result['details'] else result['recommended_tasks']
    lines+=['','完整任务列表' if result['details'] else f"建议先跟进以下 {len(tasks)} 项（共 {result['task_count']} 个任务；未展开项仍保留）"]
    if not tasks: lines.append('当前没有推荐任务；请结合扫描覆盖与完整 Raw 复核，不能据此判定安全。')
    for task in tasks:
        s=task['review_states']
        basis=' '.join(task['basis']) if result['details'] else (
            f"{task['finding_count']} 条扫描候选；AI 审阅 {s['VALID']}、未审阅 {s['UNTRIAGED']}、过期/无法核对 {s['STALE']}、失败 {s['FAILED']}、不适用 {s['NOT_ELIGIBLE']}。")
        lines += [f"{task['task']} · {task['title']}（{task['finding_count']} 条候选）",
                  '可能影响：'+task['possible_impact'],'已有依据：'+basis,
                  '位置：'+'；'.join(task['locations'][:2]),
                  '未知条件：'+' '.join(task['unknown_conditions']), '下一步（建议，未执行）：'+task['next_step']['label']]
        if result['details']:
            lines+=['Runtime priority：'+str(task['priority_counts']),'审阅状态：'+str(task['review_states'])]
            for member in task['members']:
                lines += [f"Finding {member['finding_id']} · {member['file']}:{member['line']} · {member['severity']} · {member['review_status']} · {member['freshness']}",
                          '规则：'+member['rule_id']]
                if member['advisory']:
                    lines.append('Advisory：'+str(member['advisory']))
                if member['classification']:
                    lines.append('配置分类：'+member['classification'])
                if member['ai_review']:
                    r=member['ai_review']
                    lines+=['AI 审阅（非确定性事实）：'+r['reason'],f"Verdict：{r['verdict']}；confidence：{r['confidence']}；exploitability：{r['exploitability']}",
                            'AI 未知前提：'+str(r['preconditions_unknown']),
                            '引用：'+str(r['evidence_refs']), 'Policy notes：'+str(r['policy_notes'])]
        lines.append('')
    if result['details']:
        lines+=['Scan ID：'+result['scan_id'],'Raw：security-check '+shlex.join(result['raw_access']['cli_args']),
                '覆盖契约与 provider：'+str(result['capability_details'])]
    else:
        lines+=['完整任务/逐条候选/Raw 入口：security-check summary --details（同一 workspace）；JSON 加 --json。']
    lines.append('可让宿主 Agent 继续其中一项核查；继续操作须绑定本次结果，结果变化时重新选择。')
    lines.append('本次仅只读核对审阅证据新鲜度；未启动扫描、模型请求、新风险分析、编辑、构建或修复。')
    return '\n'.join(lines)
