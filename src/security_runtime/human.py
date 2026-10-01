"""Chinese human presentation; machine diagnostics and enums stay stable."""
from .diagnostics import sanitize

CAPABILITY_LABELS = {'CODE_SAST': '代码安全', 'SECRET_SCAN': '敏感信息检测',
                     'DEPENDENCY_VULN': '依赖安全', 'IAC_MISCONFIG': 'IaC 配置安全'}
STATES = {'EXECUTED': '已完成', 'PARTIAL': '部分完成', 'FAILED': '失败', 'UNAVAILABLE': '不可用',
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
    if result.execution_state in {'NO_CHANGES', 'NOT_APPLICABLE'}:
        return f'AI Security Check\n\n{result.summary}\n状态：{result.execution_state}\n耗时：{result.duration_ms} ms'
    lines = ['AI Security Check', '', '检查完成。', f'发现 {len(result.findings)} 个需要处理的问题。', '']
    for finding in result.findings:
        lines += [finding.severity, finding.plain_title, f'位置：{finding.file_path}:{finding.line_start}',
                  '为什么危险：' + finding.impact, '建议：' + finding.fix_advice, '']
    summary = result.summary.replace('；Security check completed with limited coverage.', '。部分安全检查未能完成，结果覆盖不完整。')
    lines += ['结果：', summary, f'覆盖范围：{result.coverage}（仅针对计划文件和检查）',
              f'耗时：{result.duration_ms} ms', '', '安全检查']
    for state in ('EXECUTED', 'PARTIAL', 'FAILED', 'UNAVAILABLE', 'NOT_APPLICABLE'):
        if state == 'NOT_APPLICABLE' and not verbose:
            continue
        items = [CAPABILITY_LABELS.get(cap, cap) for cap, value in result.capability_results.items() if value == state]
        if items:
            lines += ['', STATES[state], *[label + '：' + STATES[state] for label in items]]
    if result.status == 'PARTIAL':
        lines += ['', '为什么覆盖不完整？', f'已完成检查发现的 {len(result.findings)} 个问题仍然有效。',
                  '失败或不可用的检查可能导致其他问题未被发现。']
    from dataclasses import asdict
    for run in result.scanner_runs:
        if run.status in {'SUCCESS', 'SKIPPED', 'NOT_APPLICABLE'}:
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
