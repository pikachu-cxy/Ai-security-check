"""Read-only developer task projection; suggestions never execute actions."""
from __future__ import annotations

from pathlib import Path
import base64
import hashlib
import json

from .storage import ReadOnlySQLiteStore
from .triage import TriageService
from .triage_evidence import EvidenceBuilder, encoded
from .triage_models import category, dependency_groups
from .workspace import WorkspaceResolver
from .risk import NO_FINDINGS_MESSAGE, presentation_status
from .guidance.risk_decision_guidance import handling_counts

TLS_RULES = {'ai-security.java.trust-all-hostname', 'ai-security.java.trust-all-certificates'}
SEVERITIES = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'UNKNOWN': 1}
PRIORITIES = ('ACTIONABLE', 'REVIEW', 'LOWER_PRIORITY', 'SUPPRESSED', 'UNTRIAGED')
REVIEW_STATES = ('VALID', 'FAILED', 'STALE', 'UNTRIAGED', 'NOT_ELIGIBLE')


def task_reference(scan, topic, ids):
    # Content identity, not an authorization credential. No source excerpts or
    # credentials are placed in the reference; packet freshness stays HMAC-bound.
    members = []
    for f in sorted((f for f in scan['findings'] if f['id'] in ids), key=lambda f: f['id']):
        md = f.get('technical_details', {})
        members.append({key: f.get(key) for key in ('id', 'fingerprint', 'category', 'severity',
                        'confidence', 'file_path', 'line_start', 'line_end', 'scanner_sources')})
        members[-1]['identity'] = {key: md.get(key) for key in ('rule_id', 'ecosystem', 'package',
            'package_version', 'manifest', 'canonical_vulnerability_id', 'vulnerability_id', 'aliases')}
    payload = {'workspace': str(Path(scan['target_profile']['path']).resolve()), 'scan': scan['scan_id'],
               'digest': hashlib.sha256(encoded(['task-group-v1', topic, members])).hexdigest()}
    return 'task-v1.' + base64.urlsafe_b64encode(encoded(payload)).decode().rstrip('=')


def decode_task_reference(value):
    try:
        if not isinstance(value, str) or not value.startswith('task-v1.') or len(value) > 8192:
            raise ValueError()
        data = json.loads(base64.b64decode(value[8:] + '=' * (-len(value[8:]) % 4), altchars=b'-_', validate=True))
        if set(data) != {'workspace', 'scan', 'digest'} or any(not isinstance(v, str) for v in data.values()):
            raise ValueError()
        if not data['scan'] or len(data['scan']) > 100 or len(data['digest']) != 64:
            raise ValueError()
        return data
    except (ValueError, TypeError, UnicodeError):
        raise ValueError('Invalid task reference; refresh get_security_summary and use its task_ref, never T01') from None


def _workspace(value):
    if not value or not isinstance(value, (str, Path)) or isinstance(value, str) and not value.strip():
        raise ValueError('请明确 workspace_path 或绑定当前 workspace；汇总不读取全局最近扫描。')
    path = Path(value).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink() or parent.is_junction():
            raise ValueError('Workspace symlinks and junctions are not supported')
    if WorkspaceResolver._unsafe(path):
        raise ValueError('An explicit project workspace is required')
    if not path.exists():
        # Historical results remain inspectable when source is unavailable.
        return path.resolve()
    return WorkspaceResolver().resolve(path, allow_non_git_explicit=True).path


class SecuritySummaryService:
    def __init__(self, store: ReadOnlySQLiteStore | None = None, hooks=None):
        self.store = ReadOnlySQLiteStore(store.path) if store is not None else ReadOnlySQLiteStore()
        self.hooks = hooks

    def get(self, workspace_path=None, scan_id=None, *, details=False, bound_workspace=None):
        if type(details) is not bool:
            raise ValueError('details must be boolean')
        root = _workspace(workspace_path if workspace_path is not None else bound_workspace)
        if bound_workspace is not None and root != _workspace(bound_workspace):
            raise ValueError('Requested workspace is outside this MCP connection')
        scan = self.store.get_scan(scan_id) if scan_id is not None else self.store.latest_scan(root)
        if scan_id is not None and scan is None:
            raise ValueError('Scan does not exist in the selected workspace')
        if scan is not None and Path(scan['target_profile']['path']).resolve() != root:
            raise ValueError('Scan does not belong to the selected workspace')
        if scan is None:
            return {'status': 'NEEDS_SCAN', 'workspace': str(root), 'details': details,
                    'message': '需要首次检查：当前 workspace 没有扫描记录。',
                    'next_step': {'kind': 'SUGGESTION', 'label': '选择是否执行首次项目检查',
                                  'cli_args': ['scan', '--path', str(root), '--mode', 'release'],
                                  'automatic_execution': False}}
        view = TriageService(self.store).view(scan['scan_id'], persist_stale=False)
        rows = {row['finding_id']: row for row in view['findings']}
        try:
            cleaner = EvidenceBuilder(scan)
        except (ValueError, OSError):
            cleaner = None
        def safe(value):
            if isinstance(value, str):
                if cleaner is not None:
                    try:
                        return cleaner.safe_text(value)
                    except (ValueError, OSError):
                        pass
                return '[脱敏依据不可用，内容已省略]'
            if isinstance(value, list):
                return [safe(item) for item in value]
            if isinstance(value, dict):
                return {key: safe(item) for key, item in value.items()}
            return value
        from .finding_feedback import FindingFeedbackService
        feedback = FindingFeedbackService(self.store, root).presentations(scan['scan_id'])
        tasks = self._tasks(scan, rows, safe, feedback)
        from .hook_state import HookStateStore
        from .risk_closure import RiskClosureService
        from .equivalence import equivalence_key
        closure = RiskClosureService(self.hooks or HookStateStore(self.store.path.parent / 'hooks'))
        facts = closure.statuses(root)
        closed = {r['equivalence_key'] for r in facts if r['status'] == 'CONFIRMED_CLOSED'}
        by_id = {f['id']: f for f in scan['findings']}
        for task in tasks:
            if task['topic'] == 'secret':
                states = ['CONFIRMED_CLOSED' if equivalence_key(by_id[m['finding_id']]) in closed
                          else 'UNCONFIRMED' for m in task['members']]
                task['current_closure'] = 'CONFIRMED_CLOSED' if all(s == 'CONFIRMED_CLOSED' for s in states) else 'UNCONFIRMED'
                for member, state in zip(task['members'], states):
                    member['current_closure'] = state
        coverage = dict(view['triage_coverage'])
        coverage['not_eligible'] = sum(category(f) not in {'code', 'secret', 'dependency'} for f in scan['findings'])
        coverage['eligible_untriaged'] = sum(row['triage_status'] == 'UNTRIAGED' and row['category'] in
                                            {'code', 'secret', 'dependency'} for row in rows.values())
        candidates = [task for task in tasks if task['active_finding_count'] and
                      task.get('current_closure') != 'CONFIRMED_CLOSED' and
                      (any(task['priority_counts'][key] for key in ('ACTIONABLE', 'REVIEW', 'UNTRIAGED'))
                      or task['review_states']['NOT_ELIGIBLE'])]
        recommended = [task for task in candidates if task['priority_counts']['ACTIONABLE']][:3]
        topics = {task['topic'] for task in recommended}
        for task in candidates:
            if len(recommended) == 3:
                break
            if task not in recommended and task['topic'] not in topics:
                recommended.append(task)
                topics.add(task['topic'])
        for task in candidates:
            if len(recommended) == 3:
                break
            if task not in recommended:
                recommended.append(task)
        release_status = presentation_status(scan['release_status'], finding_count=len(scan['findings']),
            status=scan['status'], execution_state=scan.get('execution_state'), coverage=scan.get('coverage'))
        result = {'status': 'AVAILABLE', 'workspace': str(root), 'details': details,
                  'scan_coverage': view['scan_coverage'], 'capability_results': view['capability_results'],
                  'release_status': release_status, 'triage_coverage': coverage,
                  'task_count': len(tasks), 'recommended_tasks': recommended,
                  'sources': {'scanner_candidates': 'SCANNER', 'accepted_ai_reviews': 'RUNTIME_ACCEPTED_AI_REVIEW',
                              'host_supplemental': 'NOT_IMPORTED'},
                  'notice': (NO_FINDINGS_MESSAGE if release_status == 'NO_FINDINGS' else
                             'VALID 表示记录通过 Runtime 校验，非人工验证、漏洞复现或线上可利用证明。0 个优先处理项不表示安全。'),
                  'automatic_execution': False}
        from .scan_freshness import summary as scan_context_summary
        result['scan_context'] = scan_context_summary(scan, self.store, root)
        result['current_credential_closure'] = facts
        result['historical_scan_unchanged'] = True
        result['false_positive_feedback'] = {
            'folded_finding_count': sum(item['folded'] for item in feedback.values()),
            'user_marked_unconfirmed_count': sum(item['state'] == 'USER_MARKED_UNCONFIRMED'
                                                  for item in feedback.values()),
            'stale_review_count': sum(item['state'] == 'REVIEW_STALE' for item in feedback.values()),
            'raw_findings_preserved': True, 'repair_authorized': False,
            'assessment_source': 'HOST_CODE_REVIEW_NOT_RUNTIME_PROOF',
            'items': [{key: item.get(key) for key in ('finding_id', 'state', 'folded', 'message',
                       'handling_status', 'handling_label', 'reminder_suppressed')}
                      for item in feedback.values() if item['state'] != 'UNREVIEWED' or item.get('folded')]}
        handling_feedback = {fid:dict(item) for fid,item in feedback.items()}
        for fid, finding in by_id.items():
            if equivalence_key(finding) in closed:
                handling_feedback[fid] = dict(handling_feedback.get(fid, {}),
                    handling_status='RESOLVED', reminder_suppressed=True)
        handling = handling_counts(handling_feedback)
        result['risk_handling'] = dict(handling, raw_finding_count=len(scan['findings']),
            pending_finding_count=handling['pending'],
            excluded_finding_count=handling['excluded_by_user']+handling['excluded_by_agent'],
            deferred_finding_count=handling['deferred'],
            raw_findings_preserved=True, repair_authorized=False)
        result['false_positive_feedback']['technical_false_positive_count'] = sum(
            item.get('technical_false_positive', item.get('state') == 'AGENT_FALSE_POSITIVE')
            for item in feedback.values())
        result['false_positive_feedback']['user_excluded_count'] = handling['excluded_by_user']
        result['false_positive_feedback']['deferred_count'] = handling['deferred']
        from .target import selection_summary
        result['target_selection'] = selection_summary(scan['target_profile'])
        result['rule_coverage'] = {key:value for key,value in scan.get('rule_coverage',{}).items()
                                   if key != 'scope_files'}
        pending = sum(t['review_states'][state] for t in tasks for state in ('UNTRIAGED','FAILED','STALE'))
        result['review_progress'] = {'phase':'CANDIDATE_REVIEW_PENDING' if pending else 'CANDIDATE_REVIEW_COMPLETE',
            'reviewed':coverage['triaged'], 'pending':pending, 'not_eligible':coverage['not_eligible'],
            'deep_audit_completion':'NOT_ATTESTED', 'is_security_clearance':False}
        dependency = scan.get('capability_details',{}).get('DEPENDENCY_VULN',{})
        fallback = dependency.get('provider_role') == 'FALLBACK'
        degraded = fallback and dependency.get('status') in {'EXECUTED','PARTIAL'}
        result['dependency_health'] = {'status':'FALLBACK_SUCCEEDED_WITH_LIMITS' if degraded else dependency.get('status','NOT_EXECUTED'),
            'message':'主依赖引擎受阻，回退引擎已提供结果；依赖图仍可能不完整，并非全部依赖扫描失败。' if degraded else
                      '以原扫描的依赖执行状态和图覆盖为准；扫描器成功不等于调用链已验证。',
            'complete_graph_verified':dependency.get('inventory', {}).get('complete_dependency_graph_attested') is True,
            'automatic_retry':False}
        result['task_selection_protocol'] = {
            'identity': 'task_ref', 'display_numbers': 'RESPONSE_LOCAL_ONLY',
            'instruction': '“继续第一项”对应本次 recommended_tasks 的第一项及其 continuation；不重新查询后按 T01 换对象。缺少原响应或引用失效时刷新并重新选择。',
            'flow': ['prepare_task_triage', 'HOST_ANALYSIS_OF_BOUNDED_PACKETS', 'submit_triage'],
            'runtime_calls_host_model': False}
        if details:
            result.update(scan_id=scan['scan_id'], tasks=tasks,
                          capability_details={cap: {key: safe(value) if key == 'coverage_notes' else value
                                                    for key, value in detail.items()}
                                              for cap, detail in scan.get('capability_details', {}).items()},
                          raw_access={'cli_args': ['triage', '--scan', scan['scan_id'], '--path', str(root), '--raw'],
                                      'mcp_tool': 'get_findings', 'arguments': {'scan_id': scan['scan_id']}})
        else:
            result['recommended_tasks'] = [self._compact(task) for task in recommended]
        from .reply_adapters import summary_facts
        from .reply_plan import plan_reply
        from .reply_render import render_reply
        plan = plan_reply(summary_facts(result))
        result['reply_plan'] = plan.to_dict()
        result['user_feedback'] = {'message': render_reply(plan)}
        # No packets, excerpts, scanner secret evidence or environment. Only
        # dynamic stored text passes through the redactor; generated enums and
        # counts stay readable even when source cannot be safely inspected.
        return result

    @staticmethod
    def _compact(task):
        return {key: value for key, value in task.items() if key not in {'members', 'group_key'}}

    def _tasks(self, scan, rows, safe, feedback=None):
        feedback = feedback or {}
        findings = scan['findings']
        grouped = []
        consumed = set()
        for group in dependency_groups(findings):
            ids = group['finding_ids']
            complete = all(group[key] for key in ('ecosystem', 'package', 'version', 'manifest'))
            for batch in ([ids] if complete else [[fid] for fid in ids]):
                grouped.append(('dependency', batch, group))
                consumed.update(batch)
        tls = [f for f in findings if category(f) == 'code' and
               f.get('technical_details', {}).get('rule_id') in TLS_RULES]
        for finding in sorted(tls, key=lambda f: (f['file_path'], f['line_start'], f['id'])):
            if finding['id'] in consumed:
                continue
            # A narrow, explicit pair in the same local utility region. Other
            # same-file or same-severity findings remain separate tasks.
            pair = next((other for other in tls if other['id'] not in consumed and other['id'] != finding['id']
                         and other['file_path'] == finding['file_path']
                         and other['technical_details']['rule_id'] != finding['technical_details']['rule_id']
                         and abs(other['line_start'] - finding['line_start']) <= 40), None)
            ids = [finding['id']] + ([pair['id']] if pair else [])
            grouped.append(('tls', ids, None))
            consumed.update(ids)
        for finding in findings:
            if finding['id'] not in consumed:
                grouped.append((category(finding), [finding['id']], None))
        by_id = {f['id']: f for f in findings}
        tasks = []
        for topic, ids, group in grouped:
            priorities = dict.fromkeys(PRIORITIES, 0)
            states = dict.fromkeys(REVIEW_STATES, 0)
            members = []
            for fid in ids:
                finding, row = by_id[fid], rows[fid]
                state = row['triage_status'] if row['category'] in {'code', 'secret', 'dependency'} else 'NOT_ELIGIBLE'
                states[state] += 1
                priority = row['triage']['priority'] if state == 'VALID' else 'UNTRIAGED'
                review = feedback.get(fid, {})
                priorities['SUPPRESSED' if review.get('folded') else priority] += 1
                md = finding.get('technical_details', {})
                members.append({'finding_id': fid, 'file': safe(finding['file_path']), 'line': finding['line_start'],
                                'severity': finding['severity'], 'rule_id': safe(md.get('rule_id', '')),
                                'scanner_sources': safe(finding['scanner_sources']), 'review_status': state,
                                'freshness': row['freshness'], 'runtime_priority': priority,
                                'classification': row.get('classification'),
                                'false_positive_review': {key: review.get(key) for key in
                                    ('state', 'folded', 'agent_review_current', 'message',
                                     'handling_status', 'handling_label', 'handling_source',
                                     'reminder_suppressed', 'reassessment_required', 'disposition')},
                                'ai_review': safe(row['triage']),
                                'advisory': safe({key: md.get(key) for key in ('canonical_vulnerability_id', 'vulnerability_id',
                                            'aliases', 'affected_ranges', 'fixed_versions',
                                            'fixed_version_text', 'remediation_evidence')}) if topic == 'dependency' else None})
            title, impact, unknown, next_step = self._guidance(topic, safe(group))
            why = [f'扫描器记录了 {len(ids)} 条关联候选；候选仍需结合实际用途判断。']
            if topic == 'tls' and len(ids) > 1:
                why.append('明确的证书与主机名校验规则位于同一文件相邻区域，按共同 HTTPS 校验目标组织；不证明调用链。')
            if states['VALID']:
                why.append(f"已有 {states['VALID']} 条 Runtime 接受的 AI 审阅；内容属于模型分析，不是确定性事实证明。")
            if states['STALE']:
                why.append(f"{states['STALE']} 条历史审阅已过期或无法核对；不能沿用其优先级。")
            tasks.append({'topic': topic, 'title': title, 'possible_impact': impact, 'basis': why,
                          'task_ref': task_reference(scan, topic, ids),
                          'unknown_conditions': unknown, 'next_step': {'kind': 'SUGGESTION', 'label': next_step,
                                                                      'automatic_execution': False},
                          'finding_count': len(ids), 'locations': sorted(set(f"{m['file']}:{m['line']}" for m in members)),
                          'folded_finding_count': sum(feedback.get(fid, {}).get('folded', False) for fid in ids),
                          'active_finding_count': sum(not feedback.get(fid, {}).get('folded', False) for fid in ids),
                          'handling_counts': handling_counts({fid:feedback.get(fid, {}) for fid in ids}),
                          'priority_counts': priorities, 'review_states': states,
                          'highest_severity': max((m['severity'] for m in members), key=lambda s: SEVERITIES.get(s, 0)),
                          'members': members, 'group_key': (safe({key: group[key] for key in ('ecosystem', 'package', 'version', 'manifest')})
                                                          if group else None)})
        topic_order = {'tls': 0, 'secret': 1, 'dependency': 2, 'code': 3, 'iac': 4, 'unsupported': 5}
        tasks.sort(key=lambda t: (not bool(t['priority_counts']['ACTIONABLE']), topic_order[t['topic']],
                                  -SEVERITIES.get(t['highest_severity'], 0), t['locations']))
        for index, task in enumerate(tasks, 1):
            task['task'] = f'T{index:02d}'
            task['continuation'] = {'mcp_tool': 'prepare_task_triage',
                                    'arguments': {'task_ref': task['task_ref'],
                                                  'workspace_path': str(Path(scan['target_profile']['path']).resolve())}}
            task['fix_handoff'] = {'mcp_tool': 'prepare_task_fix', 'arguments': dict(task['continuation']['arguments'])}
        return tasks

    @staticmethod
    def _guidance(topic, group):
        if topic == 'tls':
            return ('核查 HTTPS 连接的证书与主机名校验',
                    '若对应路径用于真实连接，可能失去服务器身份验证。',
                    ['危险实现是否安装到实际连接、生产渠道是否启用、部署版本及代理/信任配置。'],
                    '先核对本地客户端如何安装校验对象，再确认部署条件；核查与修复尚未执行。')
        if topic == 'secret':
            return ('核对敏感信息的用途与部署覆盖', '可能存在硬编码或不应入库的凭据；真实有效性未知。',
                    ['配置/代码是否实际使用、凭据是否有效、是否已轮换。'],
                    '先核对用途与部署覆盖，只提供是否使用/已轮换等状态，不提供密钥原值。')
        if topic == 'dependency':
            return (f"核查 {group['package'] or '未知包'} {group['version'] or '未知版本'} 的依赖风险",
                    '包版本与 advisory 的匹配是候选信号，不证明受影响 API 可达。',
                    ['受影响范围、修复版本、完整依赖图与实际使用条件；缺失信息保持未知。'],
                    '先补齐 advisory 的受影响范围与修复版本，再核对使用前提，不编造升级版本。')
        if topic == 'iac':
            return ('复核配置规则的适用环境', '本地配置可能有误配置、加固或最佳实践问题。',
                    ['实际部署环境、配置是否生效；本轮 IaC 不属于 AI 审阅范围。'],
                    '按原规则分类复核实际部署配置；尚未执行修改或验证。')
        return ('核查代码候选的实际影响', '扫描器发现潜在不安全行为，实际影响待确认。',
                ['实际用途、调用/运行条件与现有防护。'],
                '先核对候选位置和本地用途，再确认必要的业务事实；尚未执行核查或修复。')
