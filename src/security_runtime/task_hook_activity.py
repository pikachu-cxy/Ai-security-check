"""Shared bounded task activity ledger and deferred feedback for host connectors."""
import json

MAX_TASK_HOOK_CHECKS = 256


def _bounded_task_paths(paths, *, count=1000, bytes_limit=128_000):
    from .hook_runtime import safe_path
    ordered = sorted({safe_path(name) for name in paths})
    selected, size = [], 0
    for name in ordered:
        cost = len(name.encode('utf-8'))
        if len(selected) >= count or size + cost > bytes_limit:
            break
        selected.append(name)
        size += cost
    return selected, len(ordered)-len(selected)


def _record_task_hook(hooks, root, result, decision, *, expected_task_ref=None, max_checks=None):
    """Link edit checks to the signed task, without source or repair tokens.

    Scanner records remain in their existing store. This bounded ledger makes
    deferred/failed checks visible at task closeout and is diagnostic only;
    it never turns a historical finding into a current risk or grants repair.
    """
    from .task_security_state import TaskSecurityStore
    import sqlite3
    store = TaskSecurityStore(hooks, root)
    try:
        task = (store.get(expected_task_ref) if expected_task_ref is not None else
                store.for_hook(result.get('host'),result.get('session_id')))
    except (ValueError, OSError, sqlite3.DatabaseError):
        return None, 'UNAVAILABLE'
    if not task:
        return None, 'NOT_APPLICABLE'
    from .task_ownership import ACTIVE
    if task['phase'] not in ACTIVE:
        return None, 'TASK_CLOSED'
    from .task_ownership import record_owner
    owner=record_owner(task)
    if owner is not None and owner!={'host':result.get('host'),'session':result.get('session_id')}:
        return None, 'TASK_OWNER_MISMATCH'
    if expected_task_ref is not None and task['task_ref'] != expected_task_ref:
        return None, 'TASK_CHANGED'
    if result.get('tool_classification') == 'READ_ONLY' or result.get('workspace_mutation_observed') is False:
        return task, 'NO_MUTATION'
    row = {key: result[key] for key in ('status', 'last_check_status', 'coverage', 'scan_id',
        'change_digest', 'workspace_mutation_observed', 'changed_file_count', 'capabilities',
        'deferred_code_providers', 'dependency_check_reason') if key in result}
    row.update(scanner_run=result['execution']['scanner_run'],
        delta={key: result['delta'].get(key, 0) for key in (
            'new', 'persisting', 'resolved', 'additional_occurrences', 'removed_occurrences')})
    scope = result.get('hook_scope_files', [])
    row['scope_files'], row['scope_files_omitted'] = _bounded_task_paths(scope, count=20, bytes_limit=2048)
    row['scope_file_count'] = len(scope)
    if decision:
        row['remediation'] = {key: decision[key] for key in (
            'action', 'reason_code', 'episode_id', 'episode_number') if key in decision}
    for attempt in range(2):
        try:
            complete = (result['status'] == 'SCANNED' and result.get('last_check_status') == 'SCANNED'
                and result.get('coverage') in {'FULL', 'SCOPED'} and bool(result.get('capabilities'))
                and all(isinstance(state, str) and state in {'EXECUTED', 'NOT_APPLICABLE'}
                        for state in result['capabilities'].values())
                and not result.get('deferred_code_providers') and not result.get('dependency_check_reason')
                and result['execution']['scanner_run'])
            retained = set(task.get('hook_recheck_files', ()))
            pending = set(task.get('hook_pending_scope_files', ()))
            if complete:
                retained.difference_update(scope)
                pending.difference_update(scope)
            else:
                pending.update(scope)
            retained.update(result.get('hook_recheck_files', ()))
            task['hook_recheck_files'], omitted = _bounded_task_paths(retained)
            task['hook_recheck_paths_omitted'] = task.get('hook_recheck_paths_omitted', 0) + omitted
            task['hook_pending_scope_files'], omitted = _bounded_task_paths(pending)
            task['hook_pending_paths_omitted'] = task.get('hook_pending_paths_omitted', 0) + omitted
            rows = [*task.get('hook_checks', []), row]
            limit = MAX_TASK_HOOK_CHECKS if max_checks is None else max_checks
            task.update(hook_checks=rows[-limit:],
                hook_checks_omitted=task.get('hook_checks_omitted', 0) + max(0, len(rows)-limit))
            return store.save(task), 'RECORDED'
        except (ValueError, OSError, sqlite3.DatabaseError):
            if attempt == 0:
                try:
                    refreshed = store.get(task['task_ref'])
                    if refreshed and refreshed['phase'] not in ACTIVE:
                        return None, 'TASK_CLOSED'
                    if refreshed and refreshed['task_ref'] == task['task_ref']:
                        task = refreshed
                        continue
                except (ValueError, OSError, sqlite3.DatabaseError):
                    pass
            try:
                store.record_hook_failure(task['task_ref'], task_created_at=task['created_at'],
                    scope_files=set(scope) | set(result.get('hook_recheck_files', ())) |
                        set(task.get('hook_recheck_files', ())) | set(task.get('hook_pending_scope_files', ())),
                    scan_id=result.get('scan_id'))
                return task, 'FAILURE_MARKER_RECORDED'
            except (ValueError, OSError, sqlite3.DatabaseError):
                return task, 'UNAVAILABLE'


def _deferred_task_context(summary):
    """No per-edit user prompt or pending repair instruction in Host text."""
    from .hook_reply_context import CONTROL_DELIMITER
    control = {key: summary[key] for key in ('security_task_ref', 'status', 'last_check_status',
        'coverage', 'scan_id', 'scanner_run', 'new_families', 'persisting_families', 'resolved_families',
        'additional_occurrences', 'removed_occurrences', 'capabilities', 'deferred_code_providers',
        'dependency_check_reason', 'hook_check_recording', 'unpersisted_hook_scope_files',
        'unpersisted_hook_scope_files_omitted') if key in summary}
    control.update(feedback_delivery='TASK_FINAL_SUMMARY', user_feedback_suppressed=True,
                   repair_authorized=False)
    failure = ('本次文件修改检查的任务记录保存失败；已保留独立失败记录，任务结束必须复查其中的范围并披露历史记录缺口。'
               if summary.get('hook_check_recording') == 'FAILURE_MARKER_RECORDED' else
               '本次文件修改检查的任务记录与独立失败记录均未能保存；最终总结必须明确记录保存失败及可能遗漏的检查范围，'
               '不得声称这些结果已持久保留，也不得将未复查范围认定为安全。'
               if summary.get('hook_check_recording') == 'UNAVAILABLE' else '')
    return ('任务内检查记录（仅供工具使用，不展示给用户）\n'
        '当前是已登记的开发任务。继续用户已授权的开发工作；本次逐次静态检查与风险记录以实际工具记录为准，'
        '不要立即呈现钩子反馈、暂停开发或要求用户作出安全处理选择。'
        '任务结束时完成整次任务安全核查，把当前风险、检查范围和未完成项一次合并进开发总结；'
        '仍存在的问题由用户选择处理，已经验证消除的历史问题不能作为当前待处理风险。'
        '检查失败、缺失组件或延期检查不代表安全。'
        '本次检查没有授予修复权限，未经明确批准不得修复安全风险。'
        + failure
        + CONTROL_DELIMITER + json.dumps(control, ensure_ascii=False, separators=(',', ':')))
