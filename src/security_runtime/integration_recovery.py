"""Explain configuration conflicts without granting migration authorization.

Personal installation is user-wide. Workspace state stays isolated, but no new
project installation is required. Old project overrides are a migration case.
"""
from __future__ import annotations

import os
import shlex
from pathlib import Path

from .codex_integration import SERVER, fingerprint
from .integration_lifecycle import IntegrationDiagnostic
from .upgrade import InstallationUpgrade

CONFIGURATION_REASONS = {
    'GLOBAL_CONFIGURATION_NOT_READY', 'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR',
    'MCP_CONFIGURATION_CONFLICT', 'OWNERSHIP_INVALID', 'CONFIG_INVALID',
    'POTENTIAL_DUPLICATE_MCP', 'POTENTIAL_DUPLICATE_HOOK', 'INSTALLED_RUNTIME_REQUIRED',
    'UPGRADE_PLAN_BLOCKED', 'USER_MANAGED_APPROVAL_REQUIRED',
}

EXPLANATIONS = {
    'MCP_CONFIGURATION_CONFLICT': '此位置有同名安全连接，会与全局安装冲突；只有明确确认后才会备份并移除该接入项。',
    'OWNERSHIP_INVALID': '已有接入归属凭据无法验证，不能安全接管；请核对原安装与备份，不要删除或重建密钥。',
    'POTENTIAL_DUPLICATE_HOOK': '发现无法确认归属的相关 Hook，为避免误删或重复触发，已保留并停止自动迁移。',
    'POTENTIAL_DUPLICATE_MCP': '发现另一个相关连接名称，可能重复启动；需先核对该连接，不会自动删除。',
    'CONFIG_INVALID': '配置无法完整解析或结构无效；已保留原文件，需要核对配置格式。',
    'RUNTIME_STALE': '已托管连接与当前产品构建不一致，可备份后统一修复全局接入。',
    'INSTALLED_RUNTIME_REQUIRED': '当前是开发环境入口，请使用已安装的产品启动器；无需在每个项目重新安装。',
    'GLOBAL_NOT_CONFIGURED': '尚未登记全局安全接入，只需安装或修复一次用户级接入。',
    'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR': '此项目仍有已托管的旧安全接入，可备份迁移到全局安装，不必维护两套连接。',
    'HOOK_MISSING': '安全 Hook 配置不完整，可备份后修复全局接入；宿主信任仍需用户审核。',
    'UPGRADE_RECOVERY_REQUIRED': '上次迁移中断，需要先按已签名备份恢复，再重新诊断。',
    'UPGRADE_JOURNAL_INVALID': '本机迁移备份记录无法验证，已停止写入；需要核对原备份，不能重建凭据绕过。',
}


def _explain(code):
    return EXPLANATIONS.get(code, EXPLANATIONS['HOOK_MISSING'] if 'HOOK' in code and 'MISSING' in code
                            else '该配置检查未通过，已保留原内容；请根据诊断核对接入，不要删除其他设置。')


def display_command(argv):
    """Human guidance uses PowerShell on Windows; argv remains authoritative."""
    if os.name == 'nt':
        return '& ' + ' '.join("'" + value.replace("'", "''") + "'" for value in argv)
    return shlex.join(argv)


def _product_prefix(integration):
    """Use only a signed installed entry or the known current product launcher.

    A project command is never executed, copied into guidance, or adopted. This
    also guides an old DEV process to the signed global installation instead of
    instructing it to enroll itself globally again.
    """
    try:
        manifest = integration._manifest(integration.home)
        configs = integration._config(integration.home, manifest)
        entry = configs[0][2].get('mcp_servers', {}).get(SERVER)
        if (manifest and entry and fingerprint(entry) in {r['server'] for r in manifest['records']}
                and isinstance(entry.get('command'), str) and Path(entry['command']).is_file()
                and isinstance(entry.get('args'), list) and entry['args'][-1:] == ['mcp']
                and all(isinstance(a, str) for a in entry['args'])):
            return [entry['command'], *entry['args'][:-1]]
    except (ValueError, OSError, TypeError, RecursionError):
        pass
    try:
        runtime = integration.discover()
        return [runtime['command'], *runtime['prefix']]
    except (ValueError, OSError, TypeError, RecursionError):
        return []


def configuration_recovery(integration, workspace=None, *, reason=None):
    """Bounded read-only guidance; never scan, probe or write Host config."""
    manager = InstallationUpgrade(integration, manage_skill=False)
    layers = manager.layers(workspace)
    issues = []
    for row in layers:
        if not row['diagnostics'] and row['action'] in {'REPAIR', 'PRESERVE'}:
            continue
        diagnostics = row['diagnostics'] or [
            'LEGACY_PROJECT_CONFIGURATION_REQUIRES_REPAIR' if row['action'] == 'MIGRATE_OWNED'
            else 'GLOBAL_NOT_CONFIGURED']
        config_path = row.get('config_path') or str((Path(row['layer']) if row['scope'] == 'GLOBAL'
                                                    else Path(row['layer']) / '.codex') / 'config.toml')
        hooks_path = row.get('hooks_path') or str(Path(config_path).with_name('hooks.json'))
        issues.append({
            'scope': row['scope'],
            'config_path': config_path, 'hooks_path': hooks_path,
            'affected_paths': [config_path, hooks_path] if any('HOOK' in d for d in diagnostics) else [config_path],
            'diagnostics': diagnostics, 'action': row['action'],
            'explanations': [_explain(code) for code in diagnostics],
            'ownership': row['ownership'],
        })
    try:
        plan = manager.plan(workspace)
        blocked = plan['blocked']
        approval = any(s['kind'] == 'REMOVE_USER_SERVER' for s in plan['steps'])
    except (ValueError, OSError, TypeError, RecursionError):
        blocked, approval = ['CONFIGURATION_REQUIRES_MANUAL_REVIEW'], False
    interrupted = False
    try:
        journal = manager._load()
        interrupted = bool(journal and journal['phase'] in {'RUNNING', 'RECOVERY_REQUIRED'})
        if interrupted:
            blocked = [*blocked, 'UPGRADE_RECOVERY_REQUIRED']
    except (ValueError, OSError, KeyError, TypeError, RecursionError):
        blocked = [*blocked, 'UPGRADE_JOURNAL_INVALID']
    project_issue = any(r['scope'] == 'PROJECT' for r in issues)
    if interrupted:
        message = '上次安全接入迁移中断，扫描尚未运行。先确认恢复已备份的配置，再重新诊断；恢复会保留中断后用户新改的内容并拒绝覆盖。'
        question = '是否允许按本机已签名的备份记录恢复上次接入迁移？不会修改项目代码或重建密钥。'
    elif blocked:
        message = '安全扫描尚未运行：接入配置无法安全自动迁移。现有配置已保留，需要先审阅下面标出的冲突位置。'
        question = None
    elif approval:
        message = ('安全扫描尚未运行：发现同名接入配置，与一次安装的全局版本冲突。'
                   '无需在每个项目重新安装；确认后可备份并迁移旧接入项，保留其他设置。')
        question = '是否允许备份并移除下面列出的同名安全接入配置，改用全局安装？不会修改项目代码或其他工具设置。'
    elif project_issue:
        message = '安全扫描尚未运行：此项目保留了已托管的旧接入配置。可一次备份迁移到全局版本，之后无需为该项目重复安装。'
        question = '是否允许备份并迁移此项目的旧安全接入配置，改用全局安装？'
    elif reason in {'MCP_PROBE_FAILED', 'MCP_PROBE_TIMEOUT'}:
        message = '全局配置已登记，但连接自检尚未成功；这不证明实际连接或扫描已成功。请重新连接或重启 Codex 后核对接入状态。'
        question = None
    else:
        message = '安全扫描尚未运行：全局接入尚未就绪。下面列出具体配置问题；只需修复一次全局接入，无需为新项目重复安装。'
        question = '是否允许备份并修复全局安全接入？'
    available = not blocked and reason not in {'MCP_PROBE_FAILED', 'MCP_PROBE_TIMEOUT'}
    prefix = _product_prefix(integration) if available or interrupted else []
    argv = [*prefix, 'repair'] if prefix and available else []
    if argv and workspace is not None:
        argv += ['--path', str(Path(workspace).absolute())]
    if argv and approval:
        argv.append('--approve-user-managed')
    return {
        'contract': 'configuration-recovery-v1', 'status': 'ACTION_REQUIRED',
        'message': message, 'question': question, 'issues': issues,
        'confirmation_required': approval, 'authorization': 'NOT_GRANTED_BY_DIAGNOSIS',
        'automatic_repair_available': available and bool(prefix), 'blocked': blocked,
        'blocker_explanations': [_explain(code) for code in blocked],
        'repair_argv': argv,
        'repair_command': display_command(argv) if argv else None,
        'recovery_argv': [*prefix, 'upgrade', 'recover'] if prefix and interrupted else [],
        'reconnect_required': True, 'configuration_modified': False,
        'scanner_run': False, 'security_proof': False,
    }


def repair_connection(integration, workspace=None, *, approve_user_managed=False):
    """Explicit CLI repair: reuse the signed plan/CAS journal, no Skill writes."""
    manager = InstallationUpgrade(integration, manage_skill=False)
    plan = manager.plan(workspace)
    # All-file preflight happens before any backup journal or configuration write.
    if plan['blocked']:
        raise IntegrationDiagnostic('UPGRADE_PLAN_BLOCKED')
    if any(s['kind'] == 'REMOVE_USER_SERVER' for s in plan['steps']) and not approve_user_managed:
        raise IntegrationDiagnostic('USER_MANAGED_APPROVAL_REQUIRED')
    receipt = manager.apply(plan, approve_user_managed=approve_user_managed)
    result = integration.configuration_status()
    return result | receipt | {
        'operation': 'REPAIRED',
        'migration': {'status': 'MIGRATED' if any(s['scope'] == 'PROJECT' for s in plan['steps']) else 'NONE',
                      'removed_layers': sum(s['scope'] == 'PROJECT' for s in plan['steps'])},
        'recovery_record': str(manager.directory / 'operation.json'),
    }
