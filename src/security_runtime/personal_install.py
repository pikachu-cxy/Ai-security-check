"""One personal setup transaction: global connection AND the companion Skill.

The existing signed CAS journal owns all writes. This layer does not approve
unknown configuration, Hook trust, network operations or vulnerability repairs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from .integration_lifecycle import IntegrationDiagnostic
from .install_progress import report_progress
from .review_skill import ReviewSkillManager
from .upgrade import InstallationUpgrade, reason
from .delivery import verified_operation
from .install_checks import single_capability_check

CONTRACT = 'personal-install-v1'


def _blocked(manager, reasons, *, status='PREFLIGHT_BLOCKED', recovery=None):
    skill = manager.skill.status()
    skill_conflict = 'SKILL_USER_CONTENT_PRESERVED' in reasons
    message = ('发现同名 Skill 的自定义内容，已保留。请先选择保留或迁移它；'
               '本次不会覆盖，也不会把安装报告为成功。' if skill_conflict else
               '安装未完成。已保留现有配置；请按具体诊断处理后重试。')
    if status == 'ROLLED_BACK':
        message = '安装中断，本次配置和 Skill 改动已安全撤回；现有用户内容保留。请处理诊断后重试。'
    elif status == 'RECOVERY_REQUIRED':
        message = '安装中断，检测到不能安全自动撤回的状态。请先使用产品恢复入口，不要手动删除配置或 Skill。'
    return {'integration':'codex', 'scope':'GLOBAL', 'overall':'BROKEN',
        'diagnostics':sorted(set(reasons)), 'skill':skill,
        'installation':{'contract':CONTRACT, 'status':status, 'local_files_ready':False,
            'message':message, 'risk_fix_authorized':False,
            'recovery_status':recovery, 'restart_required':False},
        'execution':{'scanner_run':False, 'source_modified':False, 'network_query':False}}


@verified_operation
def setup_personal_codex(integration, workspace=None, *, skill=None, progress=None):
    with single_capability_check(integration):
        return _setup_personal_codex(integration, workspace, skill=skill, progress=progress)


def _setup_personal_codex(integration, workspace=None, *, skill=None, progress=None):
    """Install/upgrade both components, or return an explicit non-success result."""
    report_progress(progress, 'CHECK_CONFIG')
    manager = InstallationUpgrade(integration, skill or ReviewSkillManager())
    # Reuse the connection's stricter unknown-project preflight, before any writes.
    if workspace is not None:
        integration.inspect_project(workspace)
    plan = manager.plan(workspace)
    blocked = list(plan['blocked'])
    if any(step['kind'] == 'REMOVE_USER_SERVER' for step in plan['steps']):
        blocked.append('USER_MANAGED_APPROVAL_REQUIRED')
    if blocked:
        return _blocked(manager, blocked)
    try:
        report_progress(progress, 'APPLY_CONFIG')
        applied = manager.apply(plan, progress=progress)
    except (ValueError, OSError) as exc:
        code = reason(exc)
        recovered = None
        status = 'PREFLIGHT_BLOCKED'
        try:
            journal = manager._load()
            # Never recover an older operation merely because setup was requested.
            if (code != 'UPGRADE_RECOVERY_REQUIRED' and journal and journal['plan_id'] == plan['plan_id']
                    and journal['phase'] == 'RECOVERY_REQUIRED'):
                report_progress(progress, 'RECOVERY')
                recovered = manager.recover()['status']
                status = 'ROLLED_BACK' if recovered == 'RECOVERED' else 'RECOVERY_REQUIRED'
            elif journal and journal['phase'] not in {'COMMITTED', 'RECOVERED'}:
                status = 'RECOVERY_REQUIRED'
        except (ValueError, OSError):
            status = 'RECOVERY_REQUIRED'
        return _blocked(manager, [code], status=status, recovery=recovered)
    report_progress(progress, 'SELF_CHECK')
    data = integration.execute('status', workspace)
    current_skill = manager.skill.status()
    ready = data['overall'] == 'CONFIGURED' and current_skill['status'] == 'INSTALLED'
    data.update(skill=current_skill, reconnect_required=True,
        installation={'contract':CONTRACT, 'status':'INSTALLED' if ready else 'NOT_READY',
            'local_files_ready':ready, 'completed_steps':applied['completed_steps'],
            'message':'全局连接和专业 Skill 已协同安装。请重启 Codex，并按宿主提示审核 Hook 信任；无需逐项目安装。'
                if ready else '配置已写入，但安装自检未全部通过。请查看组件状态；不能视为已就绪。',
            'restart_required':True, 'live_host_connection':'NOT_VERIFIED_UNTIL_RECONNECT',
            'engine_preparation':'ON_DEMAND; NOT_PROVED_BY_SETUP',
            'risk_fix_authorized':False},
        execution={'scanner_run':False, 'source_modified':False, 'network_query':False})
    if not ready:
        data['overall'] = 'DEGRADED'
    return data


def _default_delivery_root():
    base = Path(os.environ['LOCALAPPDATA']) if os.name == 'nt' and os.environ.get('LOCALAPPDATA') else Path.home()/'.local/share'
    return base/'AI-Security-Runtime-install'


@verified_operation
def install_personal_codex(*, bundle=None, root=None, workspace=None, allow_dev=False, progress=None, update=None):
    """Portable EXE -> stable files -> the same atomic setup, in one command.

    A normal installed Python distribution needs only setup. No remote package
    download or public installer URL is implied by this local-package entrypoint.
    """
    report_progress(progress, 'PREPARE')
    from .global_integration import GlobalCodexIntegration
    from .delivery import StableDelivery, stable_command, package_metadata
    integration = GlobalCodexIntegration(allow_dev=allow_dev)
    frozen = bool(getattr(sys, 'frozen', False))
    stable = stable_command() if frozen else None
    if update is not None:
        if bundle is not None:
            raise IntegrationDiagnostic('INSTALL_UPDATE_AND_BUNDLE_CONFLICT')
        from .delta_delivery import materialized_update
        delivery_root = Path(root) if root is not None else Path(stable).parents[1] if stable else _default_delivery_root()
        with materialized_update(StableDelivery(delivery_root), update, progress=progress) as supplied:
            result = install_personal_codex(bundle=supplied, root=delivery_root,
                workspace=workspace, allow_dev=allow_dev, progress=progress)
            result['downloads'] = {'product': 'LOCAL_DELTA', 'network_download': False,
                'engines': 'REUSE_VALID_CACHE_OR_PREPARE_ON_DEMAND', 'skill_and_rules': 'BUNDLED'}
            return result
    if bundle is None and (not frozen or stable is not None):
        if root is not None and (stable is None or Path(root).absolute() != Path(stable).parents[1]):
            raise IntegrationDiagnostic('INSTALL_ROOT_REQUIRES_PORTABLE_BUNDLE')
        data = setup_personal_codex(integration, workspace, progress=progress)
        if stable is not None and data['installation']['local_files_ready']:
            report_progress(progress, 'CLEANUP')
            data['cleanup'] = StableDelivery(Path(stable).parents[1]).cleanup()
        return data
    supplied = Path(bundle) if bundle is not None else Path(sys.executable).parent
    # Validate all supplied package bytes, and configuration/Skill conflicts,
    # before running or activating that package. Hashes are not publisher proof.
    report_progress(progress, 'PACKAGE_VERIFY')
    package_metadata(supplied)
    report_progress(progress, 'CHECK_CONFIG')
    manager = InstallationUpgrade(integration, ReviewSkillManager())
    if workspace is not None:
        integration.inspect_project(workspace)
    plan = manager.plan(workspace)
    blocked = list(plan['blocked'])
    if any(step['kind'] == 'REMOVE_USER_SERVER' for step in plan['steps']):
        blocked.append('USER_MANAGED_APPROVAL_REQUIRED')
    if blocked:
        return _blocked(manager, blocked)
    delivery = StableDelivery(Path(root) if root is not None else _default_delivery_root())
    activated = delivery.activate(supplied, progress=progress)
    # Activation verified this exact slot. Invoke it directly, avoiding an
    # unnecessary launcher hop; discover() still writes the stable command.
    argv = [str(delivery.slot(activated['active_build']) / 'security-check.exe') if os.name == 'nt'
        else str(delivery.slot(activated['active_build']) / 'security-check'), 'setup', 'codex', '--json']
    if workspace is not None:
        argv += ['--path', str(workspace)]
    # Execute only the just-validated fixed launcher, never a config-supplied command.
    report_progress(progress, 'SETUP_CHILD')
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
            timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        code = 'INSTALLED_SETUP_TIMEOUT' if isinstance(exc, subprocess.TimeoutExpired) else 'INSTALLED_SETUP_FAILED'
        data = _blocked(manager, [code], status='NOT_READY')
        data['installation']['message'] += ' 程序文件已保留在安装目录，请重试安装并查看恢复诊断；不能视为已就绪。'
        data['delivery'] = activated
        return data
    report_progress(progress, 'VERIFY_RECEIPT')
    try:
        if len(completed.stdout) > 256_000:
            raise ValueError()
        data = json.loads(completed.stdout)
        if not isinstance(data, dict):
            raise ValueError()
        receipt = data.get('installation')
        if (not isinstance(receipt, dict) or receipt.get('contract') != CONTRACT
                or type(receipt.get('local_files_ready')) is not bool
                or not isinstance(receipt.get('message'), str)
                or receipt.get('status') not in {'INSTALLED', 'NOT_READY', 'PREFLIGHT_BLOCKED', 'ROLLED_BACK', 'RECOVERY_REQUIRED'}):
            raise ValueError()
        if receipt['local_files_ready'] and (data.get('overall') != 'CONFIGURED'
                or receipt['status'] != 'INSTALLED'
                or not isinstance(data.get('skill'), dict)
                or data['skill'].get('status') != 'INSTALLED'
                or manager.skill.status()['status'] != 'INSTALLED'):
            raise ValueError()
    except (ValueError, TypeError, RecursionError):
        data = _blocked(manager, ['INSTALLED_SETUP_RECEIPT_INVALID'], status='NOT_READY')
    if completed.returncode != 0 or data['installation'].get('local_files_ready') is not True:
        data['overall'] = 'BROKEN'
        data['installation']['local_files_ready'] = False
        data['installation']['message'] += ' 程序文件已保留在安装目录，但整体安装尚未成功；不代表可扫描。'
    data['delivery'] = activated
    if data['installation']['local_files_ready']:
        report_progress(progress, 'CLEANUP')
        data['cleanup'] = delivery.cleanup()
        data['delivery']['previous_build'] = delivery.pointer()['previous']
    data['downloads'] = {'product': 'LOCAL_DELTA' if update else 'LOCAL_FULL_PACKAGE',
        'network_download': False, 'engines': 'REUSE_VALID_CACHE_OR_PREPARE_ON_DEMAND',
        'skill_and_rules': 'BUNDLED'}
    return data
