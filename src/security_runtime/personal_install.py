"""Product installation: stable program, owned configuration, and scan readiness.

The signed CAS journal owns configuration writes. Public component preparation
is separate: a failed download must not undo successfully committed user setup.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys

from .integration_lifecycle import IntegrationDiagnostic
from .install_progress import report_progress, PREPARATION_STAGES, STAGE_PREFIX, EVENT_PREFIX, validate_preparation_event
from .processes import run_process
from .review_skill import ReviewSkillManager
from .upgrade import InstallationUpgrade, reason
from .delivery import verified_operation
from .install_checks import single_capability_check
from .install_readiness import prepare_installation_readiness, validate_readiness_receipt, CORE_TOOLS
from .toolchain import VERSIONS
from .progress import ScanCancelled
from .background_preparation import start_background_preparation, preparation_message

CONTRACT = 'personal-install-v1'
PREPARATION_TIMEOUT = 45  # Cache checks only; installation never waits for downloads.


def _unavailable_readiness(*, offline):
    return {'contract':'installation-readiness-v1', 'status':'UNAVAILABLE', 'ready':False,
        'message':'暂时无法确认安全检查组件和漏洞数据是否已准备完成。',
        'network_allowed':not offline,
        'tools':{name:{'status':'BROKEN', 'version':'', 'expected_version':VERSIONS[name],
            'ready':False} for name in CORE_TOOLS},
        'vulnerability_db':{'status':'BROKEN', 'freshness':'UNKNOWN', 'ready':False,
            'cached_usable':False}, 'failures':[]}


def _prepare_child(executable, *, offline, progress=None):
    # The installed candidate owns its compatibility pins, including when an
    # older product version is installing a newer locally validated bundle.
    argv = [str(executable), 'prepare-installation', '--json']
    if offline:
        argv.append('--offline')
    environment = dict(os.environ, SECURITY_RUNTIME_INSTALL_PROGRESS='1')
    last_stage = None
    def relay(line):
        nonlocal last_stage
        if line.startswith(EVENT_PREFIX):
            try:
                event = validate_preparation_event(json.loads(line[len(EVENT_PREFIX):]))
                if event is not None:
                    report_progress(progress, event)
            except (ValueError, TypeError, RecursionError):
                pass
            return
        if line.startswith(STAGE_PREFIX):
            stage = line[len(STAGE_PREFIX):]
            if offline and stage in {'INSTALL_TOOLS', 'INSTALL_DATA'}:
                stage = 'CHECK_SCAN_CACHE'
            if stage in {*PREPARATION_STAGES, 'CHECK_SCAN_CACHE'} and stage != last_stage:
                report_progress(progress, stage)
                last_stage = stage
    try:
        completed = run_process(argv, env=environment, timeout=PREPARATION_TIMEOUT,
            max_output=256_000, on_stderr_line=relay)
        if len(completed.stdout) > 256_000:
            raise ValueError()
        receipt = json.loads(completed.stdout)
        if (not validate_readiness_receipt(receipt)
                or completed.returncode != (0 if receipt['ready'] else 2)
                or offline and receipt['network_allowed']):
            raise ValueError()
        return receipt, None
    except (subprocess.TimeoutExpired, TimeoutError):
        return _unavailable_readiness(offline=offline), 'INSTALLATION_PREPARATION_TIMEOUT'
    except OSError:
        return _unavailable_readiness(offline=offline), 'INSTALLATION_PREPARATION_FAILED'
    except (ValueError, TypeError, AttributeError, RecursionError):
        return _unavailable_readiness(offline=offline), 'INSTALLATION_PREPARATION_RECEIPT_INVALID'


def _complete_preparation(data, *, offline, progress=None, executable=None):
    installation = data['installation']
    installation['scan_ready'] = False
    if installation.get('local_files_ready') is not True:
        return data
    diagnostic = None
    requested_offline = offline
    offline = True  # Installer checks caches; downloads belong to its detached worker.
    if executable is not None:
        report_progress(progress, 'CHECK_SCAN_CACHE')
        receipt, diagnostic = _prepare_child(executable, offline=offline, progress=progress)
        report_progress(progress, 'VERIFY_SCAN_READINESS')
    else:
        try:
            receipt = prepare_installation_readiness(progress=progress, offline=offline)
            if not validate_readiness_receipt(receipt):
                raise ValueError()
        except ScanCancelled:
            raise
        except Exception:
            receipt = _unavailable_readiness(offline=offline)
            diagnostic = 'INSTALLATION_PREPARATION_FAILED'
    data['scan_readiness'] = receipt
    ready = receipt['ready']
    installation.update(scan_ready=ready, status='INSTALLED',
        engine_preparation='AUTOMATIC_BACKGROUND; INSTALL_CACHE_CHECK_ONLY',
        message=('产品和全局连接已安装。' + receipt['message'] +
            '请完全退出并重启 Codex，按提示审核 Hook 信任；无需逐项目安装。') if ready else
            ('产品和全局连接已安装，但安全检查准备未完成。' + receipt['message'] +
            '已有配置和可用缓存会保留。'))
    if not requested_offline:
        report_progress(progress, 'START_BACKGROUND')
        try:
            background = start_background_preparation(executable)
        except (ValueError, OSError, TypeError, sqlite3.DatabaseError):
            background = {'status': 'FAILED', 'ready': False, 'reason': 'WORKER_START_FAILED'}
        data['background_preparation'] = background
        if not ready:
            installation['message'] += preparation_message(background)
        if background['status'] == 'FAILED':
            diagnostic = 'BACKGROUND_PREPARATION_START_FAILED'
    else:
        data['background_preparation'] = {'status': 'OFFLINE', 'ready': False}
        if not ready:
            installation['message'] += '本次为离线安装，未启动下载；联网后重新安装会自动准备。'
    data['overall'] = 'CONFIGURED' if ready else 'DEGRADED'
    data.setdefault('execution', {}).update(scanner_run=False, source_modified=False,
        component_preparation=False, network_allowed=False)
    # Permission to download is not evidence that a request actually occurred.
    # Do not keep the configuration-only receipt's misleading network=false.
    if not offline:
        data['execution'].pop('network_query', None)
    else:
        data['execution']['network_query'] = False
    diagnostics = set(data.get('diagnostics', []))
    if diagnostic:
        diagnostics.add(diagnostic)
    if not ready:
        diagnostics.add('INSTALLATION_SCANNING_NOT_READY')
    data['diagnostics'] = sorted(diagnostics)
    return data


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
        'installation':{'contract':CONTRACT, 'status':status, 'local_files_ready':False, 'scan_ready':False,
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
def install_personal_codex(*, bundle=None, root=None, workspace=None, allow_dev=False, progress=None, update=None, offline=False):
    """Install/check caches, then start detached preparation without waiting for it."""
    offline = bool(offline or os.getenv('SECURITY_RUNTIME_OFFLINE') == '1')
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
                workspace=workspace, allow_dev=allow_dev, progress=progress, offline=offline)
            result['downloads'] = {'product': 'LOCAL_DELTA', 'product_network_download': False,
                'engines': 'AUTOMATIC_BACKGROUND', 'skill_and_rules': 'BUNDLED'}
            return result
    if bundle is None and (not frozen or stable is not None):
        if root is not None and (stable is None or Path(root).absolute() != Path(stable).parents[1]):
            raise IntegrationDiagnostic('INSTALL_ROOT_REQUIRES_PORTABLE_BUNDLE')
        data = setup_personal_codex(integration, workspace, progress=progress)
        data = _complete_preparation(data, offline=offline, progress=progress)
        data['downloads'] = {'product':'EXISTING_INSTALL', 'product_network_download':False,
            'engines':'AUTOMATIC_BACKGROUND', 'skill_and_rules':'BUNDLED'}
        if stable is not None and data['installation']['scan_ready']:
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
    installed_executable = delivery.slot(activated['active_build']) / ('security-check.exe' if os.name == 'nt' else 'security-check')
    argv = [str(installed_executable), 'setup', 'codex', '--json']
    if workspace is not None:
        argv += ['--path', str(workspace)]
    # Execute only the just-validated fixed launcher, never a config-supplied command.
    report_progress(progress, 'SETUP_CHILD')
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
            timeout=120, check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
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
    data = _complete_preparation(data, offline=offline, progress=progress, executable=installed_executable)
    if data['installation']['scan_ready']:
        report_progress(progress, 'CLEANUP')
        data['cleanup'] = delivery.cleanup()
        data['delivery']['previous_build'] = delivery.pointer()['previous']
    data['downloads'] = {'product': 'LOCAL_DELTA' if update else 'LOCAL_FULL_PACKAGE',
        'product_network_download': False, 'engines': 'AUTOMATIC_BACKGROUND',
        'skill_and_rules': 'BUNDLED'}
    return data
