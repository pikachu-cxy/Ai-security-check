"""Build a verified Windows repair-impact candidate using existing dependencies.

Internal product regressions only. This script never installs dependencies or a
Runtime, restarts a host, runs a target project's tests, or marks desktop acceptance.
The latest pointer is published only after every gate succeeds; failures retain a
separate run receipt and leave previous candidates unchanged.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
# Use the existing editable environment: putting src first also shadows the
# installed license-bearing dist-info with setuptools' source egg-info.
import security_runtime
if Path(security_runtime.__file__).resolve().parent != ROOT / 'src/security_runtime':
    raise SystemExit('The build environment must import this checkout through its local editable install.')

# Keep direct script execution independent of the third-party `build` package.
sys.path.insert(0, str(ROOT))
from scripts.build.dependency_notices import preflight
from scripts.build.build_standalone import STANDALONE_DOCUMENTS
from security_runtime.delivery import package_metadata
from security_runtime.hook_state import no_links

CONTRACT = 'repair-impact-v1'
TOOLS = ('prepare_repair_impact', 'read_repair_impact_context',
         'submit_repair_impact', 'get_repair_impact',
         'prepare_task_risk_fix', 'cancel_task_risk_fix')
HIDDEN_TOOLS = {'prepare_functional_verification', 'run_functional_verification'}
ACCEPTANCE_REGRESSIONS = ('tests/test_repair_impact_input_contract.py',
    'tests/test_native_repair_intent.py', 'tests/test_native_repair_impact_context.py',
    'tests/tasks/test_task_risk_fix_mcp.py', 'tests/task_review/test_task_review_submission_contract.py',
    'tests/task_review/test_task_review_submission_recovery.py',
    'tests/test_repair_impact_unknown_classification.py', 'tests/test_repair_impact_a2_recovery.py')
# These are product regressions, not a new personal-edition testing capability.
REGRESSIONS = (
    'tests/test_native_repair_intent.py', 'tests/test_native_repair_impact_context.py',
    'tests/tasks/test_task_risk_fix_mcp.py', 'tests/tasks/test_task_security.py',
    'tests/tasks/test_task_security_inventory.py', 'tests/task_review/test_task_review_redacted_changes.py',
    'tests/task_review/test_task_review_submission_contract.py', 'tests/task_review/test_task_review_submission_recovery.py',
    'tests/test_rebuild_task_review_probe.py',
    'tests/test_repair_impact_unknown_classification.py', 'tests/test_repair_impact_a2_recovery.py',
    'tests/task_review/test_task_review_protocol_mcp.py', 'tests/task_review/test_task_review_invariants.py', 'tests/task_review/test_task_review_v3_state.py',
    'tests/test_local_evidence.py', 'tests/test_local_evidence_empty_literals.py', 'tests/test_redactor_markers.py',
    'tests/test_scan_workspace_contract.py',
    'tests/test_reply_plan.py', 'tests/guidance/test_risk_decision_experience.py',
    'tests/test_feedback_contract_v2.py', 'tests/test_finding_disposition.py',
    'tests/tasks/test_task_risk_dispositions.py', 'tests/tasks/test_task_risk_feedback.py',
    'tests/tasks/test_task_fix.py', 'tests/tasks/test_task_triage.py',
    'tests/test_remediation.py', 'tests/test_remediation_episodes.py',
    'tests/test_confirmation.py', 'tests/test_agent_fix_envelope.py',
    'tests/test_agent_fix_ticket.py', 'tests/test_fix_context.py',
    'tests/test_hook_advice_feedback.py', 'tests/test_hook_user_feedback.py',
    'tests/test_check_operation_boundaries.py', 'tests/test_hook_reply_context.py',
    'tests/distribution/test_bootstrap_recovery.py', 'tests/test_codex_host_claims.py',
    'tests/test_hook_dispositions.py', 'tests/guidance/test_host_feedback_contract.py',
    'tests/test_host_orchestration.py', 'tests/test_codex_code_mode_contract.py',
    'tests/test_review_mcp.py', 'tests/guidance/test_review_skill.py',
    'tests/test_global_integration.py', 'tests/test_global_ownership_v2.py',
    'tests/test_global_workspace_binding.py', 'tests/test_global_workspace_root_regression.py',
    'tests/tasks/test_task_context_global_transport.py', 'tests/tasks/test_task_ownership.py',
    'tests/tasks/test_task_preimages.py', 'tests/task_review/test_task_review_revisions.py',
    'tests/task_review/test_task_review_adaptive_budget.py', 'tests/task_review/test_task_review_transport_v3.py',
    'tests/task_review/test_task_review_results.py', 'tests/test_review_evidence.py',
    'tests/test_local_evidence_comments.py', 'tests/test_post_fix_functional_prompt.py',
    'tests/test_functional_remediation.py',
    'tests/test_personal_install.py', 'tests/distribution/test_distribution.py',
    'tests/distribution/test_standalone_documents.py', 'tests/test_cli_json_encoding.py',
    'tests/distribution/test_dependency_notices.py',
)
SOURCE_PREFIXES = ('src/', 'distribution/', 'scripts/', 'tests/')
SOURCE_NAMES = {'pyproject.toml', 'LICENSE', 'EULA.md', 'LICENSING.md',
                'THIRD_PARTY_NOTICES.md', 'SOURCE_OFFER.md', 'MANIFEST.in'}
SOURCE_SUFFIXES = {'.py', '.md', '.json', '.yml', '.yaml', '.toml', '.mjs', '.c',
                   '.h', '.spec', '.txt', '.ini', '.cfg'}


def stamp():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value, *, replace=False):
    no_links(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=True, indent=2) + '\n'
    if not replace:
        with path.open('x', encoding='utf-8') as stream:
            stream.write(payload)
        return
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            stream.write(payload)
        no_links(path)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def git(*arguments):
    result = subprocess.run(['git', '--no-optional-locks', '-c',
        'safe.directory=' + ROOT.as_posix(), '-c', 'core.fsmonitor=false',
        '-C', str(ROOT), *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
    if len(result.stdout) > 2_000_000:
        raise ValueError('Source provenance exceeds the bounded inventory size')
    return result.stdout.decode('utf-8', errors='strict')


def source_snapshot():
    commit = git('rev-parse', 'HEAD').strip()
    if len(commit) != 40 or any(char not in '0123456789abcdef' for char in commit):
        raise ValueError('Source commit is unverifiable')
    status = git('status', '--porcelain=v1', '-z', '--untracked-files=all').split('\0')
    dirty, index = [], 0
    while index < len(status) and status[index]:
        entry = status[index]
        row = {'status': entry[:2], 'path': entry[3:]}
        index += 1
        if 'R' in row['status'] or 'C' in row['status']:
            row['original_path'] = status[index]
            index += 1
        dirty.append(row)
    names = set(git('ls-files', '--cached', '--others', '--exclude-standard', '-z').split('\0'))
    hashes, total = {}, 0
    for name in sorted(names):
        relative = PurePosixPath(name)
        if not name or relative.is_absolute() or '..' in relative.parts or ':' in name:
            if name:
                raise ValueError('Source inventory contains an unsafe path')
            continue
        selected = (name in SOURCE_NAMES or name.startswith('LICENSES/')
            or name.startswith(SOURCE_PREFIXES) and relative.suffix.lower() in SOURCE_SUFFIXES
            or name in {'docs/RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md',
                'docs/REPAIR_IMPACT_ASSESSMENT_PLAN.zh-CN.md',
                'docs/design/REPAIR_IMPACT_ASSESSMENT_DESIGN.zh-CN.md'}
            or name in STANDALONE_DOCUMENTS)
        if not selected:
            continue
        file = ROOT / name
        no_links(file)
        if not file.exists():
            continue  # Deleted inputs are described by the dirty inventory.
        raw = file.read_bytes()
        total += len(raw)
        if total > 50_000_000 or len(hashes) >= 5000:
            raise ValueError('Source manifest capacity exceeded')
        hashes[name] = hashlib.sha256(raw).hexdigest()
    encoded = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()
    return {'source_commit': commit, 'source_dirty': bool(dirty),
            'source_dirty_entries': dirty, 'source_files': hashes,
            'source_manifest_sha256': hashlib.sha256(encoded).hexdigest(),
            'source_file_count': len(hashes), 'source_input_bytes': total}


def same_inputs(before, after):
    if (before['source_commit'], before['source_files'], before['source_dirty_entries']) != (
            after['source_commit'], after['source_files'], after['source_dirty_entries']):
        raise ValueError('Source inputs changed during validation; preserve this run and build a new candidate')


def regression_targets():
    feature = sorted(path.relative_to(ROOT).as_posix()
                     for path in (ROOT / 'tests').glob('test_repair_impact*.py'))
    if not feature:
        raise ValueError('Repair-impact regression files are required before packaging')
    missing = [name for name in REGRESSIONS if not (ROOT / name).is_file()]
    if missing:
        raise ValueError('Required regression files are missing: ' + ', '.join(missing))
    return list(dict.fromkeys([*feature, *REGRESSIONS]))


def junit_counts(path):
    document = ET.parse(path).getroot()
    cases = list(document.iter('testcase'))
    failed = sum(case.find('failure') is not None for case in cases)
    errors = sum(case.find('error') is not None for case in cases)
    skipped = sum(case.find('skipped') is not None for case in cases)
    feature = [case for case in cases if 'repair_impact' in case.get('classname', '')]
    feature_passed = sum(not any(case.find(tag) is not None for tag in ('failure', 'error', 'skipped'))
                         for case in feature)
    acceptance = {}
    for name in ACCEPTANCE_REGRESSIONS:
        module = Path(name).stem
        selected = [case for case in cases if module in case.get('classname', '').split('.')]
        acceptance[name] = dict(total=len(selected), passed=sum(
            not any(case.find(tag) is not None for tag in ('failure', 'error', 'skipped'))
            for case in selected))
    return {'total': len(cases), 'passed': len(cases)-failed-errors-skipped,
            'failed': failed, 'errors': errors, 'skipped': skipped,
            'repair_impact_cases': len(feature), 'repair_impact_passed': feature_passed,
            'acceptance_regressions': acceptance}


def clean_environment(profile):
    env = {name: value for name, value in os.environ.items()
           if not name.startswith('SECURITY_RUNTIME_') and name not in {'PYTHONHOME', 'PYTHONPATH'}}
    env.update(SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_INTEGRATION='codex', SECURITY_RUNTIME_HOST='codex',
        SECURITY_RUNTIME_STATE_DIR=str(profile / 'state'),
        SECURITY_RUNTIME_DATA_DIR=str(profile / 'data'),
        SECURITY_RUNTIME_CONFIG=str(profile / 'config.toml'), PYTHONUTF8='1')
    return env


def decoded_tool(result, *, expected_error=False):
    if bool(result.isError) != expected_error:
        raise ValueError('Frozen tool returned an unexpected success/error status')
    value = (result.structuredContent if result.structuredContent is not None else
        json.loads(next(item.text for item in result.content if item.type == 'text')))
    if not isinstance(value, dict):
        raise ValueError('Frozen tool did not return a structured object')
    return value


def has_contract(value, token):
    if isinstance(value, str):
        return token in value
    if isinstance(value, dict):
        return any(has_contract(item, token) for item in value.values())
    if isinstance(value, list):
        return any(has_contract(item, token) for item in value)
    return False


def task_review_schema_payload():
    """Schema-only examples; no reference here is issued or submitted as a risk."""
    return dict(workspace_path='C:/schema-only-never-admitted', task_ref='ts1-' + 'c' * 32,
        review_session='tr1-' + 'd' * 32, coverage='REVIEWED', limitations=[],
        findings=[dict(title='Schema-only access review', category='ACCESS_CONTROL', severity='MEDIUM',
            risk_scope='RELATED_EXISTING', primary_evidence='te3-' + 'a' * 32,
            task_evidence='te3-' + 'b' * 32,
            evidence_refs=['te3-' + 'a' * 32, 'te3-' + 'b' * 32], impact='Schema example only.',
            preconditions=['A caller can choose the object ID.'], unknowns=['Upstream checks are unknown.'],
            counterevidence=[], current_protections=[], fix_advice='Check access before returning content.')])


def malformed_task_review_payload():
    payload = task_review_schema_payload()
    candidate = payload['findings'][0]
    candidate['primary_evidence'] = dict(evidence_id=candidate['primary_evidence'], file_path='documents.py',
        start_line=1, end_line=3)
    candidate['task_evidence'] = dict(evidence_id=candidate['task_evidence'], file_path='download.py',
        start_line=4, end_line=5)
    candidate['evidence_refs'] = [candidate['primary_evidence'], candidate['task_evidence']]
    return payload


def malformed_impact_unknown_payload():
    """A semantic conflict must fail before the schema-only root is admitted."""
    evidence = 'ri-evidence-' + 'b' * 32
    return dict(workspace_path='C:/schema-only-never-admitted', assessment_ref='ria1-' + 'a' * 32,
        impacts=[dict(kind='EXPECTED_SECURITY_RESTRICTION', summary='Reject unauthorized reads.',
                      evidence_refs=[evidence])],
        unknowns=[dict(summary='External presentation is outside this local proposal.',
            classification='SCOPE_LIMITATION', critical=True,
            decision_basis='This intentionally contradictory label is a negative probe.',
            evidence_refs=[evidence])])


def frozen_schema_contract(rows):
    """Check the schema actually advertised by the frozen process, not src."""
    from jsonschema import Draft202012Validator
    submit = rows['submit_repair_impact']
    properties = submit['properties']
    item = properties['impacts']['items']
    if '$ref' in item:
        item = submit['$defs'][item['$ref'].removeprefix('#/$defs/')]
    if (set(item['properties']['kind'].get('enum', [])) != {
            'EXPECTED_SECURITY_RESTRICTION', 'NO_ADDITIONAL_CHANGE_IDENTIFIED',
            'BUSINESS_BEHAVIOR_CHANGE', 'UNDETERMINED'} or
            set(properties['coverage'].get('enum', [])) != {'REVIEWED', 'PARTIAL'} or
            item.get('additionalProperties') is not False):
        raise ValueError('Frozen impact schema does not expose the closed analysis contract')
    page = rows['get_repair_impact']['properties']['limit']
    if page.get('minimum') != 1 or page.get('maximum') != 10:
        raise ValueError('Frozen impact history page limits are missing')
    for name in ('prepare_task_risk_fix', 'cancel_task_risk_fix'):
        schema = rows[name]
        required = {'task_ref', 'finding_id', 'user_requested'}
        if name == 'prepare_task_risk_fix':
            required.add('impact_ref')
        intent = schema['properties']['user_requested']
        if (not required.issubset(schema.get('required', [])) or
                schema.get('additionalProperties') is not False or
                intent.get('type') != 'boolean' or intent.get('const') is not True):
            raise ValueError('Frozen native repair schema is incomplete: ' + name)
    workspace = dict(workspace_path='C:/schema-only-never-admitted')
    ref = 'ria1-' + 'a' * 32
    impact = dict(kind='EXPECTED_SECURITY_RESTRICTION', summary='Preserve shared member reads.',
                  evidence_refs=['ri-evidence-' + 'b' * 32])
    validator = Draft202012Validator(submit)
    payload = dict(workspace, assessment_ref=ref, impacts=[impact], unknowns=[])
    for kind in ('EXPECTED_SECURITY_RESTRICTION', 'NO_ADDITIONAL_CHANGE_IDENTIFIED',
                 'BUSINESS_BEHAVIOR_CHANGE', 'UNDETERMINED'):
        validator.validate(dict(payload, impacts=[dict(impact, kind=kind)], coverage='REVIEWED'))
    validator.validate(dict(payload, coverage='PARTIAL'))
    invalid = [dict(payload, impacts=[dict(impact, kind='SECURITY_RESTRICTION')]),
               dict(payload, coverage='FULL'), dict(payload, coverage='COMPLETE'),
               dict(payload, unknowns=[dict(summary='Unknown policy.', critical='true')]),
               dict(payload, impacts=[dict(impact, unsupported='not allowed')])]
    if any(validator.is_valid(value) for value in invalid):
        raise ValueError('Frozen impact schema accepts an invalid nested contract')
    unknown = properties['unknowns']['items']
    if '$ref' in unknown:
        unknown = submit['$defs'][unknown['$ref'].removeprefix('#/$defs/')]
    label = unknown['properties'].get('classification', {})
    labels = next((part.get('enum', []) for part in label.get('anyOf', [label])
                   if part.get('type') == 'string'), [])
    if set(labels) != {'BLOCKING_CONTEXT', 'SCOPE_LIMITATION'} or 'decision_basis' not in unknown['properties']:
        raise ValueError('Frozen impact schema lacks explicit unknown classification')
    for classification, critical in (('BLOCKING_CONTEXT', True), ('SCOPE_LIMITATION', False)):
        validator.validate(dict(payload, unknowns=[dict(summary='Schema-only unknown.',
            classification=classification, critical=critical, evidence_refs=impact['evidence_refs'],
            decision_basis='Explain the missing fact and its effect on this exact proposal.')]))
    for name in ('prepare_task_risk_fix', 'cancel_task_risk_fix'):
        validator = Draft202012Validator(rows[name])
        payload = dict(workspace, task_ref='ts1-' + 'c' * 32, finding_id='tc1-' + 'd' * 32,
                       user_requested=True)
        if name == 'prepare_task_risk_fix':
            payload['impact_ref'] = ref
        validator.validate(payload)
        for value in (False, 1, 'true'):
            if validator.is_valid(dict(payload, user_requested=value)):
                raise ValueError('Frozen native schema coerces user repair intent')
        for key in ('task_ref', 'finding_id', 'user_requested'):
            if validator.is_valid({k: v for k, v in payload.items() if k != key}):
                raise ValueError('Frozen native schema accepts missing selection fields')
    review = rows['submit_task_security_review']
    candidate = review['properties']['findings']['items']
    if '$ref' in candidate:
        candidate = review['$defs'][candidate['$ref'].removeprefix('#/$defs/')]
    props = candidate['properties']
    if (candidate.get('additionalProperties') is not False
            or props['primary_evidence'].get('type') != 'string'
            or props['task_evidence'].get('type') != 'string'
            or props['evidence_refs'].get('type') != 'array'
            or props['evidence_refs']['items'].get('type') != 'string'):
        raise ValueError('Frozen task review schema does not expose evidence ID strings')
    validator = Draft202012Validator(review)
    validator.validate(task_review_schema_payload())
    if validator.is_valid(malformed_task_review_payload()):
        raise ValueError('Frozen task review schema accepts B2 object-shaped evidence')
    return dict(status='PASSED', closed_impact_kinds=True, coverage_values=True,
        bounded_history_page=True, explicit_native_repair_intent=True,
        typed_task_review_evidence=True, object_shaped_task_evidence_rejected=True,
        explicit_unknown_classification=True,
        representative_schema_inputs_validated=True, invalid_schema_inputs_rejected=True,
        native_preparation_executed=False, native_baseline_guard_executed=False)


async def frozen_mcp(executable, env, errors):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    async with stdio_client(StdioServerParameters(command=str(executable), args=['mcp'],
        cwd=str(ROOT), env=env), errlog=errors) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=60)) as client:
            await client.initialize()
            info = decoded_tool(await client.call_tool('get_runtime_info', {}))
            rows, cursor = {}, None
            for _ in range(20):
                page = await client.list_tools(cursor=cursor)
                rows.update((tool.name, tool.inputSchema) for tool in page.tools)
                cursor = page.nextCursor
                if cursor is None:
                    break
            else:
                raise ValueError('Frozen tool list exceeded bounded pagination')
            # Invalid JSON is rejected before project admission; no task or scan
            # may be created by this process-level regression probe.
            rejected = decoded_tool(await client.call_tool('submit_task_security_review',
                malformed_task_review_payload()), expected_error=True)
            fields = {item['field'] for item in rejected.get('field_errors', [])}
            if (rejected.get('reason_code') != 'TASK_REVIEW_INPUT_INVALID'
                    or not {'findings[0].primary_evidence', 'findings[0].task_evidence'} <= fields
                    or any(rejected.get(key) is not False for key in
                        ('scanner_run', 'source_modified', 'repair_authorized', 'review_state_changed'))
                    or 'workspace_readiness' in rejected):
                raise ValueError('Frozen task review input rejection lost actionable safe diagnostics')
            rejected_unknown = decoded_tool(await client.call_tool('submit_repair_impact',
                malformed_impact_unknown_payload()), expected_error=True)
            if (rejected_unknown.get('reason_code') != 'REPAIR_IMPACT_INPUT_INVALID'
                    or not any(row['field'].startswith('unknowns[')
                               for row in rejected_unknown.get('field_errors', []))
                    or any(rejected_unknown.get(key) is not False for key in
                           ('scanner_run', 'source_modified', 'repair_authorized'))
                    or 'workspace_readiness' in rejected_unknown):
                raise ValueError('Frozen unknown classification conflict was not rejected before admission')
    if not set(TOOLS).issubset(rows) or HIDDEN_TOOLS.intersection(rows):
        raise ValueError('Frozen repair-impact tools missing or personal hidden tools exposed')
    schema_contract = frozen_schema_contract(rows)
    for name in ('prepare_task_fix', 'confirm_remediation'):
        if 'impact_ref' not in rows.get(name, {}).get('properties', {}):
            raise ValueError('Frozen repair gate is missing impact_ref: ' + name)
    for contract in (CONTRACT, 'security-reply-plan-v1', 'risk-decisions-v2', 'task-review-submission-v1',
                     'repair-impact-unknowns-v1'):
        if not has_contract(info, contract):
            raise ValueError('Frozen Runtime does not advertise required contract: ' + contract)
    return {'status': 'PASSED', 'runtime_info': info,
            'tool_names': sorted(rows), 'required_tools': list(TOOLS),
            'schema_contract': schema_contract,
            'task_review_input_rejection': dict(status='PASSED', field_diagnostics=True,
                scanner_run=False, workspace_admitted=False, task_created=False),
            'unknown_classification_rejection': dict(status='PASSED', field_diagnostics=True,
                scanner_run=False, workspace_admitted=False, task_created=False),
            'hidden_personal_tools_absent': True, 'impact_gate_parameters_present': True,
            'scanner_run': False, 'hook_dispatch': False, 'runtime_installed': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher-bundle', type=Path,
        help='Explicit verified local bundle for an unchanged launcher; no downloads or installs')
    args = parser.parse_args(argv)
    if os.name != 'nt':
        raise SystemExit('This candidate workflow targets Windows.')
    for name in ('pytest', 'PyInstaller', 'mcp'):
        if importlib.util.find_spec(name) is None:
            raise SystemExit('Existing build environment is missing ' + name + '; no dependency was installed.')
    if not any((Path(sys.base_prefix) / name).is_file() for name in ('LICENSE.txt', 'LICENSE')):
        raise SystemExit('A local CPython license is required; this workflow does not fetch build inputs.')
    dependencies = preflight()
    if args.launcher_bundle is None and not shutil.which('gcc'):
        raise SystemExit('Existing GCC or an explicit verified --launcher-bundle is required; no compiler was installed.')
    if args.launcher_bundle is not None:
        package_metadata(args.launcher_bundle)
    targets = regression_targets()
    candidate = 'repair-impact-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    run_dir = ROOT / 'artifacts' / candidate
    no_links(run_dir)
    run_dir.mkdir(parents=True, exist_ok=False)
    run_path = run_dir / 'run.json'
    receipt = {'candidate_kind': 'LOCAL_REPAIR_IMPACT_ACCEPTANCE', 'candidate': candidate,
        'created_at': stamp(), 'status': 'RUNNING', 'installed': False,
        'desktop_acceptance': 'PENDING_USER', 'repair_impact_contract': CONTRACT,
        'reply_plan_contract': 'security-reply-plan-v1', 'risk_decision_contract': 'risk-decisions-v2',
        'python': sys.executable, 'reviewed_build_dependencies': dependencies,
        'test_scope': targets, 'full_repository_suite_claimed': False,
        'acceptance_guide': 'docs/RUNTIME_CHAIN_REGRESSION_ACCEPTANCE.zh-CN.md'}
    stage = 'SOURCE_SNAPSHOT'
    try:
        snapshot = source_snapshot()
        manifest_path = run_dir / 'source-manifest.json'
        write_json(manifest_path, snapshot)
        receipt.update({key: snapshot[key] for key in
            ('source_commit', 'source_dirty', 'source_dirty_entries', 'source_manifest_sha256')})
        receipt['source_manifest'] = str(manifest_path)
        stage = 'INTERNAL_REGRESSIONS'
        started = time.perf_counter()
        xml = run_dir / 'regression.xml'
        with tempfile.TemporaryDirectory(prefix='ai-security-repair-impact-tests-') as temporary:
            command = [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                '--basetemp', str(Path(temporary) / 'cases'), '--junitxml', str(xml), *targets]
            result = subprocess.run(command, cwd=ROOT, check=False)
        counts = junit_counts(xml) if xml.is_file() else {}
        receipt['regression'] = {'status': 'PASSED' if result.returncode == 0 else 'FAILED',
            'exit_code': result.returncode, 'duration_seconds': round(time.perf_counter()-started, 3),
            'junit': str(xml), **counts}
        acceptance = counts.get('acceptance_regressions', {})
        if (result.returncode or not counts.get('repair_impact_passed')
                or any(not acceptance.get(name, {}).get('total') or
                       acceptance[name]['passed'] != acceptance[name]['total']
                       for name in ACCEPTANCE_REGRESSIONS)
                or counts.get('failed') or counts.get('errors')):
            receipt['regression']['status'] = 'FAILED'
            raise ValueError(
                'Required internal regressions did not pass: '
                f'pytest exit_code={result.returncode}, '
                f'passed={counts.get("passed", "UNKNOWN")}, '
                f'failed={counts.get("failed", "UNKNOWN")}, '
                f'errors={counts.get("errors", "UNKNOWN")}. '
                f'Test report: {xml}. Run receipt: {run_path}. '
                'No new candidate was built; latest was not updated.')
        same_inputs(snapshot, source_snapshot())
        stage = 'BUILD_STANDALONE'
        command = [sys.executable, str(ROOT / 'scripts/build/build_standalone.py'),
            '--output-dir', 'dist/' + candidate, '--work-dir', 'build/' + candidate]
        if args.launcher_bundle is not None:
            command.extend(['--launcher-bundle', str(args.launcher_bundle.resolve(strict=True))])
        with (run_dir / 'build.log').open('w', encoding='utf-8') as log:
            subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        bundle = ROOT / 'dist' / candidate / 'security-check'
        executable = bundle / 'security-check.exe'
        stage = 'PACKAGE_INTEGRITY'
        metadata = package_metadata(bundle)
        same_inputs(snapshot, source_snapshot())
        if (metadata['source_commit'] != snapshot['source_commit']
                or metadata['source_dirty'] != snapshot['source_dirty']):
            raise ValueError('Bundle commit differs from the validated source')
        stage = 'FROZEN_IDENTITY_AND_TOOLS'
        with tempfile.TemporaryDirectory(prefix='ai-security-repair-impact-probe-') as temporary:
            env = clean_environment(Path(temporary))
            identity = subprocess.run([str(executable), 'runtime-info', '--json'], cwd=ROOT,
                env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60, check=True)
            cli_info = json.loads(identity.stdout.decode('utf-8-sig'))
            with (run_dir / 'mcp-stderr.log').open('w', encoding='utf-8') as errors:
                probe = asyncio.run(asyncio.wait_for(frozen_mcp(executable, env, errors), timeout=120))
        for info in (cli_info, probe['runtime_info']):
            built = info.get('build_identity', {})
            if (info.get('version') != metadata['version']
                    or any(built.get(key) != metadata[key]
                           for key in ('version', 'build_id', 'source_commit', 'source_dirty'))):
                raise ValueError('Frozen process identity differs from version.json')
        write_json(run_dir / 'frozen-probe.json', dict(probe, cli_runtime_info=cli_info))
        same_inputs(snapshot, source_snapshot())
        receipt.update(status='PASSED', completed_at=stamp(), bundle=str(bundle), executable=str(executable),
            version=metadata['version'], build_id=metadata['build_id'],
            source_dirty=metadata['source_dirty'],
            package_integrity={'status': 'PASSED', 'method': 'package_metadata full inventory and SHA-256',
                'verified_file_count': len(metadata['files'])},
            source_inputs_unchanged=True, frozen_probe=str(run_dir / 'frozen-probe.json'),
            necessary_tools=list(TOOLS), build_log=str(run_dir / 'build.log'))
        write_json(run_path, receipt)
        # Only this feature's pointer changes, and only after all gates passed.
        write_json(ROOT / 'artifacts/repair-impact-latest.json', receipt, replace=True)
    except Exception as exc:
        receipt.update(status='FAILED', failed_stage=stage, completed_at=stamp(),
                       failure_type=type(exc).__name__, latest_pointer_updated=False)
        write_json(run_path, receipt, replace=run_path.exists())
        print(json.dumps(receipt, ensure_ascii=True, indent=2))
        raise
    print(json.dumps(receipt, ensure_ascii=True, indent=2))
    print('Candidate ready. Desktop acceptance is still PENDING_USER; no host was installed or restarted.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
