"""Dedicated delegated audit boundary; a capability never authorizes other tools."""
from pathlib import Path


def input_failure(arguments, errors):
    """Field names only: never echo a capability or arbitrary invalid input."""
    fields = []
    def leaf_errors(error):
        if error.context:
            detailed = [e for e in error.context if not (e.validator == 'type' and
                        e.validator_value == 'null' and e.instance is not None)]
            for child in detailed:
                yield from leaf_errors(child)
        else:
            yield error
    known = {'check_ref', 'workspace_path', 'agent_ref', 'audit_token', 'action',
             'batch_id', 'request_id', 'observations', 'business_reviews', 'windows'}
    from .development_risks import Observation, BusinessReview
    from .development_report import ReportContent
    known.update(Observation.model_fields)
    known.update(BusinessReview.model_fields)
    known.update(ReportContent.model_fields)
    for error in (leaf for parent in errors for leaf in leaf_errors(parent)):
        path = '.'.join(str(p) if isinstance(p, int) or p in known else 'field'
                        for p in error.absolute_path) or 'arguments'
        if error.validator == 'required' and isinstance(error.instance, dict):
            fields.extend(dict(field=name if path == 'arguments' else path+'.'+name, code='REQUIRED') for name in error.validator_value
                          if name not in error.instance)
        elif error.validator == 'additionalProperties':
            fields.append(dict(field=path, code='UNKNOWN_FIELDS',
                               allowed_fields=list(error.schema.get('properties', {}))))
        elif error.validator == 'enum':
            fields.append(dict(field=path, code='INVALID', allowed_values=error.validator_value))
        else:
            fields.append(dict(field=path, code='INVALID'))
    unique = list({(f['field'], f['code']): f for f in fields}.values())[:20]
    return dict(status='INPUT_INVALID', reason_code='AUDIT_REQUEST_INVALID', field_errors=unique,
        recoverable=True, review_saved=False, scanner_run=False,
        message='审计请求参数不完整或无效。使用父任务 stream_started 返回的完整 child_call；'
                '仅修正列出的字段后重试一次，保留原批次、证据和判断。不要猜测身份或重新扫描。')


def delegated_risks(application, workspace_path, check_ref, audit_token, agent_ref):
    from .development_check import DevelopmentCheckStore, DevelopmentCheckService, REF
    from .development_risks import DevelopmentRisks, require
    from .audit_stream_service import authenticate
    require(isinstance(check_ref, str) and REF.fullmatch(check_ref), 'AUDIT_CAPABILITY_INVALID')
    root = Path(application.bound_path(workspace_path))
    checks = DevelopmentCheckStore(application.hooks, root)
    # SignedRecords verifies workspace binding and MAC before capability lookup.
    check = checks.read(check_ref)
    require(check is not None, 'AUDIT_CAPABILITY_INVALID')
    authenticate(check, audit_token, agent_ref)
    service = DevelopmentCheckService(application.runtime_provider, application.hooks,
        owner=check['owner'], scan_path_provider=application.scan_path_provider)
    return DevelopmentRisks(service, root, check_ref)
