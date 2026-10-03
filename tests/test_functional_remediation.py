"""Use real existing signed remediation state, not host-asserted resolution."""
import json
import pytest

from test_hook_runtime import repo
from test_remediation import setup, FIXED, UNSAFE
from test_functional_verification import Executor
from security_runtime.functional_verification import FunctionalVerificationService
from security_runtime.remediation import RemediationService


def arguments(setup):
    data=setup[-1]['remediation']
    if data['action']=='CONFIRM_REQUIRED':
        data=setup[3].confirm(data['confirmation_ref'],data['task_ref'],setup[0],approve=True)
    return data['prepare']['arguments']


@pytest.mark.parametrize('setup',['smart_auto','ask_before_fix'],indirect=True)
def test_authorized_resolution_gates_existing_functional_service(setup,monkeypatch):
    root,runtime,provider,remediation,hook,_=setup
    # Existing fixture has no build config; do not mutate its preservation proof.
    # Exercise Python detector injected internally only for integration coverage.
    from security_runtime.functional_verifiers import Step
    from types import SimpleNamespace
    registry=SimpleNamespace(detect=lambda root:[Step('TEST','python','python-pytest','/usr/bin/python',('-m','pytest'),())],
                             plan=lambda *args:dict(version='functional-verification-v0.1',config_hash='b'*64,steps=[]))
    executor=Executor(); service=FunctionalVerificationService(remediation,registry=registry,executor=executor)
    data=arguments(setup)
    out=service.prepare(data['remediation_ref'],data['task_ref'],root,bound_workspace=root)
    assert out['overall_status']=='SECURITY_NOT_VERIFIED' and not executor.calls
    assert remediation.prepare(data['remediation_ref'],data['task_ref'],root)['status']=='READY_FOR_HOST_FIX'
    (root/'A.java').write_text(FIXED); runtime.findings=provider.findings=[]
    assert hook()['remediation']['verification']['verification_status']=='SCANNER_VERIFIED_RESOLVED'
    assert remediation.verify(data['remediation_ref'],data['task_ref'],root)['verification_status']=='SCANNER_VERIFIED_RESOLVED'
    out=service.prepare(data['remediation_ref'],data['task_ref'],root,bound_workspace=root)
    assert out['status']=='PLANNED',out
    final=service.run(out['functional_ref'],bound_workspace=root)
    assert final['overall_status']=='SECURITY_AND_FUNCTIONALLY_VERIFIED' and len(executor.calls)==1
    assert (root/'A.java').read_text()==FIXED


@pytest.mark.parametrize('setup',['ask_before_fix'],indirect=True)
def test_declined_and_forged_resolution_do_not_run(setup):
    root,_,_,remediation,_,grant=setup
    data=grant['remediation']
    assert remediation.confirm(data['confirmation_ref'],data['task_ref'],root,approve=False)['status']=='DECLINED'
    executor=Executor(); service=FunctionalVerificationService(remediation,executor=executor)
    out=service.prepare(data['confirmation_ref'],data['task_ref'],root,bound_workspace=root)
    assert out['overall_status']=='SECURITY_NOT_VERIFIED' and not executor.calls
    assert (root/'A.java').read_text()==UNSAFE


def test_changed_source_and_policy_invalidate_security_receipt(setup):
    root,runtime,provider,remediation,hook,_=setup; data=arguments(setup)
    remediation.prepare(data['remediation_ref'],data['task_ref'],root)
    (root/'A.java').write_text(FIXED); runtime.findings=provider.findings=[]; hook()
    assert remediation.functional_receipt(data['remediation_ref'],data['task_ref'],root)
    (root/'Other.java').write_text('class Other {}')
    assert remediation.functional_receipt(data['remediation_ref'],data['task_ref'],root) is None
    (root/'Other.java').unlink(); remediation.config.write('report_only')
    assert remediation.functional_receipt(data['remediation_ref'],data['task_ref'],root) is None


@pytest.mark.parametrize('setup',['ask_before_fix'],indirect=True)
def test_approved_receipt_not_restored_after_restart(setup):
    root,runtime,provider,remediation,hook,_=setup; data=arguments(setup)
    remediation.prepare(data['remediation_ref'],data['task_ref'],root)
    (root/'A.java').write_text(FIXED); runtime.findings=provider.findings=[]; hook()
    restart=RemediationService(remediation.store,registry=remediation.registry,hooks=remediation.hooks,config=remediation.config)
    assert remediation.functional_receipt(data['remediation_ref'],data['task_ref'],root)
    assert restart.functional_receipt(data['remediation_ref'],data['task_ref'],root) is None
