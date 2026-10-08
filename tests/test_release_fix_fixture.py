"""Release acceptance must use current default-enabled rules, not legacy rules."""
import pytest

from scripts.fix_verify_acceptance import write_task_sources
from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.scanners import SemgrepAdapter
from security_runtime.verification_policy import local_recheck


@pytest.mark.parametrize('hostname,secondary,count', [(True, True, 2), (False, True, 1), (False, False, 0)])
def test_release_fix_fixture_has_real_core_occurrences(tmp_path, hostname, secondary, count):
    write_task_sources(tmp_path, hostname, secondary)
    with local_recheck():
        findings, run = SemgrepAdapter().scan(ScanContext(str(tmp_path), ScanMode.FEATURE, ('Tls.java', 'OtherTls.java')), FindingNormalizer(tmp_path))
    assert run.status == 'SUCCESS' and run.rule_coverage['status'] == 'EXECUTED'
    assert len(findings) == count
    assert all(f.technical_details['rule_id'] == 'ai-security.java.trust-all-hostname' and
               f.technical_details['capability_maturity'] == 'CORE' for f in findings)
