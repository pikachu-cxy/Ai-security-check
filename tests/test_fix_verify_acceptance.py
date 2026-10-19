"""The native fix gate keeps private scan state outside its source fixture."""
import runpy
import asyncio
from pathlib import Path

import pytest

from security_runtime.hooks import HookStateStore
from security_runtime.scan_attempt import ScanAttemptStore


def test_fix_verification_fixture_separates_project_and_private_state(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / 'scripts/fix_verify_acceptance.py'
    monkeypatch.syspath_prepend(str(script.parent))
    root, store = runpy.run_path(str(script))['acceptance_workspace'](tmp_path)
    assert root == tmp_path / 'project' and root.is_dir()
    assert store.path == tmp_path / 'state/scans.db'
    attempts = ScanAttemptStore(HookStateStore(store.path.parent / 'hooks'), root)
    assert not attempts.private_parent.resolve().is_relative_to(root)


@pytest.mark.parametrize('unsupported', [False, True])
def test_tls_fixture_impact_reads_complete_merged_windows_before_submission(tmp_path, unsupported):
    script = Path(__file__).resolve().parents[1] / 'scripts/tls_impact_fixture.py'
    assess = runpy.run_path(str(script))['assess_tls_fixture']
    source = 'class Fixture { HostnameVerifier verifier = (host, session) -> true; }\n'
    (tmp_path / 'Fixture.java').write_text(source * 101, encoding='utf-8')
    waiting = dict(next_action=dict(tool='prepare_repair_impact', arguments=dict(
        source=dict(kind='SCANNER_TASK_GROUP', task_ref='synthetic-task'),
        proposal=dict(changes=[dict(file_path='Fixture.java')]))))
    calls, submitted = [], []

    async def call(name, arguments):
        calls.append((name, arguments))
        if name == 'prepare_repair_impact':
            return dict(assessment_ref='synthetic-impact', required_windows=[dict(
                file_path='Other.java' if unsupported else 'Fixture.java', start_line=1, end_line=101)],
                page=dict(next_offset=1))
        if name == 'get_repair_impact':
            return dict(required_windows=[dict(file_path='Fixture.java', start_line=100, end_line=100)],
                page=dict(next_offset=None))
        if name == 'read_repair_impact_context':
            start, end = arguments['start_line'], arguments['end_line']
            assert end - start < 80
            return dict(start_line=start, end_line=end, numbered_lines=['Known fixture'],
                evidence_ref='synthetic-evidence-' + str(start))
        assert name == 'submit_repair_impact'
        submitted.append(arguments)
        return dict(gate='READY_FOR_EXISTING_AUTH', repair_authorized=False)

    if unsupported:
        with pytest.raises(AssertionError):
            asyncio.run(assess(call, waiting, tmp_path, {'Fixture.java': source * 101}))
        assert not submitted
    else:
        assert asyncio.run(assess(call, waiting, tmp_path, {'Fixture.java': source * 101})) == 'synthetic-impact'
        reads = [arguments for name, arguments in calls if name == 'read_repair_impact_context']
        assert [(read['start_line'], read['end_line']) for read in reads] == [(1, 80), (81, 101)]
        assert submitted[0]['impacts'][0]['evidence_refs'] == ['synthetic-evidence-1', 'synthetic-evidence-81']
        assert (tmp_path / 'Fixture.java').read_text() == source * 101
