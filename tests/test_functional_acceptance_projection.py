"""A usable sandbox must not create mount directories in the source fixture."""
from pathlib import Path

import pytest


@pytest.mark.parametrize('exit_code', [0, 1])
def test_host_driver_projects_source_and_keeps_failed_step(tmp_path, monkeypatch, exit_code):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts'))
    from functional_acceptance import execute_host_plan
    root = tmp_path / 'source'
    root.mkdir()
    (root / 'pom.xml').write_bytes(b'synthetic unchanged fixture')
    working = tmp_path / 'runtime-projection'
    working.mkdir()
    (working / 'pom.xml').write_bytes((root / 'pom.xml').read_bytes())
    projections = []

    class Sandbox:
        def availability(self): return None
        def run(self, projection, step, *, timeout):
            assert projection != root and not projection.is_relative_to(root)
            assert (projection / 'pom.xml').read_bytes() == (root / 'pom.xml').read_bytes()
            projections.append(projection)
            (projection / 'target').mkdir(exist_ok=True)
            return dict(reason=None, output=b'', exit_code=exit_code, duration_ms=1)

    step = dict(command_id='fixture', working_directory=str(working), provider='maven',
                argv=['synthetic-maven'], timeout_seconds=1)
    report = execute_host_plan(dict(plan_digest='synthetic', steps=[step, step], temporary_projection=True), root, Sandbox())
    assert len(report['steps']) == (2 if exit_code == 0 else 1)
    assert report['steps'][0]['exit_code'] == exit_code
    assert report['steps'][0]['execution_status'] == 'COMPLETED'
    assert sorted(p.name for p in root.iterdir()) == ['pom.xml']
    assert (root / 'pom.xml').read_bytes() == b'synthetic unchanged fixture'
    # Runtime retains its projection until it validates the host report.
    assert projections and all(p == working for p in projections)
    assert (working / 'target').is_dir()


@pytest.mark.parametrize('child', [False, True])
def test_host_driver_rejects_execution_in_live_source(tmp_path, monkeypatch, child):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'scripts'))
    from functional_acceptance import execute_host_plan
    root = tmp_path / 'source'
    root.mkdir()
    working = root / 'nested' if child else root
    working.mkdir(exist_ok=True)
    step = dict(working_directory=str(working))
    with pytest.raises(AssertionError):
        execute_host_plan(dict(plan_digest='fixture', steps=[step], temporary_projection=True), root, None)
