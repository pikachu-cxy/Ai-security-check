"""Current artifacts and explicit loaded Runtime identity are admission checks."""
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

script=Path(__file__).parents[1]/'tools/compare_controlled_risk.py'
spec=importlib.util.spec_from_file_location('controlled_compare',script)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


def test_parse_failure_exits_nonzero_without_creating_success(tmp_path):
    before=tmp_path/'bad.json'; before.write_text('{invalid')
    after=tmp_path/'after.json'; after.write_text('{}')
    output=tmp_path/'new.json'
    result=subprocess.run([sys.executable,str(script),str(before),str(after),'--output',str(output)],capture_output=True,timeout=10)
    assert result.returncode != 0 and not output.exists()


def test_existing_success_cannot_be_reused(tmp_path):
    before=tmp_path/'before.json'; before.write_text('{}')
    after=tmp_path/'after.json'; after.write_text('{}')
    output=tmp_path/'old.json'; output.write_text('previous success')
    result=subprocess.run([sys.executable,str(script),str(before),str(after),'--output',str(output)],capture_output=True,timeout=10)
    assert result.returncode != 0
    assert output.read_text() == 'previous success'


def test_running_or_failed_invocation_is_not_success():
    with pytest.raises(ValueError,match='did not succeed'):
        module.compare({'status':'RUNNING'},{'status':'SUCCESS'})


def test_loaded_source_must_match_requested_identity():
    row=dict(status='SUCCESS',run_id='new',finished_at_utc='now',
             runtime_identity=dict(version='wrong',expected_version='0.3.4',task_source_sha256='a',expected_task_source_sha256='a'))
    with pytest.raises(ValueError,match='Loaded Runtime'):
        module.compare(row,row)
