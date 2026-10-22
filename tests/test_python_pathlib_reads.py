"""Pathlib stays in the existing experimental / cross-file scope.

Do not promote local reads until path component replacement and absolute tail
semantics have precise models. Targets below are parsed, never imported or run.
"""
import pytest

from test_bounded_dataflow import scan


@pytest.mark.parametrize('expression', [
    'Path("/srv/files") / value',
    'Path("/srv/files", value)',
    'Path("/srv/files").joinpath(value)',
    '(Path("/srv/files") / value).resolve()',
    'Path("/srv/public/fixed.txt").with_name(value).with_name("fixed.txt")',
    'Path("/srv/public/fixed.txt").with_suffix(value)',
    'Path(str(Path("/srv/public/fixed.txt").with_name(value).with_name("fixed.txt")) + "")',
    'Path(value, "//server/share/fixed.txt")',
    'Path(value) / "//server/share/fixed.txt"',
    'Path(value).joinpath("//server/share/fixed.txt")',
])
@pytest.mark.parametrize('method', ['read_text', 'read_bytes'])
def test_local_pathlib_reads_remain_experimental(tmp_path, expression, method):
    text = """from pathlib import Path
from flask import request
def route():
    value=request.args.get('name')
    path=%s
    return path.%s()
""" % (expression, method)
    default, run = scan(tmp_path, {'app.py': text})
    assert run.status == 'SUCCESS' and not default
    assert run.rule_coverage['python_path_scope'] == 'RESOLVED_CROSS_FILE_CALLS_OR_IO_CODECS_OPEN'
    assert run.rule_coverage['verification_scope_complete'] is False
    experimental, _ = scan(tmp_path, {'app.py': text}, experimental=True)
    assert len(experimental) == 1
    assert {step['kind'] for step in experimental[0].technical_details['dataflow_trace']} == {'SOURCE', 'SINK'}


def test_component_replacement_controls_have_fixed_paths():
    from pathlib import PurePosixPath, PureWindowsPath
    for path_type, base in (
        (PurePosixPath, '/srv/public/fixed.txt'),
        (PureWindowsPath, 'C:/srv/public/fixed.txt'),
    ):
        fixed = path_type(base)
        rewritten = fixed.with_name('other.txt').with_name('fixed.txt')
        assert rewritten == fixed
        assert path_type(str(rewritten) + '') == fixed
        with pytest.raises(ValueError):
            fixed.with_name('../other.txt')
        for value in ('input.txt', '../input.txt', '/other/input.txt'):
            tail = '//server/share/fixed.txt'
            assert path_type(value, tail) == path_type(tail)
            assert path_type(value) / tail == path_type(tail)
            assert path_type(value).joinpath(tail) == path_type(tail)
