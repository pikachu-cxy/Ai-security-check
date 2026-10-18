"""Retain only observable empty literals while keeping hidden values private."""
import pytest

from security_runtime.local_evidence import safe_source


@pytest.mark.parametrize('literal', ["''", '""', '``', "''''''", '""""""'])
@pytest.mark.parametrize('name', ['label', 'token', 'demoToken', 'api_key'])
def test_closed_empty_literal_is_visible_and_stable(literal, name):
    source = f'{name} = {literal};'
    assert safe_source(source) == [source]
    assert safe_source('\n'.join(safe_source(source))) == [source]


@pytest.mark.parametrize('literal', ["' '", '" "', '` `', "'''\n'''", '"""\n"""',
    "'", '"', '`', "'''", '"""', "'\\n'", '`value ${privateInput}`'])
def test_whitespace_escaped_interpolated_and_unterminated_literals_remain_hidden(literal):
    lines = safe_source('demoToken = ' + literal)
    assert '[REDACTED_LITERAL]' in '\n'.join(lines)
    assert literal not in lines
    assert 'privateInput' not in '\n'.join(lines)


@pytest.mark.parametrize('prefix', ["token=''; ", 'token=""; ', 'api_key=``; ', 'token=[REDACTED_LITERAL]; '])
def test_safe_value_does_not_skip_later_short_credential_on_same_line(prefix):
    # The redactor's generic eight-character minimum cannot hide this alone.
    result = safe_source(prefix + 'api_key=tiny;')
    assert result == [prefix + '[REDACTED_SECRET]']
    assert safe_source('\n'.join(result)) == result


@pytest.mark.parametrize('value', ['[REDACTED_LITERAL]syntheticTail', '[REDACTED_SECRET]syntheticTail',
    "'' + tiny", '"" + tiny', '`` + tiny'])
def test_safe_value_must_end_before_an_assignment_boundary(value):
    result = safe_source('token=' + value)
    assert result == ['[REDACTED_SECRET]']


def test_known_secret_ranges_still_override_empty_literals():
    assert safe_source("token='';", secret_ranges=[(1, 1)]) == ['[REDACTED_SECRET]']


def test_nonempty_literal_allowlist_does_not_expand():
    assert safe_source("label='GET'; token='short';") == [
        'label=[REDACTED_LITERAL]; token=[REDACTED_LITERAL];']


@pytest.mark.parametrize('path,comment', [('demo.py', '# cleared'), ('demo.ts', '// cleared'),
    ('demo.ts', '/* cleared */')])
def test_empty_assignment_with_trailing_comment_keeps_safe_empty_value(path, comment):
    assert safe_source("token = '' " + comment, source_path=path) == [
        "token = '' [REDACTED_COMMENT]"]


def test_comment_marker_suffix_cannot_bypass_short_credential_mask():
    assert safe_source("token='' [REDACTED_COMMENT]tiny") == ['[REDACTED_SECRET]']
