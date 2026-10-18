"""Sanitized placeholders are complete values, never a redaction bypass."""
import pytest

from security_runtime.redactor import SecretRedactor


@pytest.mark.parametrize('marker', ['[REDACTED_LITERAL]', '[REDACTED_SECRET]', '[REDACTED_COMMENT]'])
@pytest.mark.parametrize('name', ['token', 'demoToken', 'api_key', 'dbPassword', 'secret'])
def test_complete_marker_assignment_is_preserved_and_idempotent(marker, name):
    source = f'{name} = {marker};'
    redactor = SecretRedactor()
    assert redactor.redact(source) == source
    assert redactor.redact(redactor.redact(source)) == source


@pytest.mark.parametrize('marker', ['[REDACTED_LITERAL]', '[REDACTED_SECRET]'])
@pytest.mark.parametrize('suffix', ['syntheticTail', ':syntheticTail', '=syntheticTail', '[syntheticTail]'])
def test_marker_followed_by_credential_text_is_still_hidden(marker, suffix):
    redactor = SecretRedactor()
    result = redactor.redact('demoToken=' + marker + suffix)
    assert 'syntheticTail' not in result
    assert redactor.redact(result) == result


@pytest.mark.parametrize('prefix', ['token=\n  ', 'api_key:\r\n  ', 'demoToken = ', 'dbPassword: "'])
def test_actual_credential_assignment_remains_redacted(prefix):
    source = prefix + 'syntheticPrivateValue321'
    result = SecretRedactor().redact(source)
    assert 'syntheticPrivateValue321' not in result
    assert SecretRedactor().redact(result) == result


def test_multiple_assignments_and_embedded_private_key_are_all_hidden():
    source = ('token=[REDACTED_LITERAL]; api_key=syntheticPrivateValue321\n'
              'secret=-----BEGIN PRIVATE KEY-----\nprivate-key-middle\n-----END PRIVATE KEY-----\n')
    result = SecretRedactor().redact(source)
    assert 'token=[REDACTED_LITERAL]' in result
    assert 'syntheticPrivateValue321' not in result and 'private-key-middle' not in result
    assert SecretRedactor().redact(result) == result
