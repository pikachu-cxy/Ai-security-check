"""Comment punctuation cannot erase later code or weaken source redaction."""
import hashlib
import json

import pytest

from security_runtime.local_evidence import LocalEvidenceService, legacy_safe_source as safe_source


@pytest.mark.parametrize('comment,path', [
    ("# SQLite's transaction is owned here", None),
    ("#owner's transaction is owned here", 'runtime.py'),
    ("#owner's transaction is owned here", 'runtime.pyi'),
    ("#owner's transaction is owned here", 'settings.toml'),
    ("#owner's transaction is owned here", 'settings.yaml'),
    ("// SQLite's transaction is owned here", 'Runtime.java'),
    ("// SQLite's transaction is owned here", 'runtime.js'),
    ("/* SQLite's transaction is owned here */", 'Runtime.java'),
    ("/* SQLite's transaction is owned here */", 'runtime.js'),
])
def test_apostrophe_in_comment_does_not_swallow_later_code(comment, path):
    source = comment + '\ndef preserve_control():\n    verify_control()\n    value = \'private literal\'\n'
    lines = safe_source(source, source_path=path)
    assert len(lines) == len(source.splitlines())
    assert lines[0] == '[REDACTED_COMMENT]'
    assert lines[1] == 'def preserve_control():'
    assert lines[2] == '    verify_control()'
    assert lines[3] == '    value = [REDACTED_LITERAL]'
    assert 'private literal' not in '\n'.join(lines)


def test_inline_comment_quotes_and_triple_delimiters_remain_inside_comment():
    source = 'value = 1 # owner\'s """quoted note\nverify_control()\nother = "private"\n'
    lines = safe_source(source, source_path='runtime.py')
    assert lines == ['value = 1 [REDACTED_COMMENT]', 'verify_control()', 'other = [REDACTED_LITERAL]']


def test_quoted_url_does_not_open_a_comment_or_disclose_literals():
    source = ('const url = "https://private.example.invalid/path";\n'
              'const result = client.fetch(url);\n'
              'const label = "private-label";\n')
    lines = safe_source(source, source_path='client.js')
    assert lines == ['const url = [REDACTED_LITERAL];',
        'const result = client.fetch(url);', 'const label = [REDACTED_LITERAL];']
    assert 'private.example' not in '\n'.join(lines)


def test_javascript_private_fields_are_not_hash_comments():
    source = 'class Client {\n  #owner = 1;\n  getOwner() { return this.#owner; }\n}\n'
    assert safe_source(source, source_path='client.js') == source.splitlines()
    assert safe_source(source) == source.splitlines()


@pytest.mark.parametrize('opening,closing', [('"', '"'), ("'", "'"), ('`', '`'),
    ('"""', '"""'), ("'''", "'''")])
@pytest.mark.parametrize('newline', ['\n', '\r\n', '\r'])
def test_multiline_literals_keep_every_line_and_hide_comment_like_secret(opening, closing, newline):
    source = 'value = ' + opening + newline + '# private-middle // private-data' + newline + closing
    lines = safe_source(source, source_path='runtime.py')
    assert len(lines) == len(source.splitlines()) == 3
    assert 'private-middle' not in '\n'.join(lines)
    assert 'private-data' not in '\n'.join(lines)
    assert lines[0] == 'value = [REDACTED_LITERAL]'
    assert lines[2] == '[REDACTED_LITERAL]'


@pytest.mark.parametrize('opening', ['"', "'", '`', '"""', "'''"])
def test_unterminated_multiline_literal_masks_to_eof(opening):
    source = 'value = ' + opening + '\nprivate-middle\n// private-tail'
    lines = safe_source(source, source_path='runtime.js')
    assert len(lines) == 3
    assert 'private-middle' not in '\n'.join(lines)
    assert 'private-tail' not in '\n'.join(lines)


def test_escaped_backtick_does_not_expose_template_tail():
    source = 'const value = `private-first\\`private-tail`;\nverify_control();\n'
    lines = safe_source(source, source_path='runtime.js')
    assert lines == ['const value = [REDACTED_LITERAL];', 'verify_control();']


@pytest.mark.parametrize('closed', [False, True])
def test_private_key_blocks_and_line_ranges_remain_fully_redacted(closed):
    source = '-----BEGIN PRIVATE KEY-----\nprivate-key-middle\nprivate-key-tail'
    if closed:
        source += '\n-----END PRIVATE KEY-----'
    lines = safe_source(source)
    assert len(lines) == len(source.splitlines())
    assert 'private-key' not in '\n'.join(lines)
    assert all(value == '[REDACTED_LITERAL]' for value in lines)
    assert safe_source('verify_control()\nprivate_value\nnext_control()', [(2, 2)]) == [
        'verify_control()', '[REDACTED_SECRET]', 'next_control()']


def test_public_crypto_literals_stay_visible_but_other_literals_and_credentials_do_not():
    source = ('MessageDigest.getInstance("MD5");\nSSLContext.getInstance("TLS");\n'
              'other("private-literal");\npassword = shortsecret\n')
    lines = safe_source(source, source_path='Runtime.java')
    assert lines[:2] == ['MessageDigest.getInstance("MD5");', 'SSLContext.getInstance("TLS");']
    assert lines[2] == 'other([REDACTED_LITERAL]);'
    assert 'shortsecret' not in '\n'.join(lines)


def test_comment_punctuation_cannot_drop_code_or_secrets_into_evidence_receipt(tmp_path):
    source = ("# owner's retained comparison\n"
              'def fetch_document():\n'
              '    verify_control()\n'
              '    password = "private-synthetic-literal"\n')
    path = tmp_path / 'client.py'
    path.write_text(source, encoding='utf-8')
    raw = path.read_bytes()
    finding = dict(id='fixture', file_path='client.py', line_start=3, line_end=3,
        category='authorization', technical_details=dict(evidence_locator=dict(
            file_sha256=hashlib.sha256(raw).hexdigest())))
    scan = dict(target_profile=dict(path=str(tmp_path)), findings=[finding])
    receipt = LocalEvidenceService(scan).detail(finding, context_lines=2)
    assert receipt['evidence_status'] == 'EXACT'
    assert receipt['original_evidence']['matched_code'] == '    verify_control()'
    assert receipt['original_evidence']['context_start_line'] == 1
    assert receipt['original_evidence']['context_end_line'] == 4
    assert 'private-synthetic-literal' not in json.dumps(receipt)
