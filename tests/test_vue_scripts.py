"""Vue projections must not turn non-script text into executable scan input."""
import pytest

from security_runtime.vue_scripts import (
    MAX_SOURCE_BYTES, MAX_TAGS, MAX_TEMPLATE_DEPTH,
    extract_vue_scripts, read_vue_scripts,
)


def extract(text):
    return extract_vue_scripts(text.encode('utf-8'))


def test_js_and_setup_blocks_are_isolated_and_keep_original_byte_positions():
    source = ('<!-- 中文注释 -->\r\n<template><p>值</p></template>\r\n'
              '<script>\r\nconst input = location.hash;\r\n</script>\r\n'
              '<script setup>\r\neval(input);\r\n</script>\r\n').encode('utf-8')
    result = extract_vue_scripts(source)
    assert result.complete and result.has_template
    assert len(result.scripts) == 2
    ordinary, setup = result.scripts
    assert not ordinary.setup and setup.setup
    for block in result.scripts:
        assert block.language == 'javascript' and block.suffix == '.js'
        assert len(block.shadow_bytes) == len(source)
        assert block.shadow_bytes[block.content_start:block.content_end] == source[block.content_start:block.content_end]
        assert [i for i, byte in enumerate(block.shadow_bytes) if byte in (10, 13)] == [i for i, byte in enumerate(source) if byte in (10, 13)]
        assert block.contains_offset(block.content_start)
        assert not block.contains_offset(block.content_end)
    assert b'eval' not in ordinary.shadow_bytes
    assert b'location.hash' not in setup.shadow_bytes
    assert setup.shadow_bytes.index(b'eval') == source.index(b'eval')


@pytest.mark.parametrize('attributes', ["setup lang='ts'", 'lang=ts setup', 'lang="typescript" setup="yes"', 'lang="t&#115;" setup'])
def test_typescript_attributes(attributes):
    result = extract(f'<script {attributes}>const value: string = "x";</script>')
    assert result.complete
    block, = result.scripts
    assert block.language == 'typescript' and block.suffix == '.ts' and block.setup


def test_nested_templates_comments_attributes_and_interpolations_cannot_create_scripts():
    result = extract('''<!-- <script>danger(1)</script> -->
<template title="</template><script>danger(2)</script>">
  <template v-if="x"><p>{{ "</template><script>danger(3)</script>" }}</p></template>
  <!-- </template><script>danger(4)</script> -->
  <script>danger(5); const tag = "</template>";</script>
  <textarea><script>danger(6)</script></textarea>
  <style>.x { content: "</template><script>danger(7)</script>" }</style>
</template>
<style>.x { content: "<script>danger(8)</script>" }</style>
<docs><script>danger(9)</script></docs>
<script setup>safe();</script>''')
    assert result.complete
    block, = result.scripts
    assert b'safe();' in block.shadow_bytes
    assert b'danger' not in block.shadow_bytes


def test_script_raw_text_ends_at_html_closing_tag_even_inside_javascript_string():
    result = extract('<script>const text = "</script>"; eval(input);</script>')
    assert not result.complete and not result.scripts
    assert result.issues == ('MALFORMED_SFC',)


def test_close_prefix_is_not_a_script_end_and_attributes_can_contain_angle_brackets():
    result = extract('<script data-note="a > b">const text = "</scriptx>";</script>')
    assert result.complete
    assert b'</scriptx>' in result.scripts[0].shadow_bytes


@pytest.mark.parametrize('unsupported,reason', [
    ('src="./outside.js"', 'EXTERNAL_SCRIPT'),
    ('src="https://example.invalid/a.js"', 'EXTERNAL_SCRIPT'),
    ('lang="coffee"', 'UNSUPPORTED_SCRIPT_LANGUAGE'),
    ('lang="tsx"', 'UNSUPPORTED_SCRIPT_LANGUAGE'),
    ('type="application/ld+json"', 'UNSUPPORTED_SCRIPT_TYPE'),
    (':lang="chosen"', 'UNSUPPORTED_SCRIPT_ATTRIBUTES'),
])
def test_unsupported_script_is_reported_without_losing_separate_supported_block(unsupported, reason):
    result = extract(f'<script {unsupported}>unsupported();</script><script setup>supported();</script>')
    assert not result.complete and result.issues == (reason,)
    block, = result.scripts
    assert b'supported();' in block.shadow_bytes and b'unsupported' not in block.shadow_bytes


@pytest.mark.parametrize('source,reason', [
    ('<script>first()</script><script>second()</script>', 'DUPLICATE_SCRIPT'),
    ('<script setup>first()</script><script setup>second()</script>', 'DUPLICATE_SCRIPT'),
    ('<template></template><template></template><script>x()</script>', 'DUPLICATE_TEMPLATE'),
    ('<script lang="ts" lang="js">x()</script>', 'DUPLICATE_SFC_ATTRIBUTE'),
    ('<script>x()</script><script setup lang="ts">y()</script>', 'SCRIPT_LANGUAGE_MISMATCH'),
    ('<script>x()', 'MALFORMED_SFC'),
    ('<template><template></template><script>x()</script>', 'MALFORMED_SFC'),
    ('<template><div></template><script>x()</script>', 'MALFORMED_SFC'),
    ('<template><div></p></template><script>x()</script>', 'MALFORMED_SFC'),
    ('<!-- unfinished <script>x()</script>', 'MALFORMED_SFC'),
    ('<script title="unfinished>x()</script>', 'MALFORMED_SFC'),
    ('</template><script>x()</script>', 'MALFORMED_SFC'),
    ('<script>x()</script junk>', 'MALFORMED_SFC'),
    ('<Script>notScript()</Script><script setup>realScript()</script>', 'UNSUPPORTED_SFC_MARKUP'),
])
def test_ambiguous_or_damaged_sfc_discards_all_projections(source, reason):
    result = extract(source)
    assert not result.scripts and not result.complete and reason in result.issues


def test_external_and_preprocessed_templates_are_ignored_without_loading_them():
    result = extract('<template lang="pug">p <script>notJS()</script></template><script>yesJS()</script>')
    assert result.complete and result.has_template
    assert b'notJS' not in result.scripts[0].shadow_bytes
    external = extract('<template src="https://example.invalid/view"/><script>yesJS()</script>')
    assert external.complete and external.has_template


def test_bom_unicode_crlf_and_same_line_prefix_preserve_byte_column_and_offset():
    source = '\ufeff<template>中文</template><script>const x = "é"; eval(x);</script>\r\n'.encode('utf-8')
    result = extract_vue_scripts(source)
    assert result.complete
    shadow = result.scripts[0].shadow_bytes
    for token in (b'const', b'eval', 'é'.encode('utf-8')):
        assert shadow.index(token) == source.index(token)
    assert shadow.endswith(b'\r\n')
    shadow.decode('utf-8')


def test_empty_script_and_template_only_are_not_fabricated_code():
    assert extract('<template><p>Only markup</p></template>').scripts == ()
    result = extract('<script/>')
    assert result.complete and len(result.scripts) == 1
    assert result.scripts[0].content_start == result.scripts[0].content_end


def test_html_void_tags_and_self_closing_components_are_accepted():
    result = extract('<template><div><input><br><img src="x"><Widget/></div></template><script>x()</script>')
    assert result.complete and len(result.scripts) == 1


def test_invalid_encoding_and_bounded_resources_fail_closed(tmp_path):
    assert extract_vue_scripts(b'<script>\xff</script>').issues == ('SFC_INVALID_UTF8',)
    assert extract_vue_scripts(b'<script>\x00</script>').issues == ('MALFORMED_SFC',)
    oversized = b' ' * (MAX_SOURCE_BYTES + 1)
    assert extract_vue_scripts(oversized).issues == ('SFC_SIZE_LIMIT',)
    path = tmp_path / 'large.vue'
    path.write_bytes(oversized)
    assert read_vue_scripts(path).issues == ('SFC_SIZE_LIMIT',)
    assert read_vue_scripts(tmp_path / 'missing.vue').issues == ('SFC_READ_ERROR',)
    assert extract('<template>' * (MAX_TEMPLATE_DEPTH + 1)).issues == ('SFC_NESTING_LIMIT',)
    assert extract('<template>' + '<span/>' * MAX_TAGS + '</template>').issues == ('SFC_TAG_LIMIT',)


def test_reader_preserves_bytes_without_universal_newline_conversion(tmp_path):
    path = tmp_path / 'sample.vue'
    source = b'<script>\r\nconst value = 1;\r\n</script>\r\n'
    path.write_bytes(source)
    result = read_vue_scripts(path)
    assert result.complete and result.scripts[0].shadow_bytes.count(b'\r\n') == 3
