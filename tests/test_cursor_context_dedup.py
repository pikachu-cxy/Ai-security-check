"""Cursor automatic Hook regressions: context cost and cross-path edit dedup.

Both bugs were found by the three-host compatibility audit (stage 3):

* A full ~1.5k-character ``session_context()`` was re-injected on *every*
  ``postToolUse``, including read-only tools.
* ``postToolUse`` and ``afterFileEdit`` / ``afterShellExecution`` are two
  independent Hook deliveries for one edit. They used unrelated replay
  identities, so the same edit was recorded twice, ``dirty_seq`` advanced
  twice and an imprecise post-tool scope could widen a precise file record.

These tests drive ``handle_cursor_event(automatic=True)`` with the real
installed event shapes and inspect the real ``DevelopmentCheckService`` store.
"""
import re

import pytest

from security_runtime.cursor_hook import CursorBindings, handle_cursor_event
from security_runtime.development_check import DevelopmentCheckService
from security_runtime.recent_hooks import RecentHookStore
from security_runtime.tasks.ownership import session_owner, verify_session_ref
from test_cursor_automatic import ingress, tool
from test_cursor_host_adapter import payload
from test_hook_runtime import repo, coordinator, FakeRuntime


FULL_MARKER = '安全任务会话路由'
TOKEN = re.compile(r'sh1-[a-f0-9]{32}')


def audit_core(tmp_path):
    return coordinator(tmp_path, FakeRuntime(), task_audit_mode=True)


def post(repo, tmp_path, core, *, name='Write', tool_input=None, generation=None, **fields):
    values = dict(tool_name=name, tool_input=tool_input if tool_input is not None
                  else {'file_path': str(repo / 'A.java')}, tool_use_id='opaque')
    if generation is not None:
        values['generation_id'] = generation
    values.update(fields)
    return ingress(repo, tmp_path, core, 'postToolUse', **values)


def edit(repo, tmp_path, core, *, file='A.java', **fields):
    return ingress(repo, tmp_path, core, 'afterFileEdit', file_path=str(repo / file), **fields)


def saved_check(core, repo, ref):
    service = DevelopmentCheckService(None, core.store,
        owner=session_owner('cursor', 'private-cursor-conversation'))
    return service.get(repo, ref)


# --- Fix A: repeated full routing context -----------------------------------

def test_full_routing_context_is_injected_at_most_once_per_generation(repo, tmp_path):
    core = audit_core(tmp_path)
    tool(repo, tmp_path, core, 'Write', file_path=str(repo / 'A.java'))
    contexts = [post(repo, tmp_path, core)[0].get('additional_context', '') for _ in range(4)]
    full = [item for item in contexts if FULL_MARKER in item]
    assert len(full) == 1, 'full routing text must not be repeated for every tool use'
    assert all(len(item) < 240 for item in contexts if FULL_MARKER not in item)
    tokens = {TOKEN.search(item).group() for item in contexts}
    assert len(tokens) == 1
    assert verify_session_ref(core.store, repo, tokens.pop()) == session_owner(
        'cursor', 'private-cursor-conversation')
    assert not core.runtime.calls


@pytest.mark.parametrize('name,inputs', [('Read', {}), ('Shell', {'command': 'git status'})])
def test_read_only_post_tool_never_carries_full_routing_context(repo, tmp_path, name, inputs):
    core = audit_core(tmp_path)
    tool(repo, tmp_path, core, name, **inputs)
    output, result = post(repo, tmp_path, core, name=name, tool_input=inputs)
    context = output.get('additional_context', '')
    assert FULL_MARKER not in context
    assert len(context) < 240
    token = TOKEN.search(context)
    assert token and verify_session_ref(core.store, repo, token.group())
    assert not result['scanner_run'] and not core.runtime.calls


def test_new_generation_can_recover_the_full_context_once(repo, tmp_path):
    core = audit_core(tmp_path)
    tool(repo, tmp_path, core, 'Write', file_path=str(repo / 'A.java'))
    first = post(repo, tmp_path, core)[0]['additional_context']
    assert FULL_MARKER in first
    tool(repo, tmp_path, core, 'Write', generation='second-generation',
         file_path=str(repo / 'A.java'))
    second = post(repo, tmp_path, core, generation='second-generation')[0]['additional_context']
    third = post(repo, tmp_path, core, generation='second-generation')[0]['additional_context']
    assert FULL_MARKER in second and FULL_MARKER not in third
    assert TOKEN.search(second).group() == TOKEN.search(first).group()


def test_session_start_still_delivers_the_full_routing_context(repo, tmp_path):
    core = audit_core(tmp_path)
    output, _ = ingress(repo, tmp_path, core, 'sessionStart', generation_id='')
    assert FULL_MARKER in output['additional_context']
    assert verify_session_ref(core.store, repo, TOKEN.search(
        output['additional_context']).group())


# --- Fix B: one edit seen through two Hook paths ----------------------------

@pytest.mark.parametrize('order', [('afterFileEdit', 'postToolUse'),
                                   ('postToolUse', 'afterFileEdit')])
def test_one_edit_seen_by_two_hooks_is_recorded_once(repo, tmp_path, order):
    core = audit_core(tmp_path)
    tool(repo, tmp_path, core, 'Write', file_path=str(repo / 'A.java'))
    (repo / 'A.java').write_text('edited bytes')
    refs = []
    for event in order:
        result = (edit(repo, tmp_path, core) if event == 'afterFileEdit'
                  else post(repo, tmp_path, core))[1]
        refs.append(result.get('development_check_ref'))
    assert refs[0] and refs[0] == refs[1]
    saved = saved_check(core, repo, refs[0])
    assert saved['dirty_seq'] == 1, 'the same edit must not advance the batch twice'
    assert saved['scope']['paths'] == ['A.java']
    assert saved['scope']['scope_unknown'] is False
    assert not core.runtime.calls


def test_imprecise_post_tool_does_not_widen_a_precise_edit_record(repo, tmp_path):
    core = audit_core(tmp_path)
    tool(repo, tmp_path, core, 'Write', file_path=str(repo / 'A.java'))
    (repo / 'A.java').write_text('edited bytes')
    _, precise = edit(repo, tmp_path, core)
    post(repo, tmp_path, core, tool_input={})
    saved = saved_check(core, repo, precise['development_check_ref'])
    assert saved['dirty_seq'] == 1
    assert saved['scope']['paths'] == ['A.java']
    assert saved['scope']['scope_unknown'] is False


def test_distinct_files_in_one_generation_are_not_over_deduplicated(repo, tmp_path):
    core = audit_core(tmp_path)
    (repo / 'B.java').write_text('pre-existing B')
    tool(repo, tmp_path, core, 'Write', file_path=str(repo / 'A.java'))
    (repo / 'A.java').write_text('edited A')
    (repo / 'B.java').write_text('edited B')
    first = edit(repo, tmp_path, core)[1]
    post(repo, tmp_path, core)
    second = edit(repo, tmp_path, core, file='B.java')[1]
    post(repo, tmp_path, core, tool_input={'file_path': str(repo / 'B.java')})
    assert first['development_check_ref'] == second['development_check_ref']
    saved = saved_check(core, repo, first['development_check_ref'])
    assert saved['dirty_seq'] == 2
    assert sorted(saved['scope']['paths']) == ['A.java', 'B.java']


def test_a_new_generation_records_a_new_edit_after_a_previous_batch(repo, tmp_path):
    core = audit_core(tmp_path)
    tool(repo, tmp_path, core, 'Write', file_path=str(repo / 'A.java'))
    (repo / 'A.java').write_text('edit in generation one')
    first = edit(repo, tmp_path, core)[1]
    post(repo, tmp_path, core)
    assert saved_check(core, repo, first['development_check_ref'])['dirty_seq'] == 1

    tool(repo, tmp_path, core, 'Write', generation='second-generation',
         file_path=str(repo / 'A.java'))
    (repo / 'A.java').write_text('edit in generation two')
    second = edit(repo, tmp_path, core, generation_id='second-generation')[1]
    post(repo, tmp_path, core, generation='second-generation')
    assert second['development_check_ref'] == first['development_check_ref']
    assert saved_check(core, repo, first['development_check_ref'])['dirty_seq'] == 2


@pytest.mark.parametrize('value', [None, {}, 123, 'x' * 300])
def test_non_string_tool_use_id_no_longer_breaks_edit_recording(repo, tmp_path, value):
    core = audit_core(tmp_path)
    tool(repo, tmp_path, core, 'Write', file_path=str(repo / 'A.java'))
    (repo / 'A.java').write_text('edited bytes')
    output, result = handle_cursor_event(
        payload(repo, 'postToolUse', tool_name='Write', tool_use_id=value,
                tool_input={'file_path': str(repo / 'A.java')}),
        automatic=True, core=core, bindings=CursorBindings(tmp_path / 'bindings'),
        project_dir=str(repo), store=RecentHookStore(tmp_path / 'recent.db'))
    assert result.get('development_check_ref'), result
    assert result['status'] != 'INCONCLUSIVE'
    assert not core.runtime.calls
