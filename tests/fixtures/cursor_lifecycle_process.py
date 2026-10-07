"""Independent command processes with pipe-controlled ordering, never a benchmark."""
import json
import sys
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from test_hook_runtime import FakeRuntime
from test_cursor_host_adapter import payload
from security_runtime.cursor_hook import CursorBindings, handle_cursor_event
from security_runtime.hook_runtime import HookCoordinator, capture_snapshot
from security_runtime.hook_state import HookStateStore
from security_runtime.recent_hooks import RecentHookStore

root, directory, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]

class OrderedStore(HookStateStore):
    def save(self, path, value):
        if mode == 'publish':
            print('SNAPSHOT_READY', flush=True)
            assert sys.stdin.readline().strip() == 'release'
        super().save(path, value)

    def pending_activity(self, *args, **kwargs):
        value = super().pending_activity(*args, **kwargs)
        if kwargs.get('mark'):
            print('ACTIVITY_MARKED', flush=True)
        return value

store = OrderedStore(directory/'hooks')
if mode == 'hold':
    with store.lock(root) as acquired:
        assert acquired
        print('LOCKED', flush=True)
        assert sys.stdin.readline().strip() == 'release'
    raise SystemExit(0)

first = True
def capture(root, key):
    global first
    if mode == 'capture' and first:
        first = False
        print('CAPTURE_PENDING', flush=True)
        assert sys.stdin.readline().strip() == 'release'
    return capture_snapshot(root, key)

runtime = FakeRuntime()
core = HookCoordinator(runtime, store, snapshot_capture=capture)
event = 'sessionStart' if mode in {'publish','capture'} else 'afterFileEdit'
_, result = handle_cursor_event(payload(root, event), core=core,
    bindings=CursorBindings(directory/'bindings'), project_dir=str(root),
    store=RecentHookStore(directory/'recent.db'))
print(json.dumps(dict(result=result, scopes=runtime.calls)), flush=True)
