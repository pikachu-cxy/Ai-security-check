"""Explicit immutable-input port for test doubles, never a production fallback."""
from functools import wraps

from security_runtime.progress import progress_context
from security_runtime.scan_input import capture_scan_input


def captured_scan(method):
    """Exercise the same input_ready/after_scan lifetime as SecurityRuntime."""
    @wraps(method)
    def scan(self, root, mode, **kwargs):
        execution = kwargs.get('execution')
        if execution is None:
            return method(self, root, mode, **kwargs)
        request = kwargs['request']
        with progress_context(execution), capture_scan_input(request,
                private_parent=execution.private_parent, on_created=execution.input_created,
                on_removed=execution.input_removed) as view:
            execution.input_ready(view)
            result = method(self, root, mode, **kwargs)
            view.assert_intact()
            execution.after_scan(view, result)
            return result
    return scan
