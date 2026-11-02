"""Usage monitoring is an explicit opt-in, independent of risk statistics."""
import os


def enabled():
    return os.environ.get('SECURITY_RUNTIME_USAGE_MONITOR_ENABLED') == '1'


def require_enabled():
    if not enabled():
        raise ValueError('MONITOR_DISABLED_BY_DEFAULT')
