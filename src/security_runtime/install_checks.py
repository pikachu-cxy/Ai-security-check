"""Transaction-local capability reuse; configuration inspection always stays live."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path


@contextmanager
def single_capability_check(integration):
    original, cache = integration.probe, {}
    def check(runtime, home, environment):
        from .delivery import package_inventory
        command = Path(runtime['command'])
        # Do not cache unknown development launch layouts or failed probes.
        identity = None
        if runtime.get('kind') == 'FROZEN':
            try:
                from .delivery import launcher_metadata
                metadata = launcher_metadata(command.parent)
                identity = (metadata['build_id'], package_inventory(command.parent))
                if command.parent.name in {'launcher', 'launcher-v2'}:
                    from .delivery import StableDelivery, package_metadata
                    delivery = StableDelivery(command.parent.parent)
                    pointer = delivery.pointer()
                    active = delivery.slot(pointer['active'])
                    verified = package_metadata(active)
                    identity = (*identity, pointer, verified['build_id'], package_inventory(active))
            except (ValueError, OSError):
                return original(runtime, home, environment)
        else:
            # Explicit DEV/testing injection: still bounded to this transaction.
            identity = str(command)
        key = hashlib.sha256(json.dumps([runtime, str(home), environment, identity],
            sort_keys=True, default=str).encode()).hexdigest()
        if key not in cache:
            result = original(runtime, home, environment)
            if result.get('status') == 'OK':
                cache[key] = deepcopy(result)
            return result
        return deepcopy(cache[key])
    integration.probe = check
    try:
        yield
    finally:
        integration.probe = original
