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
        command = Path(runtime['command'])
        probe_runtime = runtime
        # Do not cache unknown development launch layouts or failed probes.
        identity = None
        if runtime.get('kind') == 'FROZEN':
            try:
                from .delivery import launcher_metadata
                metadata, inventory = launcher_metadata(command.parent, _with_inventory=True)
                identity = (metadata['build_id'], inventory)
                if command.parent.name in {'launcher', 'launcher-v2'}:
                    from .delivery import EXE, StableDelivery, package_metadata
                    delivery = StableDelivery(command.parent.parent)
                    pointer = delivery.pointer()
                    active = delivery.slot(pointer['active'])
                    verified, active_inventory = package_metadata(active, _with_inventory=True)
                    identity = (*identity, pointer, verified['build_id'], active_inventory)
                    if (command.name == EXE and not runtime.get('prefix')
                            and pointer.get('launcher', 'launcher') == command.parent.name
                            and verified['build_id'] == pointer['active']):
                        # Both the launcher and active slot were verified above.
                        # Only this install probe skips the forwarding process;
                        # the host configuration retains its stable launcher.
                        probe_runtime = {**runtime, 'command': str(active / EXE)}
            except (ValueError, OSError):
                return original(runtime, home, environment)
        else:
            # Explicit DEV/testing injection: still bounded to this transaction.
            identity = str(command)
        key = hashlib.sha256(json.dumps([runtime, str(home), environment, identity],
            sort_keys=True, default=str).encode()).hexdigest()
        if key not in cache:
            result = original(probe_runtime, home, environment)
            if result.get('status') == 'OK':
                cache[key] = deepcopy(result)
            return result
        return deepcopy(cache[key])
    integration.probe = check
    try:
        yield
    finally:
        integration.probe = original
