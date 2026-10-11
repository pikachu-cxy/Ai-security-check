"""Real legacy bootstrap migration; all files and processes are isolated."""
from pathlib import Path
import argparse
import json
import subprocess
import tempfile
import time

from security_runtime.delivery import StableDelivery, EXE
from security_runtime.trial import TrialProfile, isolated_environment
from personal_install_acceptance import receipt
from security_runtime.hook_state import atomic_bytes


def main(old, new, output):
    with tempfile.TemporaryDirectory(prefix='install-migration-') as temporary:
        root = Path(temporary).resolve() / 'profile with spaces'
        TrialProfile(root).create()
        env = dict(isolated_environment(root), SECURITY_RUNTIME_GLOBAL='1',
            SECURITY_RUNTIME_WORKSPACE='', SECURITY_RUNTIME_INTEGRATION='codex')
        program = root / 'program'
        delivery = StableDelivery(program, probe=lambda _: {'status': 'OK'})
        initial = delivery.activate(old)
        with subprocess.Popen([initial['launcher'], 'mcp'], env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            # Wait only for this verified legacy process to reach its child.
            time.sleep(4)
            assert process.poll() is None
            updated, feedback = receipt([str(new / EXE), 'install', 'codex', '--root', str(program), '--json'], root, env)
            assert updated['installation']['local_files_ready']
            assert Path(updated['delivery']['launcher']).parent.name == 'launcher-v2'
            assert updated['cleanup']['legacy_bootstrap'] == 'DEFERRED_IN_USE'
            assert initial['active_build'] in updated['cleanup']['deferred_builds']
            process.stdin.close()
            process.wait(timeout=20)
        ready, _ = receipt([updated['delivery']['launcher'], 'install', 'codex', '--json'], root, env)
        assert ready['installation']['local_files_ready']
        assert ready['cleanup']['legacy_bootstrap'] == 'REMOVED'
        assert not (program / 'launcher').exists()
        assert not delivery.slot(initial['active_build']).exists()
        result = {'status': 'PASS', 'legacy_process_preserved': True,
            'new_fixed_launcher': 'launcher-v2', 'old_slot_and_bootstrap_removed_after_exit': True,
            'installation': feedback, 'real_global_installation_modified': False}
    atomic_bytes(output, json.dumps(result, ensure_ascii=False, indent=2).encode())
    print(json.dumps(result, ensure_ascii=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--old', type=Path, required=True)
    parser.add_argument('--new', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    main(args.old.absolute(), args.new.absolute(), args.output.absolute())
