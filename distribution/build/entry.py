"""Console entry for the standalone Runtime."""

import sys


if __name__ == "__main__":
    if sys.argv[1:] == ['runtime-info', '--identity', '--json']:
        # The native launcher already verified every package byte. Return the
        # running module version and build identity without loading scanners or
        # parsing the rule catalog again merely to compare installation IDs.
        import json
        from security_runtime.build_identity import build_identity
        from security_runtime._version import __version__
        identity = build_identity()
        identity['version'] = __version__
        print(json.dumps({'build_identity': identity, 'component_checks': False}))
        code = 0
    elif sys.argv[1:3] == ['install', 'codex']:
        # Show feedback before importing the CLI or validating a launcher slot.
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, 'reconfigure'):
                stream.reconfigure(encoding='utf-8')
        from security_runtime.install_progress import InstallationProgress
        with InstallationProgress() as progress:
            from security_runtime.delivery import dispatch, verification_session
            with verification_session():
                dispatched = dispatch(progress=progress)
                if dispatched is None:
                    from security_runtime.cli import main
                    code = main(installation_progress=progress)
                else:
                    code = dispatched
    else:
        from security_runtime.delivery import dispatch, verification_session
        with verification_session():
            dispatched = dispatch()
            if dispatched is None:
                # Historical-slot cleanup is explicit maintenance. It must not
                # delay the first host connection after a successful install.
                from security_runtime.cli import main
                code = main()
            else:
                code = dispatched
    raise SystemExit(code)
