"""Console entry for the standalone Runtime."""

import sys


if __name__ == "__main__":
    if sys.argv[1:3] == ['install', 'codex']:
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
                from security_runtime.delivery import cleanup_after_reconnect
                cleanup_after_reconnect()
                from security_runtime.cli import main
                code = main()
            else:
                code = dispatched
    raise SystemExit(code)
