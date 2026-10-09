"""Console entry for the standalone Runtime."""

from security_runtime.cli import main


if __name__ == "__main__":
    from security_runtime.delivery import dispatch
    dispatched = dispatch()
    raise SystemExit(main() if dispatched is None else dispatched)
