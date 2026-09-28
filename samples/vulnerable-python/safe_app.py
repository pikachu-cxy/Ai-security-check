import subprocess


def export_report(name: str) -> int:
    if not name.isidentifier():
        raise ValueError("Invalid report name")
    return subprocess.run(["tar", "-czf", name + ".tar.gz", "reports"], check=False).returncode
