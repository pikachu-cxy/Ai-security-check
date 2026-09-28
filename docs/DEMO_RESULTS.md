# Local demo results

Measured on Windows with Python 3.12.14 and a temporary Git repository copied from `samples/vulnerable-python`. The scanners were real local executables: Semgrep 1.166.0, Gitleaks 8.30.0, and Trivy 0.74.0. Trivy's vulnerability database was downloaded before the test and scans then used its local cache. Results are a single run, not a benchmark average.

| Mode | Duration | Findings | Scanner results |
| --- | ---: | ---: | --- |
| QUICK | 5,188 ms | 2 | Semgrep SUCCESS, Gitleaks SUCCESS, Trivy SKIPPED |
| FEATURE | 5,546 ms | 2 | Semgrep SUCCESS, Gitleaks SUCCESS, Trivy SKIPPED |
| RELEASE | 5,813 ms | 2 | Semgrep SUCCESS, Gitleaks SUCCESS, Trivy SUCCESS |

The two findings were a command injection in `app.py:8` and a synthetic GitHub token in `app.py:4`. RELEASE merged the secret reports from Gitleaks and Trivy into one finding. All three modes returned `BLOCKED`. QUICK scanned changed files and changed lines; Trivy did not run in QUICK.

The template `generate_fix` returned root cause, fix strategy, and coding agent prompt. Replacing the vulnerable file with `safe_app.py` made `verify` return `RESOLVED`. The installed pre-commit hook rejected the unsafe staged file and allowed the fixed version. The official MCP SDK client successfully called `scan_diff`, `get_findings`, `generate_fix`, and `verify` over stdio.

The installed `security-check scan --mode release --json` command was also run directly from `samples/vulnerable-python`: `COMPLETED`, `BLOCKED`, two findings, and SUCCESS from all three scanners.

The full suite passed: 10 tests. Tests include unit coverage plus real CLI, scanner, MCP, verify, and pre-commit flows. The wheel build included the packaged Semgrep rule file.

Limits: QUICK was slightly above the five second design target because Semgrep startup took about 4.6 seconds. Trivy requires a local database prepared before its first offline scan. The current Semgrep rule set targets a narrow, high risk command execution pattern and is not comprehensive SAST coverage. The default SQLite store is relative to the caller's working directory; CLI and MCP should run from the same project directory to share scan IDs.
