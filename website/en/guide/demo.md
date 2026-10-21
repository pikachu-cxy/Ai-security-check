# Your first security demo

Use a small Python example to follow a finding through approval and fix verification. You need a [verified connection](./verify.md) and Git. You do not need to run the sample function, start a service, or install project dependencies.

## 1. Create an isolated example

Create an empty folder named `security-runtime-demo`, open a terminal there, and initialize it:

```sh
git init
```

Open the folder in the connected editor. Create and save `demo.py`; no Git commit is required:

```python
import os


def export_report(name: str) -> int:
    return os.system("tar -czf " + name + ".tar.gz reports")
```

This intentionally unsafe command-concatenation example is for static analysis only. Keep it in the isolated folder, do not execute it, and do not add it to a real project.

## 2. Request a check

```text
Use AI Security Runtime to check demo.py in this example project.
Only perform static checks and code analysis. Do not execute the sample function,
install dependencies, or modify code. Report actual scope, findings, and trigger conditions.
```

This request also works with manual MCP integration. Ordinary code advice without actual service execution and scope is not a completed Runtime check.

## 3. Understand the finding

An illustrative explanation is: `name` flows into a command passed to `os.system`. If a caller lets external users control it, shell metacharacters may be interpreted as extra commands. A proposed fix is argument-list execution with filename validation. This example does not establish a real caller, authorization model, or deployment, so production exploitability remains unverified.

Actual results depend on enabled rules and successful engine execution. If the expected issue is absent, check whether the saved file was included and the Python rules actually ran.

## 4. Approve a specific fix and verify it

After receiving the actual finding, send:

```text
Fix the command-concatenation issue just identified in demo.py.
Preserve export behavior, validate the filename, and invoke the process with an argument list.
Verify the original finding afterward. Do not execute the example function.
```

One comparison implementation is:

```python
import subprocess


def export_report(name: str) -> int:
    if not name.isidentifier():
        raise ValueError("Invalid report name")
    return subprocess.run(
        ["tar", "-czf", name + ".tar.gz", "reports"],
        check=False,
    ).returncode
```

The value is no longer interpreted by a shell, and the filename is constrained. This addresses the illustrated concatenation issue; a real application still needs directory, authorization, and caller review.

The demo is complete when actual results, your selected fix, and verification against the original finding are reported. Preserve incomplete results instead of excluding a finding to make the demo appear successful.

[Practice checklist](./playground.md) · [Daily workflow](./workflow.md)
