# Quick start

::: info Check language coverage before installing
**Code rules cover defined Java, Python, and JavaScript/TypeScript subsets**: 56 distinct rules, 48 default-on. Vue single-file components, Go, PHP, and others have no corresponding bundled SAST rules. Secrets and dependencies have separate scope. [View languages, file types, and detection coverage →](../reference/support.md#languages)
:::

Use the **0.3.9 official release**. Managed macOS installation uses the separate **macos-trial-v0.3.10** release, with Runtime version 0.3.10. Choose your editor, install for your operating system, restart, and verify the real connection before trying a small task.

## 1. Choose your editor {#choose-editor}

| Editor | Setup |
| --- | --- |
| Codex | [Windows bundle or managed macOS installation](./editors/codex.md) |
| Cursor | [Windows bundle or managed macOS installation](./editors/cursor.md) |
| WorkBuddy | [Project-level MCP setup](./editors/workbuddy.md) |
| Other clients | [Manual stdio MCP integration](./editors/other.md) |

The Windows bundle includes Python. The managed macOS installer prepares a dedicated Python environment and detects Apple Silicon or Intel. Runtime installation does not require Git; project checks and the demo do.

You can run the documented command yourself, or ask a local assistant to follow your editor's setup page, verify the download and checksum, and preserve unrelated settings. Paste natural-language requests into chat, not a terminal.

## 2. Restart and verify

Installation starts component preparation in the background. Completely quit and reopen the editor, then open a new chat in the intended local project and send:

```text
Use actual AI Security Runtime tool calls to check the connection, installed version,
build_id, source commit, scanner readiness, vulnerability data, and bound project path.
Confirm that the companion guidance is available. Do not scan or modify the project.
List anything you cannot verify and the next step.
```

A configuration entry alone does not prove the service is connected. See [installation verification](./verify.md).

## 3. Try a small development task

Open a separate empty folder named `security-runtime-demo` in the connected editor and send:

```text
Confirm this is the separate security-runtime-demo folder and initialize Git if needed.
Create labels.py with normalize_label(text), trimming whitespace and converting to lowercase.
Then use AI Security Runtime to check this change and report actual coverage and results.
Do not install project dependencies. Explain any risks before attempting a fix.
```

You should receive both the file change and its actual check status. Component readiness or file creation is not a substitute for a completed check.

Continue with [your first security demo](./demo.md), [practice cases](./playground.md), or the [daily workflow](./workflow.md).
