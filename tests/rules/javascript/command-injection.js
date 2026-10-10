// Synthetic Node.js shell boundaries; never execute these routes.
const express = require("express");
const cp = require("node:child_process");
const { exec: runShell, execFile: runFile } = require("child_process");
const app = express();
app.get("/run", (req, res) => {
  const value = req.query.value;
  // ruleid: ai-security.javascript.command-injection
  cp.exec("echo " + value);
  // ruleid: ai-security.javascript.command-injection
  cp.execSync(req.query.command);
  // ruleid: ai-security.javascript.command-injection
  runShell("echo " + value);
  // ruleid: ai-security.javascript.command-injection
  cp.spawn("echo", [value], { shell: true });
  // ruleid: ai-security.javascript.command-injection
  cp.execFile("echo", [value], { shell: true });
  // ruleid: ai-security.javascript.command-injection
  cp.spawn("/bin/sh", ["-c", value]);
  // ruleid: ai-security.javascript.command-injection
  cp.execFile("cmd.exe", ["/c", value]);
  // ruleid: ai-security.javascript.command-injection
  cp.spawn("powershell.exe", ["-Command", req.query.script]);
  // ok: ai-security.javascript.command-injection
  cp.execFile("cmd.exe", ["/c", "echo synthetic"]);
  // ok: ai-security.javascript.command-injection
  cp.spawn("powershell.exe", ["-Command", "Write-Output synthetic"]);
  // ok: ai-security.javascript.command-injection
  cp.exec("echo fixed-synthetic-value");
  // ok: ai-security.javascript.command-injection
  cp.execFile("/usr/bin/printf", ["%s", value], { shell: false });
  // ok: ai-security.javascript.command-injection
  runFile("/usr/bin/printf", ["%s", value]);
  // ok: ai-security.javascript.command-injection
  cp.spawn("/usr/bin/printf", ["%s", value], { shell: false });
});

import { exec as esmExec, execFile as esmExecFile } from "node:child_process";
import * as esmProcess from "child_process";
app.post("/esm-command", (req, res) => {
  // ruleid: ai-security.javascript.command-injection
  esmExec("echo " + req.body.value);
  // ruleid: ai-security.javascript.command-injection
  esmProcess.exec(req.body.command);
  // ok: ai-security.javascript.command-injection
  esmExecFile("/usr/bin/printf", ["%s", req.body.value]);
});
