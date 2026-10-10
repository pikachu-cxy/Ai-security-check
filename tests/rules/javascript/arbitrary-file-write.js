// Synthetic write paths; payload taint alone is not this rule's sink.
const express = require("express");
const fs = require("fs");
const path = require("node:path");
const { writeFile: writeLocal } = require("fs/promises");
const app = express();
app.post("/files", async (req, res) => {
  // ruleid: ai-security.javascript.arbitrary-file-write
  fs.writeFile(req.body.path, "synthetic-content", () => {});
  // ruleid: ai-security.javascript.arbitrary-file-write
  fs.appendFileSync(path.normalize(req.body.path), "synthetic-content");
  // ruleid: ai-security.javascript.arbitrary-file-write
  fs.createWriteStream(path.join("/srv/synthetic", path.basename(req.body.path)));
  // ruleid: ai-security.javascript.arbitrary-file-write
  await writeLocal(req.body.path, "synthetic-content");
  // ok: ai-security.javascript.arbitrary-file-write
  fs.writeFileSync("/srv/synthetic/output.txt", req.body.content);
  // ok: ai-security.javascript.arbitrary-file-write
  fs.appendFileSync("/srv/synthetic/output.txt", "synthetic-content");
});

import { writeFile as esmWrite } from "node:fs/promises";
import * as esmFs from "fs";
app.post("/esm-write", async (req, res) => {
  // ruleid: ai-security.javascript.arbitrary-file-write
  await esmWrite(req.body.path, "synthetic");
  // ruleid: ai-security.javascript.arbitrary-file-write
  esmFs.writeFileSync(req.body.path, "synthetic");
  // ok: ai-security.javascript.arbitrary-file-write
  await esmWrite("/srv/synthetic/output.txt", req.body.content);
});
