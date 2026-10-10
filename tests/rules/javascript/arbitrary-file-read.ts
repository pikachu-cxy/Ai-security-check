// Synthetic bounded-read candidates; never execute these routes.
const express = require("express");
const fs = require("node:fs");
const path = require("node:path");
const { readFile: readLocal } = require("fs/promises");
const app = express();
app.get("/files", async (req: any, res: any) => {
  const candidate = req.query.path;
  // ruleid: ai-security.javascript.arbitrary-file-read
  fs.readFile(candidate, () => {});
  // ruleid: ai-security.javascript.arbitrary-file-read
  fs.readFileSync(path.normalize(candidate));
  // ruleid: ai-security.javascript.arbitrary-file-read
  fs.createReadStream(path.join("/srv/synthetic", path.basename(candidate)));
  // ruleid: ai-security.javascript.arbitrary-file-read
  await readLocal(candidate);
  // ruleid: ai-security.javascript.arbitrary-file-read
  res.sendFile(candidate);
  // ruleid: ai-security.javascript.arbitrary-file-read
  res.download(candidate);
  const unrelated = { sendFile(value) { return value; } };
  // ok: ai-security.javascript.arbitrary-file-read
  unrelated.sendFile(candidate);
  // ok: ai-security.javascript.arbitrary-file-read
  fs.readFileSync("/srv/synthetic/public.txt");
  // ok: ai-security.javascript.arbitrary-file-read
  res.sendFile("/srv/synthetic/public.txt");
});

import { readFile as esmRead } from "node:fs/promises";
import * as esmFs from "fs";
app.get("/esm-read", async (req: any, res: any) => {
  // ruleid: ai-security.javascript.arbitrary-file-read
  await esmRead(req.query.path);
  // ruleid: ai-security.javascript.arbitrary-file-read
  esmFs.readFileSync(req.query.path);
  // ok: ai-security.javascript.arbitrary-file-read
  await esmRead("/srv/synthetic/public.txt");
});
