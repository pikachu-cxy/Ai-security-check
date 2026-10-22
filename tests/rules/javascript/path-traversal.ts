// Synthetic delete paths; basename/normalize are not containment proofs.
const express = require("express");
const fs = require("node:fs");
const path = require("node:path");
const { unlink: deleteLocal } = require("fs/promises");
const app = express();
app.delete("/files", async (req: any, res: any) => {
  // ruleid: ai-security.javascript.path-traversal
  fs.unlink(req.query.path, () => {});
  // ruleid: ai-security.javascript.path-traversal
  fs.rmSync(path.normalize(req.query.path));
  // ruleid: ai-security.javascript.path-traversal
  fs.rmdir(path.join("/srv/synthetic", path.basename(req.query.path)), () => {});
  // ruleid: ai-security.javascript.path-traversal
  await deleteLocal(req.query.path);
  // ok: ai-security.javascript.path-traversal
  fs.unlinkSync("/srv/synthetic/temporary.txt");
  // ok: ai-security.javascript.path-traversal
  fs.rmSync("/srv/synthetic/temporary.txt");
});

import { unlink as esmUnlink } from "node:fs/promises";
import * as esmFs from "fs";
app.delete("/esm-delete", async (req: any, res: any) => {
  // ruleid: ai-security.javascript.path-traversal
  await esmUnlink(req.query.path);
  // ruleid: ai-security.javascript.path-traversal
  esmFs.rmSync(req.query.path);
  // ok: ai-security.javascript.path-traversal
  await esmUnlink("/srv/synthetic/temporary.txt");
});

// Standalone handler requires an explicitly imported Express Request type.
import { type Request, type Response } from 'express';
import * as typedFs from 'node:fs';
export function typedQualityHandler(request: Request, response: Response) {
  // ruleid: ai-security.javascript.path-traversal
  typedFs.unlinkSync(request.body.name);
  // ok: ai-security.javascript.path-traversal
  typedFs.unlinkSync('/fixed/file');
}
