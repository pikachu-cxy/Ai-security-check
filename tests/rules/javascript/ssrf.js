// Synthetic outbound-target examples, not a reachability/exploitability proof.
const express = require("express");
const https = require("node:https");
const axios = require("axios");
const app = express();
app.get("/proxy", async (req, res) => {
  // ruleid: ai-security.javascript.ssrf
  await fetch(req.query.url);
  // ruleid: ai-security.javascript.ssrf
  https.get(req.query.url);
  // ruleid: ai-security.javascript.ssrf
  axios.get(req.query.url);
  // ruleid: ai-security.javascript.ssrf
  await fetch(new URL(req.query.url, "https://fixed.example/"));
  // ok: ai-security.javascript.ssrf
  await fetch("https://fixed.example/status");
  // ok: ai-security.javascript.ssrf
  await fetch("https://fixed.example/search?q=" + encodeURIComponent(req.query.q));
  const targets = { status: "https://fixed.example/status", health: "https://fixed.example/health" };
  const destination = req.query.mode === "status" ? targets.status : targets.health;
  // ok: ai-security.javascript.ssrf
  await fetch(destination);
});

import * as esmHttps from "node:https";
import esmAxios from "axios";
app.post("/esm-proxy", async (req, res) => {
  // ruleid: ai-security.javascript.ssrf
  esmHttps.get(req.body.url);
  // ruleid: ai-security.javascript.ssrf
  await esmAxios(req.body.url);
  // ruleid: ai-security.javascript.ssrf
  await esmAxios.request({url: req.body.url, data: "synthetic"});
  // ruleid: ai-security.javascript.ssrf
  esmHttps.request({hostname: req.body.host, path: "/"});
  // ok: ai-security.javascript.ssrf
  await esmAxios.request({url: "https://fixed.example/submit", data: req.body.data});
  // ok: ai-security.javascript.ssrf
  esmHttps.request({hostname: "fixed.example", path: req.body.path});
  // ok: ai-security.javascript.ssrf
  await esmAxios({url: "https://fixed.example/submit", data: req.body.data});
});
