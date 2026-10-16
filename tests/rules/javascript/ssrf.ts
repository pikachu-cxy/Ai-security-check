// Synthetic outbound-target examples, not a reachability/exploitability proof.
import { type Request, type Response } from "express";
const express = require("express");
const https = require("node:https");
const axios = require("axios");
const app = express();
const legacyRequest = require("request");

export function typedProxyFactory() {
  return (incoming: Request, outgoing: Response) => {
    // ruleid: ai-security.javascript.ssrf
    legacyRequest.get(incoming.body.url);
    // ruleid: ai-security.javascript.ssrf
    fetch(incoming.query.url);
    // ok: ai-security.javascript.ssrf
    legacyRequest.get("https://fixed.example/status");
    // ok: ai-security.javascript.ssrf
    fetch("https://fixed.example/search?q=" + encodeURIComponent(incoming.query.q));
  };
}

export async function typedNamedProxy(incoming: Request, outgoing: Response) {
  // ruleid: ai-security.javascript.ssrf
  await fetch(incoming.body.url);
}

type LocalRequest = { body: { url: string } };
function localDataConsumer(incoming: LocalRequest) {
  // ok: ai-security.javascript.ssrf
  legacyRequest.get(incoming.body.url);
}

function typedClientShadow(incoming: Request, outgoing: Response) {
  const ordinaryClient = { get(value: unknown) { return value; } };
  // ok: ai-security.javascript.ssrf
  ordinaryClient.get(incoming.body.url);
}
app.get("/proxy", async (req: any, res: any) => {
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
app.post("/esm-proxy", async (req: any, res: any) => {
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

import outboundClient from "needle";
function EndpointGroup() {
  this.proxy = (req: any, res: any) => {
    // ruleid: ai-security.javascript.ssrf
    outboundClient.get(req.query.target, () => {});
    // ok: ai-security.javascript.ssrf
    outboundClient.get("https://fixed.example/status", () => {});
  };
  this.asyncProxy = async (req: any, res: any) => {
    // ruleid: ai-security.javascript.ssrf
    await fetch(req.body.target);
    // ok: ai-security.javascript.ssrf
    await fetch("https://fixed.example/status");
  };
}
app.get("/needle-proxy", (req: any, res: any) => {
  // ruleid: ai-security.javascript.ssrf
  outboundClient.get(req.query.target, () => {});
  const localRegistry = { get: (key: string) => key };
  // ok: ai-security.javascript.ssrf
  localRegistry.get(req.query.target);
});
