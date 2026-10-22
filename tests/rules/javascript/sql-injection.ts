// Synthetic, independently authored local taint fixtures. Never executed.
const express = require("express");
const pg = require("pg");
const mysql = require("mysql2");
const { Client } = require("pg");
const app = express();
const pool = new pg.Pool({});
const mysqlDb = mysql.createConnection({});
const client = new Client({});

app.get("/users", (req: any, res: any) => {
  const name = req.query.name;
  // ruleid: ai-security.javascript.sql-injection
  pool.query("SELECT id FROM users WHERE name='" + name + "'");
  // ruleid: ai-security.javascript.sql-injection
  client.query(`SELECT id FROM users WHERE name='${name}'`);
  // ok: ai-security.javascript.sql-injection
  pool.query("SELECT id FROM users WHERE name=$1", [name]);
  // ok: ai-security.javascript.sql-injection
  pool.query({ text: "SELECT id FROM users WHERE name=$1", values: [name] });
  // ruleid: ai-security.javascript.sql-injection
  pool.query({ text: "SELECT id FROM users WHERE name='" + name + "'", values: [] });
  // ruleid: ai-security.javascript.sql-injection
  mysqlDb.query("SELECT id FROM users WHERE name='" + name + "'");
  // ruleid: ai-security.javascript.sql-injection
  mysqlDb.execute("SELECT id FROM users ORDER BY " + req.query.order);
  // ok: ai-security.javascript.sql-injection
  mysqlDb.execute("SELECT id FROM users WHERE name=?", [name]);
  // ruleid: ai-security.javascript.sql-injection
  mysqlDb.query({ sql: "SELECT id FROM users WHERE name='" + name + "'", values: [] });
  // ok: ai-security.javascript.sql-injection
  mysqlDb.query({ sql: "SELECT id FROM users WHERE name=?", values: [name] });
  // ruleid: ai-security.javascript.sql-injection
  mysqlDb.execute({ sql: "SELECT id FROM users ORDER BY " + req.query.order, values: [] });
  // ok: ai-security.javascript.sql-injection
  mysqlDb.execute({ sql: "SELECT id FROM users WHERE name=?", values: [name] });
  const unrelated = { query(value) { return value; } };
  // ok: ai-security.javascript.sql-injection
  unrelated.query(name);
});

app.post("/users", function (req: any, res: any) {
  // ruleid: ai-security.javascript.sql-injection
  pool.query("SELECT id FROM users WHERE name='" + req.body.name + "'");
});

import { Pool } from "pg";
import mysqlPromise from "mysql2/promise";
const esmPool = new Pool({});
app.get("/esm-sql", async (req: any, res: any) => {
  const promiseDb = await mysqlPromise.createConnection({});
  // ruleid: ai-security.javascript.sql-injection
  esmPool.query("SELECT id FROM users WHERE name='" + req.query.name + "'");
  // ruleid: ai-security.javascript.sql-injection
  promiseDb.query("SELECT id FROM users WHERE name='" + req.query.name + "'");
  // ok: ai-security.javascript.sql-injection
  promiseDb.query("SELECT id FROM users WHERE name=?", [req.query.name]);
});

// Standalone handler requires an explicitly imported Express Request type.
import { type Request, type Response } from 'express';
import { Pool } from 'pg';
const typedDb = new Pool();
export function typedQualityHandler(request: Request, response: Response) {
  // ruleid: ai-security.javascript.sql-injection
  typedDb.query("SELECT * FROM users WHERE id=" + request.query.id);
  // ok: ai-security.javascript.sql-injection
  typedDb.query("SELECT * FROM users WHERE id=$1", [request.query.id]);
}
