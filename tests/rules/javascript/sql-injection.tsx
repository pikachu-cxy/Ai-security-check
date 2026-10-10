// Synthetic parser/taint fixture only. This source is never executed.
import * as pg from "pg";
import express, { Request, Response } from "express";
const app = express();
const pool = new pg.Pool({});
const preview = <span>synthetic</span>;
app.get("/users", (req: Request, res: Response) => {
  // ruleid: ai-security.javascript.sql-injection
  pool.query("SELECT id FROM users WHERE name='" + req.query.name + "'");
  // ok: ai-security.javascript.sql-injection
  pool.query("SELECT id FROM users WHERE name=$1", [req.query.name]);
});
