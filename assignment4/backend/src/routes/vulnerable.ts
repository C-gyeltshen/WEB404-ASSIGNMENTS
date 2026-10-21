import { Hono } from "hono";
import { db } from "../db.js";

/**
 * ⚠️  DELIBERATELY VULNERABLE ROUTES  ⚠️
 *
 * Every query here is built by GLUEING USER INPUT INTO THE SQL STRING.
 * That single mistake — string concatenation instead of parameters — is the
 * root cause of every SQL injection in this file. Do not copy this pattern.
 *
 * Compare each handler with its twin in routes/safe.ts.
 */
export const vulnerable = new Hono();

/* 1) AUTHENTICATION BYPASS ------------------------------------------------ */
// The username/password are dropped straight into the WHERE clause.
// Payload: username = ' OR '1'='1' --   (comment out the password check)
vulnerable.post("/login", async (c) => {
  const { username, password } = await c.req.json<{ username: string; password: string }>();

  const sql = `SELECT id, username, role FROM users
               WHERE username = '${username}' AND password = '${password}'`;
  try {
    const row = db.prepare(sql).get() as { username: string; role: string } | undefined;
    return c.json({ sql, loggedIn: !!row, user: row ?? null });
  } catch (e) {
    return c.json({ sql, error: (e as Error).message }, 400);
  }
});

/* 2) UNION-BASED + 3) ERROR-BASED ---------------------------------------- */
// A product search. Because the input is concatenated, an attacker can close
// the string and append UNION SELECT to read other tables, or trigger a DB
// error that leaks schema/data.
//   UNION:  Monitor' UNION SELECT id, username || ':' || password, 0 FROM users --
//   ERROR:  zzz' OR 1=json_extract('{}',(SELECT api_token FROM users WHERE role='admin')) --
//           (SQLite puts the stolen value into the "bad JSON path: ..." error)
vulnerable.get("/products", (c) => {
  const search = c.req.query("q") ?? "";

  const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${search}%'`;
  try {
    const rows = db.prepare(sql).all();
    return c.json({ sql, results: rows });
  } catch (e) {
    // Leaking the raw DB error is what makes ERROR-BASED injection possible.
    return c.json({ sql, error: (e as Error).message }, 400);
  }
});

/* 4) BLIND (boolean + time-based) ---------------------------------------- */
// Looks up a user by id and returns ONLY whether a row was found — no data.
// An attacker asks yes/no questions one bit at a time:
//   boolean: 1 AND (SELECT substr(password,1,1) FROM users WHERE id=3)='S'
//   time:    1 AND sleep(2)
vulnerable.get("/user", (c) => {
  const id = c.req.query("id") ?? "";

  const sql = `SELECT id, username FROM users WHERE id = ${id}`;
  const started = Date.now();
  try {
    const row = db.prepare(sql).get();
    // Deliberately minimal: the attacker only learns TRUE (found) or FALSE.
    return c.json({ sql, found: !!row, ms: Date.now() - started });
  } catch (e) {
    return c.json({ sql, error: (e as Error).message, ms: Date.now() - started }, 400);
  }
});
