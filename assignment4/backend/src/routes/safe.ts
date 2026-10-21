import { Hono } from "hono";
import { db } from "../db.js";

/**
 * ✅  SECURE VERSIONS of the same three endpoints.
 *
 * The ONE change that fixes every injection: user input is passed as a
 * PARAMETER (the `?` placeholders), never concatenated into the SQL text.
 * The database then treats the input purely as data, so ' OR '1'='1 is just
 * a username that happens to contain quotes — it is matched literally and
 * found nowhere.
 *
 * Secondary defences shown too: input validation and not leaking raw errors.
 */
export const safe = new Hono();

/* 1) AUTHENTICATION — parameterised ------------------------------------- */
safe.post("/login", async (c) => {
  const { username, password } = await c.req.json<{ username: string; password: string }>();

  // `?` placeholders: the values are sent to the DB separately from the SQL.
  const sql = `SELECT id, username, role FROM users WHERE username = ? AND password = ?`;
  const row = db.prepare(sql).get(username, password) as
    | { username: string; role: string }
    | undefined;

  return c.json({ sql, params: [username, password], loggedIn: !!row, user: row ?? null });
});

/* 2+3) PRODUCT SEARCH — parameterised ----------------------------------- */
safe.get("/products", (c) => {
  const search = c.req.query("q") ?? "";

  // The LIKE wildcards are added to the VALUE, not the SQL string.
  const sql = `SELECT id, name, price FROM products WHERE name LIKE ?`;
  try {
    const rows = db.prepare(sql).all(`%${search}%`);
    return c.json({ sql, params: [`%${search}%`], results: rows });
  } catch {
    // Never return the raw DB error to the client.
    return c.json({ error: "Query failed." }, 400);
  }
});

/* 4) USER LOOKUP — parameterised + validated ---------------------------- */
safe.get("/user", (c) => {
  const raw = c.req.query("id") ?? "";

  // Defence in depth: an id must be a positive integer. Reject anything else
  // before it ever reaches the database.
  if (!/^\d+$/.test(raw)) {
    return c.json({ error: "id must be a positive integer." }, 400);
  }

  const sql = `SELECT id, username FROM users WHERE id = ?`;
  const row = db.prepare(sql).get(Number(raw));
  return c.json({ sql, params: [Number(raw)], found: !!row, user: row ?? null });
});
