import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { findByLogin, type User } from "./users.js";
import {
  insecureVerify, issueInsecureToken, issueSecureToken, secureVerify, type Claims,
} from "./tokens.js";

type Verify = (t: string) => Claims;
type Sign = (u: User) => string;

const app = new Hono();
app.use("*", cors({ origin: "http://localhost:3000" }));

function bearer(authHeader: string | undefined): string | null {
  if (!authHeader?.startsWith("Bearer ")) return null;
  return authHeader.slice(7).trim();
}

/** Builds the three routes (/login, /me, /admin) for one "world". */
function world(sign: Sign, verify: Verify) {
  const r = new Hono();

  r.post("/login", async (c) => {
    const { username, password } = await c.req.json<{ username: string; password: string }>();
    const user = findByLogin(username, password);
    if (!user) return c.json({ error: "Invalid credentials." }, 401);
    return c.json({ token: sign(user), tokenType: "Bearer" });
  });

  // Any authenticated user.
  r.get("/me", (c) => {
    const token = bearer(c.req.header("authorization"));
    if (!token) return c.json({ error: "Missing Bearer token." }, 401);
    try {
      const claims = verify(token);
      return c.json({ ok: true, claims });
    } catch (e) {
      return c.json({ ok: false, error: (e as Error).message }, 401);
    }
  });

  // Admin only — the prize an attacker is after.
  r.get("/admin", (c) => {
    const token = bearer(c.req.header("authorization"));
    if (!token) return c.json({ error: "Missing Bearer token." }, 401);
    try {
      const claims = verify(token);
      if (claims.role !== "admin") return c.json({ ok: false, error: "Forbidden: admin only." }, 403);
      return c.json({ ok: true, secret: "FLAG{admin-dashboard-unlocked}", claims });
    } catch (e) {
      return c.json({ ok: false, error: (e as Error).message }, 401);
    }
  });

  return r;
}

app.get("/", (c) =>
  c.json({
    name: "JWT auth lab",
    warning: "The /insecure world is intentionally broken. Run locally only.",
    worlds: {
      insecure: ["POST /insecure/login", "GET /insecure/me", "GET /insecure/admin"],
      secure: ["POST /secure/login", "GET /secure/me", "GET /secure/admin"],
    },
  }),
);

app.route("/insecure", world(issueInsecureToken, insecureVerify));
app.route("/secure", world(issueSecureToken, secureVerify));

const port = Number(process.env.PORT ?? 8090);
serve({ fetch: app.fetch, port }, (i) =>
  console.log(`JWT lab on http://localhost:${i.port}  (insecure world under /insecure)`),
);
