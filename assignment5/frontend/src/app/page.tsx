"use client";

import { useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8090";
type World = "insecure" | "secure";

function b64url(o: unknown) {
  return btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
// Decode a JWT's header + payload in the browser (no verification — just reading).
function decode(token: string) {
  try {
    const [h, p] = token.split(".");
    return {
      header: JSON.parse(atob(h.replace(/-/g, "+").replace(/_/g, "/"))),
      payload: JSON.parse(atob(p.replace(/-/g, "+").replace(/_/g, "/"))),
    };
  } catch {
    return null;
  }
}

export default function Home() {
  const [world, setWorld] = useState<World>("insecure");
  const [token, setToken] = useState("");
  const [out, setOut] = useState<Record<string, unknown> | null>(null);

  async function call(method: string, path: string, body?: unknown, auth = true) {
    const headers: Record<string, string> = {};
    if (body) headers["Content-Type"] = "application/json";
    if (auth && token) headers.authorization = `Bearer ${token}`;
    const r = await fetch(`${API}/${world}${path}`, {
      method, headers, body: body ? JSON.stringify(body) : undefined,
    });
    const data = await r.json();
    setOut({ status: r.status, ...data });
    return data;
  }

  async function login() {
    const d = await call("POST", "/login", { username: "alice", password: "alice-pass-123" }, false);
    if (d.token) setToken(d.token);
  }

  // Forge an alg:none admin token entirely in the browser.
  function forgeAlgNone() {
    setToken(`${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub: "99", username: "mallory", role: "admin" })}.`);
    setOut({ note: "Forged an alg:none admin token (no signature). Now call /admin." });
  }

  const decoded = token ? decode(token) : null;

  return (
    <main>
      <header>
        <div>
          <h1>JWT Attack Lab</h1>
          <p className="muted">Next.js → Hono · Bearer tokens · for learning only</p>
        </div>
        <div className="toggle">
          <button className={world === "insecure" ? "on insecure" : ""} onClick={() => setWorld("insecure")}>Insecure</button>
          <button className={world === "secure" ? "on secure" : ""} onClick={() => setWorld("secure")}>Secure</button>
        </div>
      </header>

      <p className={`banner ${world}`}>
        {world === "insecure"
          ? "⚠ /insecure — trusts alg:none, ignores expiry, weak secret, trusts the role claim."
          : "✓ /secure — pinned HS256, checks exp + issuer + audience, role from the server."}
      </p>

      <section className="card">
        <h2>1 · Get a token</h2>
        <div className="row">
          <button className="go" onClick={login}>Login as alice (normal user)</button>
          <button className="attack" onClick={forgeAlgNone}>Forge alg:none admin token</button>
        </div>
        <label>Bearer token (editable — tamper with it and re-send)
          <textarea value={token} onChange={(e) => setToken(e.target.value)} rows={4} placeholder="token appears here after login" />
        </label>
        {decoded && (
          <div className="decoded">
            <div><span className="k">header</span><pre>{JSON.stringify(decoded.header, null, 2)}</pre></div>
            <div><span className="k">payload</span><pre>{JSON.stringify(decoded.payload, null, 2)}</pre></div>
          </div>
        )}
      </section>

      <section className="card">
        <h2>2 · Use the token</h2>
        <div className="row">
          <button className="go" onClick={() => call("GET", "/me")}>GET /{world}/me</button>
          <button className="go" onClick={() => call("GET", "/admin")}>GET /{world}/admin (admin only)</button>
        </div>
        {out && (
          <pre className={`result ${out.ok && out.status === 200 ? "ok" : "fail"}`}>
            {JSON.stringify(out, null, 2)}
          </pre>
        )}
      </section>
    </main>
  );
}
