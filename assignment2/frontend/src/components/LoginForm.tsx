"use client";

import { useState, type FormEvent } from "react";
import { api, ApiError, type User } from "@/lib/api";

export function LoginForm({ onLogin }: { onLogin: (user: User) => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const { user } = await api.login(String(data.get("username")), String(data.get("password")));
      onLogin(user);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card narrow">
      <h1>Secure Upload</h1>
      <p className="muted">Sign in to upload files. Demo users: alice, bob.</p>
      <form onSubmit={submit} className="stack">
        <label>
          Username
          <input name="username" autoComplete="username" required maxLength={50} />
        </label>
        <label>
          Password
          <input name="password" type="password" autoComplete="current-password" required />
        </label>
        {error && <p className="alert error" role="alert">{error}</p>}
        <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </section>
  );
}
