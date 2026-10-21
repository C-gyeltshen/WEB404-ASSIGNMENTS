"use client";

import { useCallback, useEffect, useState } from "react";
import { FileTable } from "@/components/FileTable";
import { LoginForm } from "@/components/LoginForm";
import { UploadForm } from "@/components/UploadForm";
import { api, type FileList, type User } from "@/lib/api";

export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(true);
  const [data, setData] = useState<FileList>({ files: [], usedBytes: 0, quotaBytes: 1 });

  const refresh = useCallback(async () => {
    try {
      setData(await api.listFiles());
    } catch {
      /* the table shows its own errors */
    }
  }, []);

  // On first load, restore an existing session (the HttpOnly cookie) and its files.
  useEffect(() => {
    api.me()
      .then(async ({ user }) => {
        setUser(user);
        await refresh();
      })
      .catch(() => setUser(null))
      .finally(() => setChecking(false));
  }, [refresh]);

  function onLogin(u: User) {
    setUser(u);
    void refresh();
  }

  async function logout() {
    await api.logout().catch(() => {});
    setUser(null);
  }

  if (checking) return <main className="container"><p className="muted">Loading…</p></main>;
  if (!user) return <main className="container"><LoginForm onLogin={onLogin} /></main>;

  return (
    <main className="container">
      <header className="row between header">
        <div>
          <h1>Secure Upload</h1>
          <p className="muted small">Next.js → Hono API → Prisma + Supabase Storage</p>
        </div>
        <div className="row">
          <span className="muted small">Signed in as <strong>{user.username}</strong></span>
          <button className="secondary" onClick={logout}>Sign out</button>
        </div>
      </header>

      <UploadForm onUploaded={() => void refresh()} />
      <FileTable
        {...data}
        onDeleted={(id) => {
          setData((d) => ({ ...d, files: d.files.filter((f) => f.id !== id) }));
          void refresh(); // update the quota bar
        }}
      />
    </main>
  );
}
