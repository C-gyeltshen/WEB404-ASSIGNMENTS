"use client";

import { useState } from "react";
import { api, ApiError, formatBytes, type FileItem } from "@/lib/api";

interface Props {
  files: FileItem[];
  usedBytes: number;
  quotaBytes: number;
  onDeleted: (id: string) => void;
}

export function FileTable({ files, usedBytes, quotaBytes, onDeleted }: Props) {
  const [error, setError] = useState<string | null>(null);
  const pct = Math.min(100, (usedBytes / quotaBytes) * 100);

  async function download(id: string) {
    setError(null);
    try {
      // The API checks ownership, then returns a 60-second signed URL that
      // forces a download (Content-Disposition: attachment) instead of rendering.
      const { url } = await api.downloadUrl(id);
      window.location.assign(url);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Download failed.");
    }
  }

  async function remove(id: string) {
    setError(null);
    try {
      await api.remove(id);
      onDeleted(id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Delete failed.");
    }
  }

  return (
    <section className="card">
      <div className="row between">
        <h2>Your files</h2>
        <span className="muted small">{formatBytes(usedBytes)} of {formatBytes(quotaBytes)} used</span>
      </div>
      <div className="bar"><span style={{ width: `${pct}%` }} /></div>

      {error && <p className="alert error" role="alert">{error}</p>}

      {files.length === 0 ? (
        <p className="muted empty">No files yet.</p>
      ) : (
        <table>
          <thead>
            <tr><th>Name</th><th>Type</th><th>Size</th><th>Uploaded</th><th aria-label="Actions" /></tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id}>
                <td className="name">{f.name}</td>
                <td><span className="tag">{f.mimeType.split("/")[1]}</span></td>
                <td>{formatBytes(f.size)}</td>
                <td className="muted">{new Date(f.createdAt).toLocaleString()}</td>
                <td className="actions">
                  <button className="link" onClick={() => download(f.id)}>Download</button>
                  <button className="link danger" onClick={() => remove(f.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
