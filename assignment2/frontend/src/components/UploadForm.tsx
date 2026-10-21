"use client";

import { useRef, useState, type DragEvent } from "react";
import { api, ApiError, formatBytes, type FileItem } from "@/lib/api";

const ACCEPT = ".png,.jpg,.jpeg,.gif,.webp,.pdf";
const MAX_BYTES = 5 * 1024 * 1024;

type Status = { kind: "success" | "error"; text: string } | null;

/**
 * The checks here are for USER EXPERIENCE only (fast feedback).
 * They are trivially bypassed with curl or DevTools, so the server repeats
 * every check and more. Never rely on client-side validation for security.
 */
export function UploadForm({ onUploaded }: { onUploaded: (file: FileItem) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [selected, setSelected] = useState<File | null>(null);
  const [status, setStatus] = useState<Status>(null);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);

  function choose(file: File | undefined) {
    setStatus(null);
    setSelected(file ?? null);
    if (file && file.size > MAX_BYTES) {
      setStatus({ kind: "error", text: `File is too large (max ${formatBytes(MAX_BYTES)}).` });
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    choose(e.dataTransfer.files[0]);
  }

  async function upload() {
    if (!selected) return;
    setBusy(true);
    setStatus(null);
    try {
      const { file } = await api.upload(selected);
      onUploaded(file);
      setStatus({ kind: "success", text: `Uploaded “${file.name}” (${formatBytes(file.size)}).` });
      setSelected(null);
      if (input.current) input.current.value = "";
    } catch (err) {
      // React escapes this text, so a malicious filename echoed back can't inject HTML.
      setStatus({ kind: "error", text: err instanceof ApiError ? err.message : "Upload failed." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Upload a file</h2>
      <label
        className={`dropzone${dragging ? " dragging" : ""}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <input ref={input} type="file" accept={ACCEPT} onChange={(e) => choose(e.target.files?.[0])} />
        <span className="dropzone-title">
          {selected ? selected.name : "Drop a file here or click to choose"}
        </span>
        <span className="muted">
          {selected ? formatBytes(selected.size) : "PNG, JPG, GIF, WEBP or PDF · max 5 MB"}
        </span>
      </label>

      {status && <p className={`alert ${status.kind}`} role="status">{status.text}</p>}

      <div className="row">
        <button onClick={upload} disabled={!selected || busy}>{busy ? "Uploading…" : "Upload"}</button>
        <span className="muted small">Images are re-encoded and their metadata (EXIF, GPS) is removed.</span>
      </div>
    </section>
  );
}
