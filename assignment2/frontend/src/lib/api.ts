/**
 * Tiny typed client for the Hono API.
 * - credentials: "include" sends the HttpOnly session cookie.
 * - The browser never sees Supabase keys or storage paths: it only talks to our API.
 */
const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8787").replace(/\/+$/, "");

export interface User {
  id: string;
  username: string;
}

export interface FileItem {
  id: string;
  name: string;
  mimeType: string;
  size: number;
  createdAt: string;
}

export interface FileList {
  files: FileItem[];
  usedBytes: number;
  quotaBytes: number;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, { ...init, credentials: "include" });
  } catch {
    throw new ApiError(0, "Cannot reach the server. Is the API running?");
  }
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, body.error ?? `Request failed (${res.status}).`);
  return body as T;
}

export const api = {
  me: () => request<{ user: User }>("/auth/me"),

  login: (username: string, password: string) =>
    request<{ user: User }>("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    }),

  logout: () => request<void>("/auth/logout", { method: "POST" }),

  listFiles: () => request<FileList>("/files"),

  upload: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    // No Content-Type header: the browser sets the multipart boundary itself.
    return request<{ file: FileItem }>("/files", { method: "POST", body: form });
  },

  downloadUrl: (id: string) =>
    request<{ url: string; expiresIn: number }>(`/files/${encodeURIComponent(id)}/download-url`),

  remove: (id: string) => request<void>(`/files/${encodeURIComponent(id)}`, { method: "DELETE" }),
};

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
