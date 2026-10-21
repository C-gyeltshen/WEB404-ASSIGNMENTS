// Shared types used across routes -> controllers -> services -> repositories.

/** The authenticated user attached to the request by the auth middleware. */
export interface AuthUser {
  id: string;
  username: string;
}

/** Hono generic: makes c.get("user") strongly typed. */
export interface AppEnv {
  Variables: {
    user: AuthUser;
    requestId: string;
  };
}

/** File types the server accepts. Extension is decided by the server, never the client. */
export type AllowedExtension = "png" | "jpg" | "gif" | "webp" | "pdf";

export interface AllowedType {
  ext: AllowedExtension;
  mime: string;
  kind: "image" | "pdf";
}

/** Result of the validation layer: the bytes passed every check. */
export interface ValidatedUpload {
  displayName: string; // sanitised original name (display only)
  type: AllowedType;   // detected from file content (magic bytes)
  bytes: Buffer;       // raw bytes that passed validation
}

/** Result of the sanitising step: what actually gets stored. */
export interface SanitizedUpload extends ValidatedUpload {
  sha256: string;
}

/** What the API returns to the browser. Storage keys are never exposed. */
export interface FileDTO {
  id: string;
  name: string;
  mimeType: string;
  size: number;
  createdAt: string;
}

export interface CreateFileRecord {
  ownerId: string;
  originalName: string;
  storageKey: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
}

export interface AuditEntry {
  userId: string | null;
  fileName: string;
  sizeBytes: number;
  sha256: string | null;
  outcome: "ACCEPTED" | "REJECTED";
  reason: string | null;
  ip: string | null;
}
