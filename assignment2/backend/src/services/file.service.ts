import { createHash, randomUUID } from "node:crypto";
import { env } from "../config/env.js";
import { AppError, UploadRejectedError } from "../lib/errors.js";
import { auditRepository, fileRepository } from "../repositories/file.repository.js";
import { storageRepository } from "../repositories/storage.repository.js";
import { validateUpload } from "../validation/file.validation.js";
import { sanitizeUpload } from "./sanitizer.service.js";
import type { AuthUser, FileDTO } from "../types/index.js";

type FileRow = Awaited<ReturnType<typeof fileRepository.findOwned>> & {};

function toDTO(row: FileRow): FileDTO {
  return {
    id: row.id,
    name: row.originalName,
    mimeType: row.mimeType,
    size: row.sizeBytes,
    createdAt: row.createdAt.toISOString(),
  };
}

export const fileService = {
  /**
   * validate -> sanitise -> quota -> store (random key) -> save metadata -> audit.
   * Any failure before storage means nothing is stored.
   */
  async upload(user: AuthUser, file: File, ip: string | null): Promise<FileDTO> {
    let sha256: string | null = null;
    try {
      if (file.size <= env.MAX_FILE_SIZE_BYTES) {
        sha256 = createHash("sha256").update(Buffer.from(await file.arrayBuffer())).digest("hex");
      }

      const validated = await validateUpload(file);
      const clean = await sanitizeUpload(validated);

      const used = await fileRepository.totalBytesForOwner(user.id);
      if (used + clean.bytes.length > env.USER_QUOTA_BYTES) {
        throw new UploadRejectedError(`Storage quota of ${env.USER_QUOTA_MB} MB exceeded.`, 413);
      }

      // Server-generated key: the user's filename never becomes a storage path.
      const storageKey = `${user.id}/${randomUUID()}.${clean.type.ext}`;
      await storageRepository.upload(storageKey, clean.bytes, clean.type.mime);

      let row;
      try {
        row = await fileRepository.create({
          ownerId: user.id,
          originalName: clean.displayName,
          storageKey,
          mimeType: clean.type.mime,
          sizeBytes: clean.bytes.length,
          sha256: clean.sha256,
        });
      } catch (dbErr) {
        // Keep storage and DB consistent: remove the orphaned object.
        await storageRepository.remove(storageKey).catch(() => {});
        throw dbErr;
      }

      await auditRepository.log({
        userId: user.id, fileName: clean.displayName, sizeBytes: clean.bytes.length,
        sha256, outcome: "ACCEPTED", reason: null, ip,
      });
      return toDTO(row);
    } catch (err) {
      if (err instanceof UploadRejectedError) {
        await auditRepository.log({
          userId: user.id, fileName: file.name || "(none)", sizeBytes: file.size,
          sha256, outcome: "REJECTED", reason: err.message, ip,
        });
      }
      throw err;
    }
  },

  async list(user: AuthUser): Promise<{ files: FileDTO[]; usedBytes: number; quotaBytes: number }> {
    const [rows, usedBytes] = await Promise.all([
      fileRepository.listByOwner(user.id),
      fileRepository.totalBytesForOwner(user.id),
    ]);
    return { files: rows.map(toDTO), usedBytes, quotaBytes: env.USER_QUOTA_BYTES };
  },

  async getDownloadUrl(user: AuthUser, fileId: string): Promise<{ url: string; expiresIn: number }> {
    const row = await fileRepository.findOwned(fileId, user.id);
    // 404 (not 403) so attackers can't tell whether another user's file exists.
    if (!row) throw new AppError(404, "File not found.", "NOT_FOUND");
    const url = await storageRepository.createSignedDownloadUrl(
      row.storageKey, row.originalName, env.SIGNED_URL_TTL_SECONDS,
    );
    return { url, expiresIn: env.SIGNED_URL_TTL_SECONDS };
  },

  async remove(user: AuthUser, fileId: string): Promise<void> {
    const row = await fileRepository.findOwned(fileId, user.id);
    if (!row) throw new AppError(404, "File not found.", "NOT_FOUND");
    await storageRepository.remove(row.storageKey);
    await fileRepository.deleteOwned(fileId, user.id);
  },
};
