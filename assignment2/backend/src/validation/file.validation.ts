import { fileTypeFromBuffer } from "file-type";
import { z } from "zod";
import { env } from "../config/env.js";
import { UploadRejectedError } from "../lib/errors.js";
import type { AllowedExtension, AllowedType, ValidatedUpload } from "../types/index.js";

/* ------------------------------------------------------------------ config */

/**
 * ALLOWLIST of accepted types, keyed by the MIME type that `file-type`
 * detects from the file's magic bytes. Anything not here is rejected.
 * SVG and HTML are deliberately absent: both can carry JavaScript.
 */
export const ALLOWED_TYPES: Record<string, AllowedType> = {
  "image/png": { ext: "png", mime: "image/png", kind: "image" },
  "image/jpeg": { ext: "jpg", mime: "image/jpeg", kind: "image" },
  "image/gif": { ext: "gif", mime: "image/gif", kind: "image" },
  "image/webp": { ext: "webp", mime: "image/webp", kind: "image" },
  "application/pdf": { ext: "pdf", mime: "application/pdf", kind: "pdf" },
};

/** Extensions a user may put in the filename, mapped to the canonical one. */
const EXTENSION_ALIASES: Record<string, AllowedExtension> = {
  png: "png", jpg: "jpg", jpeg: "jpg", gif: "gif", webp: "webp", pdf: "pdf",
};

/** Executable / interpretable extensions. Used to catch "shell.php.png". */
const DANGEROUS_EXTENSIONS = new Set([
  "php", "php3", "php4", "php5", "php7", "phtml", "phar", "pht", "phps",
  "asp", "aspx", "ashx", "asmx", "cer", "jsp", "jspx", "cgi", "pl", "py", "rb",
  "sh", "bash", "exe", "dll", "bat", "cmd", "com", "ps1", "vbs", "js", "mjs",
  "html", "htm", "xhtml", "shtml", "svg", "xml", "swf", "jar", "war",
  "htaccess", "config", "ini",
]);

/** Markers of server-side code or HTML hidden inside a "valid" file (polyglots). */
const SCRIPT_MARKERS = ["<?php", "<script", "<jsp:", "<%@ page", 'runat="server"'];

/* ------------------------------------------------------- request schemas */

/** Shape of the multipart form: exactly one field called "file". */
export const uploadFormSchema = z.object({
  file: z.instanceof(File, { message: "A file is required in the 'file' field." }),
});

/** Route param: must be a UUID, so "../../etc/passwd" never reaches the DB. */
export const fileIdParamSchema = z.object({
  id: z.uuid({ message: "Invalid file id." }),
});

/* -------------------------------------------------------- filename checks */

/**
 * Clean the client-supplied name. It is used for display and for the
 * download name only. The object is stored under a random UUID.
 */
export function sanitizeFileName(raw: string): string {
  if (!raw) throw new UploadRejectedError("No filename supplied.", 400);
  if (raw.includes("\0")) throw new UploadRejectedError("Invalid filename (null byte).", 400);

  let name = raw.normalize("NFKC");
  name = name.replace(/\\/g, "/").split("/").pop() ?? ""; // strip any path: ../../x -> x
  name = name.replace(/[^A-Za-z0-9._ -]/g, "_");          // safe character set only
  name = name.replace(/^[ .]+|[ .]+$/g, "");              // "shell.php." / ".htaccess"

  if (!name) throw new UploadRejectedError("Invalid filename.", 400);
  return name.slice(0, 120);
}

/** Allowlisted extension + no dangerous inner extension ("shell.php.jpg"). */
export function checkExtension(name: string): AllowedExtension {
  const parts = name.toLowerCase().split(".");
  if (parts.length < 2) throw new UploadRejectedError("File has no extension.");

  const ext = parts.at(-1)!;
  const canonical = EXTENSION_ALIASES[ext];
  if (!canonical) {
    throw new UploadRejectedError(
      `File type '.${ext}' is not allowed. Allowed: ${Object.keys(EXTENSION_ALIASES).join(", ")}.`,
    );
  }
  if (parts.slice(1, -1).some((p) => DANGEROUS_EXTENSIONS.has(p))) {
    throw new UploadRejectedError("Suspicious double extension in filename.");
  }
  return canonical;
}

/* --------------------------------------------------------- content checks */

/**
 * Detect the real type from magic bytes. The browser's Content-Type header
 * and the filename are NOT trusted: the content must agree with the extension.
 */
export async function detectType(bytes: Buffer, claimedExt: AllowedExtension): Promise<AllowedType> {
  const detected = await fileTypeFromBuffer(bytes);
  const type = detected ? ALLOWED_TYPES[detected.mime] : undefined;
  if (!type) throw new UploadRejectedError("File content is not an allowed type.");
  if (type.ext !== claimedExt) {
    throw new UploadRejectedError(
      `File content (${type.ext}) does not match its extension (.${claimedExt}).`,
    );
  }
  return type;
}

/** Reject files that hide PHP/JSP/HTML script code anywhere in their bytes. */
export function checkForEmbeddedScripts(bytes: Buffer): void {
  const text = bytes.toString("latin1").toLowerCase();
  if (SCRIPT_MARKERS.some((m) => text.includes(m))) {
    throw new UploadRejectedError("File contains embedded script content.");
  }
}

/* --------------------------------------------------------------- pipeline */

/** Run every check in order. The first failure throws (fail closed). */
export async function validateUpload(file: File): Promise<ValidatedUpload> {
  // Size: checked from the declared size first, then from the bytes actually read.
  if (file.size === 0) throw new UploadRejectedError("File is empty.", 400);
  if (file.size > env.MAX_FILE_SIZE_BYTES) {
    throw new UploadRejectedError(`File is too large (max ${env.MAX_FILE_SIZE_MB} MB).`, 413);
  }
  const bytes = Buffer.from(await file.arrayBuffer());
  if (bytes.length > env.MAX_FILE_SIZE_BYTES) {
    throw new UploadRejectedError(`File is too large (max ${env.MAX_FILE_SIZE_MB} MB).`, 413);
  }

  const displayName = sanitizeFileName(file.name);
  const claimedExt = checkExtension(displayName);
  const type = await detectType(bytes, claimedExt);
  checkForEmbeddedScripts(bytes);

  return { displayName, type, bytes };
}
