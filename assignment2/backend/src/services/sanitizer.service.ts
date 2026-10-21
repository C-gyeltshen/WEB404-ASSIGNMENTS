import { createHash } from "node:crypto";
import sharp from "sharp";
import { UploadRejectedError } from "../lib/errors.js";
import { checkForEmbeddedScripts } from "../validation/file.validation.js";
import type { SanitizedUpload, ValidatedUpload } from "../types/index.js";

/** Decompression-bomb guard: refuse images that decode to more than this. */
const MAX_IMAGE_PIXELS = 25_000_000; // ~5000 x 5000

/** PDF features that can execute code or carry hidden payloads. */
const PDF_ACTIVE_CONTENT = [
  "/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/RichMedia",
  "/XFA", "/AA", "/OpenAction", "/SubmitForm", "/ImportData",
];

/**
 * Re-encode images from decoded pixels. The stored file is a brand-new image,
 * so anything hidden in the original (appended payloads, polyglot tricks,
 * EXIF/GPS metadata, malformed chunks aimed at image parsers) is gone.
 */
async function reencodeImage(upload: ValidatedUpload): Promise<Buffer> {
  const { ext } = upload.type;
  try {
    const img = sharp(upload.bytes, {
      limitInputPixels: MAX_IMAGE_PIXELS,
      failOn: "error",
      animated: ext === "gif" || ext === "webp",
    }).rotate(); // apply EXIF orientation before metadata is dropped

    // sharp strips all metadata (EXIF, GPS, XMP, ICC comments) unless told to keep it.
    switch (ext) {
      case "jpg": return await img.jpeg({ quality: 90, mozjpeg: true }).toBuffer();
      case "png": return await img.png({ compressionLevel: 9 }).toBuffer();
      case "gif": return await img.gif().toBuffer();
      case "webp": return await img.webp({ quality: 90 }).toBuffer();
      default: throw new UploadRejectedError("Unsupported image type.");
    }
  } catch (err) {
    if (err instanceof UploadRejectedError) throw err;
    const msg = err instanceof Error ? err.message : "";
    if (/pixel limit/i.test(msg)) {
      throw new UploadRejectedError("Image dimensions are too large (possible decompression bomb).");
    }
    throw new UploadRejectedError("File is not a valid image.");
  }
}

/**
 * PDFs cannot be safely re-encoded here, so reject any with active content.
 * PDF names may be hex-escaped (/J#61vaScript = /JavaScript): decode first.
 */
function checkPdf(bytes: Buffer): Buffer {
  const text = bytes.toString("latin1");
  if (!text.slice(-1024).includes("%%EOF")) {
    throw new UploadRejectedError("PDF is malformed or truncated.");
  }
  const decoded = text.replace(/#([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  for (const keyword of PDF_ACTIVE_CONTENT) {
    // match "/JS" but not "/JSomethingElse"
    if (new RegExp(`${keyword.replace("/", "\\/")}(?![A-Za-z])`).test(decoded)) {
      throw new UploadRejectedError(
        "PDF contains active content (JavaScript, auto-actions, launch actions or embedded files).",
      );
    }
  }
  return bytes;
}

export async function sanitizeUpload(upload: ValidatedUpload): Promise<SanitizedUpload> {
  const clean = upload.type.kind === "image" ? await reencodeImage(upload) : checkPdf(upload.bytes);
  checkForEmbeddedScripts(clean); // re-check the output too
  return {
    ...upload,
    bytes: clean,
    sha256: createHash("sha256").update(clean).digest("hex"),
  };
}
