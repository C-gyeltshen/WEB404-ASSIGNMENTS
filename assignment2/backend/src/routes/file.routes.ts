import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { zValidator } from "@hono/zod-validator";
import { env } from "../config/env.js";
import { fileController } from "../controllers/file.controller.js";
import { AppError } from "../lib/errors.js";
import { requireAuth } from "../middleware/auth.js";
import { rateLimit } from "../middleware/rate-limit.js";
import { fileIdParamSchema, uploadFormSchema } from "../validation/file.validation.js";
import type { AppEnv } from "../types/index.js";

/** Turn a Zod failure into a clean 400 instead of Zod's raw output. */
const onInvalid = (result: { success: boolean; error?: { issues: { message: string }[] } }) => {
  if (!result.success) {
    throw new AppError(400, result.error?.issues[0]?.message ?? "Invalid request.", "VALIDATION_ERROR");
  }
};

/**
 * Order matters on POST /files:
 *   auth -> rate limit -> body size cap (before parsing!) -> form schema -> controller
 */
export const fileRoutes = new Hono<AppEnv>()
  .use("*", requireAuth)

  .get("/", (c) => fileController.list(c))

  .post(
    "/",
    rateLimit({ name: "uploads", limit: env.UPLOADS_PER_MINUTE, windowMs: 60_000 }),
    bodyLimit({
      maxSize: env.MAX_FILE_SIZE_BYTES + 64 * 1024, // file + multipart overhead
      onError: () => {
        throw new AppError(413, `File is too large (max ${env.MAX_FILE_SIZE_MB} MB).`, "TOO_LARGE");
      },
    }),
    zValidator("form", uploadFormSchema, onInvalid),
    (c) => fileController.upload(c),
  )

  .get("/:id/download-url", zValidator("param", fileIdParamSchema, onInvalid), (c) =>
    fileController.downloadUrl(c),
  )

  .delete("/:id", zValidator("param", fileIdParamSchema, onInvalid), (c) =>
    fileController.remove(c),
  );
