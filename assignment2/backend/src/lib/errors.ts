import type { ContentfulStatusCode } from "hono/utils/http-status";

/**
 * An error whose message is safe to show to the client.
 * Anything that is NOT an AppError becomes a generic 500 with no details.
 */
export class AppError extends Error {
  constructor(
    public readonly status: ContentfulStatusCode,
    message: string,
    public readonly code = "ERROR",
  ) {
    super(message);
  }
}

/** Thrown by the validation layer when an upload is rejected. */
export class UploadRejectedError extends AppError {
  constructor(message: string, status: ContentfulStatusCode = 422) {
    super(status, message, "UPLOAD_REJECTED");
  }
}
