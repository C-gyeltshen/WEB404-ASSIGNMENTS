import type { ErrorHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import { AppError } from "../lib/errors.js";
import type { AppEnv } from "../types/index.js";

/**
 * One place that turns errors into responses.
 * Expected errors (AppError) return their safe message. Everything else is
 * logged server-side and returns a generic 500: no stack traces, SQL errors
 * or storage paths ever reach the client.
 */
export const errorHandler: ErrorHandler<AppEnv> = (err, c) => {
  if (err instanceof AppError) {
    return c.json({ error: err.message, code: err.code }, err.status);
  }
  if (err instanceof HTTPException) {
    // hono/csrf throws a bare 403 when the Origin header isn't our frontend.
    const message =
      err.status === 403 ? "Cross-site request blocked (origin not allowed)." : err.message || "Request failed.";
    return c.json({ error: message, code: "HTTP_ERROR" }, err.status);
  }
  console.error(`[${c.get("requestId") ?? "-"}] Unhandled error:`, err);
  return c.json({ error: "Something went wrong.", code: "INTERNAL" }, 500);
};
