import { Hono } from "hono";
import { cors } from "hono/cors";
import { csrf } from "hono/csrf";
import { logger } from "hono/logger";
import { requestId } from "hono/request-id";
import { secureHeaders } from "hono/secure-headers";
import { env } from "./config/env.js";
import { errorHandler } from "./middleware/error-handler.js";
import { routes } from "./routes/index.js";
import type { AppEnv } from "./types/index.js";

export const app = new Hono<AppEnv>();

app.use("*", requestId());
app.use("*", logger());

// Security headers on every response (nosniff, frame-ancestors, etc.).
// This is a JSON API, so its CSP allows nothing.
app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
    crossOriginResourcePolicy: "same-site",
    strictTransportSecurity: env.isProd ? "max-age=63072000; includeSubDomains" : false,
  }),
);

// Only the frontend origin may call the API with cookies.
app.use(
  "*",
  cors({
    origin: env.FRONTEND_ORIGIN,
    credentials: true,
    allowMethods: ["GET", "POST", "DELETE"],
    allowHeaders: ["Content-Type"],
    maxAge: 600,
  }),
);

// CSRF: a multipart form POST is a "simple request" that skips the CORS
// preflight, so a malicious site could submit one. Reject it unless the
// Origin header is our frontend.
app.use("*", csrf({ origin: env.FRONTEND_ORIGIN }));

app.route("/", routes);

app.notFound((c) => c.json({ error: "Not found.", code: "NOT_FOUND" }, 404));
app.onError(errorHandler);
