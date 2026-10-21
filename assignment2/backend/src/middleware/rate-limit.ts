import { getConnInfo } from "@hono/node-server/conninfo";
import { createMiddleware } from "hono/factory";
import { AppError } from "../lib/errors.js";
import type { AppEnv } from "../types/index.js";

/**
 * Sliding-window limiter keyed by user id (falls back to IP).
 * In-memory: fine for one process. Use Redis/Upstash when running several.
 */
export function rateLimit(opts: { limit: number; windowMs: number; name: string }) {
  const hits = new Map<string, number[]>();

  return createMiddleware<AppEnv>(async (c, next) => {
    const user = c.get("user");
    // Use the socket address, not X-Forwarded-For (a client can set that header).
    // Behind a trusted proxy, read the proxy's client-IP header instead.
    let ip = "unknown";
    try { ip = getConnInfo(c).remote.address ?? "unknown"; } catch { /* non-node runtime */ }
    const key = user ? `u:${user.id}` : `ip:${ip}`;
    const now = Date.now();
    const recent = (hits.get(key) ?? []).filter((t) => now - t < opts.windowMs);

    if (recent.length >= opts.limit) {
      const retryAfter = Math.ceil((opts.windowMs - (now - recent[0]!)) / 1000);
      c.header("Retry-After", String(retryAfter));
      throw new AppError(429, `Too many ${opts.name}. Try again in ${retryAfter}s.`, "RATE_LIMITED");
    }
    recent.push(now);
    hits.set(key, recent);
    await next();
  });
}
