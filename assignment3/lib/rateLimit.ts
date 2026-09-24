/**
 * Tiny in-memory fixed-window rate limiter (per client IP).
 * Good enough for a single-instance demo; use Redis or similar in production.
 */
const WINDOW_MS = 60_000;
const MAX_REQUESTS = 30;
const hits = new Map<string, { count: number; start: number }>();

export function rateLimit(key: string): { allowed: boolean; retryAfter: number } {
  const now = Date.now();
  const entry = hits.get(key);
  if (!entry || now - entry.start > WINDOW_MS) {
    hits.set(key, { count: 1, start: now });
    return { allowed: true, retryAfter: 0 };
  }
  entry.count++;
  if (entry.count > MAX_REQUESTS) {
    return { allowed: false, retryAfter: Math.ceil((entry.start + WINDOW_MS - now) / 1000) };
  }
  return { allowed: true, retryAfter: 0 };
}

export function clientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "local";
}

/** Structured audit log line for every command attempt (allowed or blocked). */
export function audit(event: Record<string, unknown>) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), type: "cli-audit", ...event }));
}
