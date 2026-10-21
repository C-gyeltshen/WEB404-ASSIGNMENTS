import type { Context } from "hono";
import { deleteCookie, getSignedCookie, setSignedCookie } from "hono/cookie";
import { createMiddleware } from "hono/factory";
import { env } from "../config/env.js";
import { AppError } from "../lib/errors.js";
import { authService } from "../services/auth.service.js";
import type { AppEnv, AuthUser } from "../types/index.js";

// "__Host-" prefix (production): cookie is Secure, path=/ and bound to this exact host.
const COOKIE = env.isProd ? "__Host-sid" : "sid";
const SESSION_TTL_SECONDS = 8 * 60 * 60;

/** HMAC-signed, HttpOnly cookie holding "<userId>.<expiry>". JS in the page can't read it. */
export async function startSession(c: Context, user: AuthUser) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  await setSignedCookie(c, COOKIE, `${user.id}.${expires}`, env.SESSION_SECRET, {
    httpOnly: true,
    secure: env.isProd,
    sameSite: "Lax",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
}

export function endSession(c: Context) {
  deleteCookie(c, COOKIE, { path: "/", secure: env.isProd });
}

/** Every file route requires a valid session. No anonymous uploads. */
export const requireAuth = createMiddleware<AppEnv>(async (c, next) => {
  const value = await getSignedCookie(c, env.SESSION_SECRET, COOKIE);
  if (!value) throw new AppError(401, "Please sign in.", "UNAUTHENTICATED");

  const [userId, exp] = value.split(".");
  if (!userId || !exp || Number(exp) < Date.now() / 1000) {
    throw new AppError(401, "Session expired. Please sign in again.", "UNAUTHENTICATED");
  }
  const user = await authService.findUser(userId);
  if (!user) throw new AppError(401, "Please sign in.", "UNAUTHENTICATED");

  c.set("user", user);
  await next();
});
