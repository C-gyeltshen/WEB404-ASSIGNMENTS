import { randomBytes } from "node:crypto";

/**
 * Two "worlds" run side by side:
 *   /insecure/*  — common JWT mistakes, so the attacks succeed
 *   /secure/*    — JWTs done right, so the same attacks fail
 *
 * For learning only. Run locally.
 */

// ❌ INSECURE: a short, guessable HMAC secret. This is the kind of value that
//    ends up in tutorials and .env defaults. It is in every wordlist, so it can
//    be brute-forced offline from a single captured token (see attacks).
export const WEAK_SECRET = "secret";

// ✅ SECURE: 256 bits of randomness, generated at startup. Not in any wordlist.
//    In production this comes from a secrets manager, not from code.
export const STRONG_SECRET = randomBytes(32).toString("hex");

// Secure tokens are pinned to an issuer and audience and are short-lived.
export const ISSUER = "jwt-lab";
export const AUDIENCE = "jwt-lab-clients";
export const ACCESS_TTL_SECONDS = 15 * 60; // 15 minutes
