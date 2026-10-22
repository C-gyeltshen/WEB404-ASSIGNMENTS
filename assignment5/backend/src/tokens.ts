import jwt from "jsonwebtoken";
import {
  ACCESS_TTL_SECONDS, AUDIENCE, ISSUER, STRONG_SECRET, WEAK_SECRET,
} from "./config.js";
import { findById, type User } from "./users.js";

export interface Claims {
  sub: string;
  username: string;
  role: string;
}

/* ─────────────────────────── INSECURE WORLD ─────────────────────────── */

// Signs with the WEAK secret and no expiry. Mistake #1 (weak key) and
// mistake #2 (no exp) both live here.
export function issueInsecureToken(user: User): string {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    WEAK_SECRET,
    { algorithm: "HS256" }, // note: no expiresIn
  );
}

/**
 * ❌ A hand-rolled verifier full of the classic bugs. Many real "custom auth"
 *    middlewares look exactly like this.
 */
export function insecureVerify(token: string): Claims {
  const [h, p, signature] = token.split(".");
  if (!h || !p) throw new Error("malformed token");

  const header = JSON.parse(Buffer.from(h, "base64url").toString());
  const payload = JSON.parse(Buffer.from(p, "base64url").toString()) as Claims & { exp?: number };

  // BUG #1 — "alg: none" is trusted: if the token says it isn't signed,
  //          we skip signature checking entirely and believe the payload.
  if (header.alg === "none") {
    return payload;
  }

  // BUG #2 — the algorithm is taken from the attacker-controlled header
  //          instead of being pinned by the server.
  // BUG #3 — ignoreExpiration:true means expired/replayed tokens still pass.
  //          (A real, common one-line misconfiguration.)
  jwt.verify(token, WEAK_SECRET, { algorithms: [header.alg], ignoreExpiration: true });

  // BUG #4 — the role is read straight from the token and trusted, never
  //          re-checked against the user store.
  return payload;
}

/* ──────────────────────────── SECURE WORLD ──────────────────────────── */

export function issueSecureToken(user: User): string {
  return jwt.sign(
    { username: user.username, role: user.role },
    STRONG_SECRET,
    {
      algorithm: "HS256",
      subject: user.id,
      issuer: ISSUER,
      audience: AUDIENCE,
      expiresIn: ACCESS_TTL_SECONDS, // short-lived
    },
  );
}

/**
 * ✅ Secure verification:
 *   - algorithms is PINNED to ['HS256'] → rejects "none" and algorithm confusion
 *   - issuer + audience are checked → a token from elsewhere won't do
 *   - expiry is enforced by jwt.verify (throws TokenExpiredError)
 *   - the role is re-read from the user store, never trusted from the token
 */
export function secureVerify(token: string): Claims {
  const decoded = jwt.verify(token, STRONG_SECRET, {
    algorithms: ["HS256"],
    issuer: ISSUER,
    audience: AUDIENCE,
  }) as jwt.JwtPayload;

  const user = findById(String(decoded.sub));
  if (!user) throw new Error("unknown subject");

  // Authorization comes from the server's source of truth, not the claim.
  return { sub: user.id, username: user.username, role: user.role };
}
