/**
 * Fires real malicious uploads at the running API and prints what happened.
 * Start the API first (npm run dev), then: npm run attack
 *
 * Every row should say BLOCKED, except the legitimate uploads and the two
 * "sanitised" cases (accepted, but made safe).
 */
import "dotenv/config";
import sharp from "sharp";

const API = process.env.API_URL ?? `http://localhost:${process.env.PORT ?? 8787}`;
const ORIGIN = process.env.FRONTEND_ORIGIN ?? "http://localhost:3000";
const PASSWORD = process.env.DEMO_PASSWORD ?? "SecureUpload-2026";
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: number, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);

async function login(username: string): Promise<string> {
  const res = await fetch(`${API}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: ORIGIN },
    body: JSON.stringify({ username, password: PASSWORD }),
  });
  if (!res.ok) throw new Error(`login ${username} failed: ${res.status}`);
  return res.headers.getSetCookie().map((h) => h.split(";")[0]).join("; ");
}

let rateLimitSeen = false;

async function upload(
  cookie: string | null, name: string, bytes: Buffer | string, type: string, origin = ORIGIN,
): Promise<{ status: number; body: { error?: string; file?: { id: string; name: string } } }> {
  const form = new FormData();
  form.append("file", new Blob([typeof bytes === "string" ? bytes : new Uint8Array(bytes)], { type }), name);
  const headers: Record<string, string> = { Origin: origin };
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(`${API}/files`, { method: "POST", headers, body: form });
  const body = (await res.json().catch(() => ({}))) as { error?: string; file?: { id: string; name: string } };

  // The API allows UPLOADS_PER_MINUTE per user. Record the first 429 as its
  // own result, then wait for the window to reset and retry the same attack.
  if (res.status === 429) {
    if (!rateLimitSeen) {
      rateLimitSeen = true;
      rows.push({ attack: "Upload flood (rate limit per user)", expect: "BLOCK", status: 429, result: body.error ?? "" });
    }
    const wait = Number(res.headers.get("retry-after") ?? 60);
    process.stderr.write(`  (rate limited, waiting ${wait}s before continuing...)\n`);
    await new Promise((r) => setTimeout(r, (wait + 1) * 1000));
    return upload(cookie, name, bytes, type, origin);
  }
  return { status: res.status, body };
}

// ----------------------------------------------------------------- payloads
const PHP = "<?php system($_GET['cmd']); ?>";
const png = await sharp({ create: { width: 64, height: 64, channels: 3, background: "#d33" } }).png().toBuffer();
const jpegWithGps = await sharp({ create: { width: 64, height: 64, channels: 3, background: "#39c" } })
  .jpeg()
  .withExif({ IFD0: { Make: "SecretPhoneMaker", Model: "GPS 27.47N 89.64E" } })
  .toBuffer();
const bomb = await sharp({ create: { width: 6000, height: 6000, channels: 3, background: "#000" } })
  .png({ compressionLevel: 9 })
  .toBuffer();
const pdf = (extra = "") =>
  `%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R ${extra} >> endobj\n2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n`;

type Row = { attack: string; expect: "BLOCK" | "ALLOW"; status: number; result: string };
const rows: Row[] = [];
const record = (attack: string, expect: Row["expect"], r: { status: number; body: { error?: string; file?: { name: string } } }) =>
  rows.push({ attack, expect, status: r.status, result: r.body.error ?? `stored as "${r.body.file?.name}"` });

const alice = await login("alice");
const bob = await login("bob");

record("Legitimate PNG", "ALLOW", await upload(alice, "holiday.png", png, "image/png"));
record("JPEG with EXIF/GPS (metadata stripped)", "ALLOW", await upload(alice, "photo.jpg", jpegWithGps, "image/jpeg"));
record("PHP web shell (shell.php)", "BLOCK", await upload(alice, "shell.php", PHP, "application/x-php"));
record("Spoofed Content-Type: image/png", "BLOCK", await upload(alice, "shell.png", PHP, "image/png"));
record("Double extension (shell.php.png)", "BLOCK", await upload(alice, "shell.php.png", png, "image/png"));
record("Case trick (shell.PhP)", "BLOCK", await upload(alice, "shell.PhP", PHP, "image/png"));
record("Trailing dot (shell.php.)", "BLOCK", await upload(alice, "shell.php.", PHP, "image/png"));
record("Null byte (shell.php%00.png)", "BLOCK", await upload(alice, "shell.php\0.png", png, "image/png"));
record("GIF89a header + PHP payload", "BLOCK", await upload(alice, "avatar.gif", `GIF89a;${PHP}`, "image/gif"));
record("Polyglot: real PNG + appended PHP", "BLOCK", await upload(alice, "cat.png", Buffer.concat([png, Buffer.from(PHP)]), "image/png"));
record("SVG with <script> (stored XSS)", "BLOCK", await upload(alice, "logo.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml"));
record("HTML page (stored XSS)", "BLOCK", await upload(alice, "page.html", "<script>alert(document.cookie)</script>", "text/html"));
record(".htaccess (server config override)", "BLOCK", await upload(alice, ".htaccess", "AddType application/x-httpd-php .png", "text/plain"));
record("PDF with JavaScript", "BLOCK", await upload(alice, "invoice.pdf", pdf("/OpenAction << /S /JavaScript /JS (app.alert(1)) >>"), "application/pdf"));
record("PDF hex-obfuscated (/J#61vaScript)", "BLOCK", await upload(alice, "invoice2.pdf", pdf("/Names << /J#61vaScript 3 0 R >>"), "application/pdf"));
record("Decompression bomb (36 MP PNG)", "BLOCK", await upload(alice, "bomb.png", bomb, "image/png"));
record("Oversized file (6 MB)", "BLOCK", await upload(alice, "big.png", Buffer.concat([png, Buffer.alloc(6 * 1024 * 1024)]), "image/png"));
record("Path traversal (../../../etc/x.png)", "ALLOW", await upload(alice, "../../../etc/x.png", png, "image/png"));
record("No session cookie (anonymous)", "BLOCK", await upload(null, "a.png", png, "image/png"));
record("CSRF: Origin https://evil.example", "BLOCK", await upload(alice, "a.png", png, "image/png", "https://evil.example"));

// IDOR: bob asks for a download URL for alice's file
const aliceFile = await upload(alice, "private.png", png, "image/png");
const idor = await fetch(`${API}/files/${aliceFile.body.file!.id}/download-url`, { headers: { Cookie: bob, Origin: ORIGIN } });
rows.push({ attack: "IDOR: bob downloads alice's file", expect: "BLOCK", status: idor.status, result: ((await idor.json()) as { error: string }).error });

// ------------------------------------------------------------------- report
const w = Math.max(...rows.map((r) => r.attack.length));
console.log(`\n${c(1, "Attack".padEnd(w))}  ${c(1, "HTTP")}  ${c(1, "Outcome")}   ${c(1, "Server response")}`);
console.log("-".repeat(w + 80));
let failures = 0;
for (const r of rows) {
  const blocked = r.status >= 400;
  const ok = (r.expect === "BLOCK") === blocked;
  if (!ok) failures++;
  const outcome = blocked ? c(32, "BLOCKED ") : ok ? c(36, "ACCEPTED") : c(31, "BYPASSED");
  console.log(`${r.attack.padEnd(w)}  ${String(r.status).padEnd(4)}  ${outcome}  ${r.result}`);
}
console.log(`\n${failures === 0 ? c(32, `All ${rows.length} checks behaved as expected.`) : c(31, `${failures} unexpected result(s)!`)}\n`);
process.exit(failures ? 1 : 0);
