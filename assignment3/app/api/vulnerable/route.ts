/**
 * !!! INTENTIONALLY VULNERABLE - FOR EDUCATION ONLY !!!
 *
 * This endpoint shows the classic command-injection mistake:
 *   1. a naive "allowlist" that only checks the FIRST word, and
 *   2. exec() with a string, which runs through /bin/sh.
 * So "ls; whoami" passes the check (first word is "ls") and the shell then runs both.
 *
 * It is disabled unless ENABLE_VULNERABLE_DEMO=true, and never runs in production.
 * Never deploy this to a reachable server.
 */
import { NextResponse } from "next/server";
import { exec } from "node:child_process";
import path from "node:path";
import { audit, clientIp } from "@/lib/rateLimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const NAIVE_ALLOWED = ["help", "echo", "date", "ls", "cat", "wc", "ping", "whoami", "uptime"];

export async function POST(req: Request) {
  if (process.env.ENABLE_VULNERABLE_DEMO !== "true" || process.env.NODE_ENV === "production") {
    return NextResponse.json(
      { error: "Vulnerable demo is disabled. Start with `npm run dev:demo` to enable it locally." },
      { status: 403 },
    );
  }

  const { command } = (await req.json().catch(() => ({}))) as { command?: string };
  if (typeof command !== "string" || !command.trim()) {
    return NextResponse.json({ error: "empty command" }, { status: 400 });
  }

  // BAD: only the first word is checked.
  const first = command.trim().match(/^[a-z]+/)?.[0] ?? "";
  if (!NAIVE_ALLOWED.includes(first)) {
    return NextResponse.json({ blocked: true, error: `command not allowed: ${first}` }, { status: 400 });
  }
  if (first === "help") {
    return NextResponse.json({ stdout: `Allowed: ${NAIVE_ALLOWED.join(", ")}`, stderr: "", exitCode: 0 });
  }

  audit({ ip: clientIp(req), mode: "VULNERABLE", input: command });

  // BAD: string passed to exec() -> interpreted by a shell.
  return new Promise<Response>((resolve) => {
    exec(command, { cwd: path.resolve(process.cwd(), "sandbox"), timeout: 6000 }, (error, stdout, stderr) => {
      resolve(
        NextResponse.json({
          blocked: false,
          executed: { shellString: `/bin/sh -c "${command}"` },
          stdout: String(stdout),
          stderr: String(stderr),
          exitCode: error ? (typeof error.code === "number" ? error.code : 1) : 0,
        }),
      );
    });
  });
}
