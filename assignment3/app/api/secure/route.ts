import { NextResponse } from "next/server";
import { parseCommand } from "@/lib/commandPolicy";
import { runCommand } from "@/lib/runner";
import { audit, clientIp, rateLimit } from "@/lib/rateLimit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const ip = clientIp(req);

  // Only accept JSON (also makes simple cross-site form posts fail).
  if (!req.headers.get("content-type")?.includes("application/json")) {
    return NextResponse.json({ error: "Content-Type must be application/json" }, { status: 415 });
  }

  const rl = rateLimit(ip);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: `Too many requests. Try again in ${rl.retryAfter}s.` },
      { status: 429, headers: { "Retry-After": String(rl.retryAfter) } },
    );
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  const raw = (body as { command?: unknown })?.command;

  const policy = parseCommand(raw);
  if (!policy.ok) {
    audit({ ip, mode: "secure", input: String(raw).slice(0, 200), decision: "blocked", rule: policy.rule });
    return NextResponse.json({ blocked: true, rule: policy.rule, error: policy.error }, { status: 400 });
  }

  audit({ ip, mode: "secure", input: raw, decision: "allowed", argv: [policy.command.name, ...policy.command.args] });
  const result = await runCommand(policy.command);
  return NextResponse.json({
    blocked: false,
    executed: { program: policy.command.name, argv: policy.command.args },
    ...result,
  });
}
