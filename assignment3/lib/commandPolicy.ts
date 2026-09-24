/**
 * Command policy for the SECURE web CLI.
 *
 * Defence-in-depth layers applied here (all before any process is spawned):
 *   1. Length limit on the raw input.
 *   2. Character ALLOWLIST: only [A-Za-z0-9 space . _ - / : @ , =] may appear.
 *      Every shell metacharacter (; & | ` $ ( ) < > * ? ! ~ { } [ ] ' " \ newline ...)
 *      is rejected outright - we never try to "escape" or "clean" them.
 *   3. Command ALLOWLIST: the first token must be a known command.
 *   4. Per-command ARGUMENT validation: only known flags, bounded numbers,
 *      hostnames that match a strict pattern, and paths confined to the sandbox.
 *      This also blocks *argument injection* (e.g. smuggling "--some-flag").
 *   5. The result is a fixed binary + an argv ARRAY, later executed with
 *      execFile(shell: false), so no shell ever parses user input.
 */
import fs from "node:fs";
import path from "node:path";

export const MAX_INPUT_LENGTH = 200;
export const SANDBOX_DIR = path.resolve(process.cwd(), "sandbox");

const ALLOWED_CHARS = /^[A-Za-z0-9 ._\-/:@,=]*$/;
const HOSTNAME = /^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const IPV4 = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export type BuiltinName = "help" | "echo" | "date" | "clear";
export type ExternalName = "ls" | "cat" | "wc" | "ping" | "whoami" | "uptime";

export type ParsedCommand =
  | { kind: "builtin"; name: BuiltinName; args: string[] }
  | { kind: "external"; name: ExternalName; args: string[] };

export type PolicyResult =
  | { ok: true; command: ParsedCommand }
  | { ok: false; error: string; rule: string };

const deny = (rule: string, error: string): PolicyResult => ({ ok: false, rule, error });

/** Human-friendly name for the first forbidden character (for error messages only). */
function describeForbiddenChar(input: string): string {
  for (const ch of input) {
    if (!ALLOWED_CHARS.test(ch)) {
      const code = ch.codePointAt(0)!;
      return code < 32 || code === 127 ? `control character 0x${code.toString(16)}` : `'${ch}'`;
    }
  }
  return "unknown";
}

/**
 * Resolve a user-supplied path inside the sandbox.
 * Rejects absolute paths, "..", option-looking names, and symlink escapes.
 */
export function resolveSandboxPath(userPath: string, mustExist = true): string | null {
  if (userPath.startsWith("-")) return null; // would be read as an option
  if (path.isAbsolute(userPath)) return null;
  if (userPath.split("/").includes("..")) return null;

  const resolved = path.resolve(SANDBOX_DIR, userPath);
  if (resolved !== SANDBOX_DIR && !resolved.startsWith(SANDBOX_DIR + path.sep)) return null;

  if (!fs.existsSync(resolved)) return mustExist ? null : resolved;
  // Follow symlinks and check again, so a link like sandbox/x -> /etc cannot escape.
  const real = fs.realpathSync(resolved);
  const realSandbox = fs.realpathSync(SANDBOX_DIR);
  if (real !== realSandbox && !real.startsWith(realSandbox + path.sep)) return null;
  return real;
}

type Validator = (args: string[]) => PolicyResult;

function splitFlags(args: string[]) {
  const flags = args.filter((a) => a.startsWith("-"));
  const operands = args.filter((a) => !a.startsWith("-"));
  return { flags, operands };
}

function validatePaths(operands: string[], opts: { min: number; max: number; filesOnly: boolean }) {
  if (operands.length < opts.min) return { error: `expected at least ${opts.min} path(s)` };
  if (operands.length > opts.max) return { error: `at most ${opts.max} path(s) allowed` };
  const out: string[] = [];
  for (const p of operands) {
    const resolved = resolveSandboxPath(p);
    if (!resolved) return { error: `path '${p}' is outside the sandbox or does not exist` };
    if (opts.filesOnly && !fs.statSync(resolved).isFile()) return { error: `'${p}' is not a file` };
    // Pass paths relative to the sandbox (the process runs with cwd = sandbox).
    out.push(path.relative(fs.realpathSync(SANDBOX_DIR), resolved) || ".");
  }
  return { paths: out };
}

const noArgs =
  (name: ExternalName): Validator =>
  (args) =>
    args.length === 0
      ? { ok: true, command: { kind: "external", name, args: [] } }
      : deny("no-args", `'${name}' does not take any arguments`);

const VALIDATORS: Record<ExternalName, Validator> = {
  ls: (args) => {
    const allowed = new Set(["-l", "-a", "-la", "-al", "-h", "-lh", "-lah"]);
    const { flags, operands } = splitFlags(args);
    const bad = flags.find((f) => !allowed.has(f));
    if (bad) return deny("flag-allowlist", `flag '${bad}' is not allowed for ls`);
    const r = validatePaths(operands, { min: 0, max: 3, filesOnly: false });
    if ("error" in r) return deny("sandbox-path", r.error!);
    // "--" ends option parsing, so a path can never be misread as a flag.
    return { ok: true, command: { kind: "external", name: "ls", args: [...flags, "--", ...r.paths!] } };
  },

  cat: (args) => {
    const { flags, operands } = splitFlags(args);
    if (flags.length) return deny("flag-allowlist", "cat does not accept flags here");
    const r = validatePaths(operands, { min: 1, max: 3, filesOnly: true });
    if ("error" in r) return deny("sandbox-path", r.error!);
    return { ok: true, command: { kind: "external", name: "cat", args: ["--", ...r.paths!] } };
  },

  wc: (args) => {
    const allowed = new Set(["-l", "-w", "-c"]);
    const { flags, operands } = splitFlags(args);
    const bad = flags.find((f) => !allowed.has(f));
    if (bad) return deny("flag-allowlist", `flag '${bad}' is not allowed for wc`);
    const r = validatePaths(operands, { min: 1, max: 3, filesOnly: true });
    if ("error" in r) return deny("sandbox-path", r.error!);
    return { ok: true, command: { kind: "external", name: "wc", args: [...flags, "--", ...r.paths!] } };
  },

  ping: (args) => {
    // Accepted forms:  ping <host>   |   ping -c <1-4> <host>
    let count = 2;
    let rest = args;
    if (rest[0] === "-c") {
      const n = Number(rest[1]);
      if (!/^\d$/.test(rest[1] ?? "") || n < 1 || n > 4) return deny("bounded-number", "-c must be 1-4");
      count = n;
      rest = rest.slice(2);
    }
    if (rest.length !== 1) return deny("arg-shape", "usage: ping [-c 1-4] <hostname|ipv4>");
    const host = rest[0];
    if (host.startsWith("-") || !(IPV4.test(host) || HOSTNAME.test(host))) {
      return deny("hostname-format", `'${host}' is not a valid hostname or IPv4 address`);
    }
    return { ok: true, command: { kind: "external", name: "ping", args: ["-c", String(count), host] } };
  },

  whoami: noArgs("whoami"),
  uptime: noArgs("uptime"),
};

const BUILTINS = new Set<BuiltinName>(["help", "echo", "date", "clear"]);

export const HELP_TEXT = [
  "Available commands (secure mode):",
  "  help                      show this help",
  "  echo <text>               print text (handled in JavaScript, no process)",
  "  date                      server date/time",
  "  clear                     clear the screen",
  "  ls [-l|-a|-h...] [path]   list files inside the sandbox",
  "  cat <file>                print a sandbox file",
  "  wc [-l|-w|-c] <file>      count lines/words/bytes",
  "  ping [-c 1-4] <host>      ping a hostname or IPv4 address",
  "  whoami | uptime           system info",
].join("\n");

/** Validate raw user input and turn it into a safe, structured command. */
export function parseCommand(raw: unknown): PolicyResult {
  if (typeof raw !== "string") return deny("type", "command must be a string");
  const input = raw.trim();
  if (input.length === 0) return deny("empty", "empty command");
  if (input.length > MAX_INPUT_LENGTH) return deny("length", `command longer than ${MAX_INPUT_LENGTH} characters`);

  if (!ALLOWED_CHARS.test(input)) {
    return deny(
      "char-allowlist",
      `blocked: forbidden character ${describeForbiddenChar(input)} (shell metacharacters are not allowed)`,
    );
  }

  const [name, ...args] = input.split(/ +/);

  if (BUILTINS.has(name as BuiltinName)) {
    return { ok: true, command: { kind: "builtin", name: name as BuiltinName, args } };
  }
  if (Object.prototype.hasOwnProperty.call(VALIDATORS, name)) {
    return VALIDATORS[name as ExternalName](args);
  }
  return deny("command-allowlist", `command not allowed: '${name}'. Type 'help'.`);
}
