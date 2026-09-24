"use client";

import { useEffect, useRef, useState, type KeyboardEvent } from "react";

type Mode = "secure" | "vulnerable";
type Line = { kind: "prompt" | "out" | "err" | "blocked" | "meta"; text: string };

const SAFE_EXAMPLES = ["help", "ls -l", "cat notes.txt", "wc -l notes.txt", "ls docs", "ping -c 1 127.0.0.1", "whoami"];
const ATTACKS = [
  "ls; whoami",
  "cat notes.txt && id",
  "ls | cat /etc/passwd",
  "echo $(whoami)",
  "echo `id`",
  "cat ../../../../etc/passwd",
  "ping 127.0.0.1; uname -a",
  "ls --color=always /",
];

export default function Home() {
  const [mode, setMode] = useState<Mode>("secure");
  const [lines, setLines] = useState<Line[]>([{ kind: "meta", text: "Secure Web CLI - type 'help' to begin." }]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const termRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    termRef.current?.scrollTo({ top: termRef.current.scrollHeight });
  }, [lines]);

  const append = (...l: Line[]) => setLines((prev) => [...prev, ...l]);

  async function run(command: string) {
    const cmd = command.trim();
    if (!cmd || busy) return;
    append({ kind: "prompt", text: `${mode === "secure" ? "secure" : "VULN"}$ ${cmd}` });
    setHistory((h) => [cmd, ...h].slice(0, 50));
    setHistIdx(-1);
    setInput("");
    setBusy(true);
    try {
      const res = await fetch(`/api/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command: cmd }),
      });
      const data = await res.json();
      if (data.clear) {
        setLines([]);
      } else if (data.blocked) {
        append({ kind: "blocked", text: `⛔ ${data.error}${data.rule ? `  [rule: ${data.rule}]` : ""}` });
      } else if (data.error) {
        append({ kind: "err", text: data.error });
      } else {
        if (data.executed?.argv) append({ kind: "meta", text: `execFile(${JSON.stringify([data.executed.program, ...data.executed.argv])}, shell: false)` });
        if (data.executed?.shellString) append({ kind: "meta", text: `exec → ${data.executed.shellString}` });
        if (data.stdout) append({ kind: "out", text: data.stdout.replace(/\n$/, "") });
        if (data.stderr) append({ kind: "err", text: data.stderr });
      }
    } catch {
      append({ kind: "err", text: "Network error" });
    } finally {
      setBusy(false);
      inputRef.current?.focus();
    }
  }

  function onKey(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") run(input);
    else if (e.key === "ArrowUp" && history.length) {
      e.preventDefault();
      const i = Math.min(histIdx + 1, history.length - 1);
      setHistIdx(i);
      setInput(history[i]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const i = histIdx - 1;
      setHistIdx(i);
      setInput(i >= 0 ? history[i] : "");
    } else if (e.key === "l" && e.ctrlKey) {
      e.preventDefault();
      setLines([]);
    }
  }

  return (
    <main>
      <h1>Web Command-Line Interface</h1>
      <p className="sub">Compare a hardened command endpoint with a deliberately vulnerable one.</p>

      <div className="tabs">
        <button className={`tab secure ${mode === "secure" ? "active" : ""}`} onClick={() => setMode("secure")}>
          🔒 Secure mode
        </button>
        <button className={`tab vuln ${mode === "vulnerable" ? "active" : ""}`} onClick={() => setMode("vulnerable")}>
          ⚠️ Vulnerable demo
        </button>
      </div>

      {mode === "secure" ? (
        <div className="banner secure">
          Input is checked against a character allowlist, a command allowlist and per-command argument rules, then run
          with <code>execFile</code> and <code>shell: false</code>. Paths are locked to the <code>sandbox/</code> folder.
        </div>
      ) : (
        <div className="banner vuln">
          Checks only the first word, then passes the whole string to <code>exec()</code>, which runs it through{" "}
          <code>/bin/sh</code>. Try the attack payloads below to see injection succeed. Enabled only with{" "}
          <code>npm run dev:demo</code>, and never in production.
        </div>
      )}

      <div className="term" ref={termRef} onClick={() => inputRef.current?.focus()}>
        {lines.map((l, i) => (
          // React escapes text content, so command output can't inject HTML (no XSS).
          <p key={i} className={`line ${l.kind === "prompt" ? "prompt" : l.kind === "out" ? "" : l.kind}`}>
            {l.text}
          </p>
        ))}
        <div className="inputrow">
          <span className="prompt">{mode === "secure" ? "secure$" : "VULN$"}</span>
          <input
            ref={inputRef}
            value={input}
            maxLength={200}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKey}
            disabled={busy}
            autoFocus
            spellCheck={false}
            autoComplete="off"
            aria-label="Command input"
          />
        </div>
      </div>

      <div className="payloads">
        <h2>Safe commands</h2>
        <div className="chips">
          {SAFE_EXAMPLES.map((c) => (
            <button key={c} className="chip" onClick={() => run(c)}>{c}</button>
          ))}
        </div>
      </div>
      <div className="payloads">
        <h2>Injection payloads (try them in both modes)</h2>
        <div className="chips">
          {ATTACKS.map((c) => (
            <button key={c} className="chip attack" onClick={() => run(c)}>{c}</button>
          ))}
        </div>
      </div>
    </main>
  );
}
