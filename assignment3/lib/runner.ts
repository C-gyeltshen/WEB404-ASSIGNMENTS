/**
 * Executes an already-validated command.
 *
 * Safeguards at execution time:
 *   - execFile with shell:false  -> arguments go straight to the program as argv,
 *     no shell ever interprets them, so ; | && $() etc. have no special meaning.
 *   - Absolute binary paths resolved once from trusted system dirs (no PATH hijacking).
 *   - Minimal environment, cwd locked to the sandbox, timeout, output size cap.
 */
import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { HELP_TEXT, SANDBOX_DIR, type ExternalName, type ParsedCommand } from "./commandPolicy";

const TRUSTED_DIRS = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"];
const TIMEOUT_MS = 6000;
const MAX_OUTPUT_BYTES = 64 * 1024;

const binaryCache = new Map<ExternalName, string | null>();

function resolveBinary(name: ExternalName): string | null {
  if (!binaryCache.has(name)) {
    const found = TRUSTED_DIRS.map((d) => path.join(d, name)).find((p) => {
      try {
        fs.accessSync(p, fs.constants.X_OK);
        return true;
      } catch {
        return false;
      }
    });
    binaryCache.set(name, found ?? null);
  }
  return binaryCache.get(name)!;
}

export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  clear?: boolean;
}

export async function runCommand(cmd: ParsedCommand): Promise<RunResult> {
  if (cmd.kind === "builtin") {
    switch (cmd.name) {
      case "help":
        return { stdout: HELP_TEXT, stderr: "", exitCode: 0 };
      case "echo":
        return { stdout: cmd.args.join(" "), stderr: "", exitCode: 0 };
      case "date":
        return { stdout: new Date().toString(), stderr: "", exitCode: 0 };
      case "clear":
        return { stdout: "", stderr: "", exitCode: 0, clear: true };
    }
  }

  const bin = resolveBinary(cmd.name);
  if (!bin) return { stdout: "", stderr: `${cmd.name}: not available on this server`, exitCode: 127 };

  return new Promise((resolve) => {
    execFile(
      bin,
      cmd.args,
      {
        shell: false,
        cwd: SANDBOX_DIR,
        timeout: TIMEOUT_MS,
        killSignal: "SIGKILL",
        maxBuffer: MAX_OUTPUT_BYTES,
        windowsHide: true,
        env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" } as unknown as NodeJS.ProcessEnv,
      },
      (error, stdout, stderr) => {
        let exitCode = 0;
        let err = String(stderr);
        if (error) {
          const e = error as NodeJS.ErrnoException & { code?: number | string; killed?: boolean };
          exitCode = typeof e.code === "number" ? e.code : 1;
          if (e.killed) err += `\n[killed: exceeded ${TIMEOUT_MS / 1000}s time limit]`;
          if (e.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") err += "\n[output truncated]";
        }
        resolve({ stdout: String(stdout), stderr: err.trim(), exitCode });
      },
    );
  });
}
