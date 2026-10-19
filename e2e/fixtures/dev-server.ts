// Arranque reproducible de `dev.ts` (LOCAL, store en memoria, datos sintéticos) en un puerto libre.
// No toca Postgres ni Docker: CONSENT_STORE=memory es el default de dev.ts y expone la misma superficie
// HTTP/UI que el modo postgres (la UI no distingue el store).
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "..", "..");

export interface DevServer {
  readonly baseURL: string;
  /** Ruta /i/<token> de la invitación sembrada por dev.ts (un solo canje). */
  readonly seededInvitationPath: string;
  /** Ruta /m/<token> sobre la decisión GRANTED sembrada. */
  readonly managementPath: string;
  stop(): Promise<void>;
}

function freePort(): Promise<number> {
  return new Promise((ok, fail) => {
    const srv = createServer();
    srv.once("error", fail);
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as { port: number }).port;
      srv.close(() => ok(port));
    });
  });
}

export async function startDevServer(extraEnv: Record<string, string> = {}): Promise<DevServer> {
  const port = await freePort();
  const child: ChildProcess = spawn(process.execPath, ["src/server/entrypoints/dev.ts"], {
    cwd: REPO_ROOT,
    env: {
      PATH: process.env.PATH ?? "",
      CNS_ENVIRONMENT: "LOCAL",
      PORT: String(port),
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stderr?.on("data", (d: Buffer) => { out += d.toString(); if (process.env.E2E_DEBUG) process.stderr.write(`[dev.ts] ${d}`); });
  const ready = new Promise<{ inv: string; mgmt: string }>((ok, fail) => {
    const timer = setTimeout(() => fail(new Error(`dev.ts no arrancó en 30 s:\n${out}`)), 30_000);
    child.once("exit", (code) => fail(new Error(`dev.ts terminó (code ${code}):\n${out}`)));
    child.stdout?.on("data", (d: Buffer) => {
      out += d.toString();
      const inv = /\/i\/([0-9a-f]{16,})/.exec(out);
      const mgmt = /\/m\/(dev-mgmt-token-\d+)/.exec(out);
      if (inv && mgmt) {
        clearTimeout(timer);
        ok({ inv: `/i/${inv[1]}`, mgmt: `/m/${mgmt[1]}` });
      }
    });
  });
  const { inv, mgmt } = await ready;
  return {
    baseURL: `http://127.0.0.1:${port}`,
    seededInvitationPath: inv,
    managementPath: mgmt,
    stop: () =>
      new Promise<void>((ok) => {
        if (child.exitCode !== null) return ok();
        child.once("exit", () => ok());
        child.kill("SIGTERM");
        setTimeout(() => child.kill("SIGKILL"), 3000).unref();
      }),
  };
}
