// Gobierna: ADR-010 rev. 6 §4.5.3, F-PR7-03, T-8 (plan PR-7 v3), C-9; PR-7e. Modo `breakglass-watch` del chain-verifier: una corrida por activacion del timer de 1 minuto (infra/systemd/consent-breakglass-watch.timer).
// Mismo rol (integrity_chain_verifier), sin egress, sin credencial nueva. Exit 0 sin hallazgos; 2 hallazgo (LOGIN o sesion de ddl_breakglass sin ceremonia vigente, o ceremonia vencida sin cerrar; la unidad OnFailure alerta);
// 1 arranque o lectura fallida (fail-closed). Log sin PII: solo codigos y la referencia opaca de la ceremonia.

import { readBreakglassSnapshot, evaluateBreakglass } from "../../../infra/adapters/postgres/breakglass-watch-reader.ts";
import type { BreakglassFinding } from "../../../infra/adapters/postgres/breakglass-watch-reader.ts";
import { openProcessPool, parseRuntimeEnvironment } from "../../../infra/adapters/postgres/runtime-process.ts";
import { parseChainVerifierConfig } from "./chain-verify-process.ts";

export const BREAKGLASS_WATCH_EXIT = { OK: 0, ERROR: 1, FINDING: 2 } as const;

export function formatBreakglassFindings(findings: readonly BreakglassFinding[]): string[] {
  if (findings.length === 0) return ["breakglass-watch: ok (sin LOGIN ni sesion de ddl_breakglass fuera de una ceremonia vigente)"];
  return findings.map((f) => `breakglass-watch: HALLAZGO ${f.code}${f.ceremonyRef === undefined ? "" : ` ceremonia=${f.ceremonyRef}`}`);
}

/** Una corrida. Misma configuracion y chequeos de arranque del chain-verifier (rol, sin CNS_VERIFIER_*). Devuelve los hallazgos; lanza ante un error. */
export async function runBreakglassWatch(env: Readonly<Record<string, string | undefined>> = process.env): Promise<BreakglassFinding[]> {
  parseChainVerifierConfig(env);
  const environment = parseRuntimeEnvironment(env.CNS_ENVIRONMENT);
  const pool = await openProcessPool({ process: "chain-verifier", environment, env, max: 1 });
  try {
    const client = await pool.connect();
    try {
      return evaluateBreakglass(await readBreakglassSnapshot(client));
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

export async function mainBreakglassWatch(): Promise<number> {
  try {
    const findings = await runBreakglassWatch();
    for (const line of formatBreakglassFindings(findings)) (findings.length === 0 ? console.log : console.error)(line);
    return findings.length === 0 ? BREAKGLASS_WATCH_EXIT.OK : BREAKGLASS_WATCH_EXIT.FINDING;
  } catch (error) {
    const e = error as { name?: unknown; code?: unknown };
    const name = typeof e.name === "string" && /^[A-Za-z]{1,40}$/.test(e.name) ? e.name : "Error";
    const errCode = typeof e.code === "string" && /^[A-Z0-9_]{1,40}$/.test(e.code) ? ` code=${e.code}` : "";
    console.error(`breakglass-watch: no verifica (name=${name}${errCode})`);
    return BREAKGLASS_WATCH_EXIT.ERROR;
  }
}
