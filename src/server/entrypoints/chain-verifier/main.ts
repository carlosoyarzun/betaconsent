// Gobierna: ADR-010 rev. 6 §1-§2 (proceso `chain-verifier`, rol integrity_chain_verifier; exit 0/2/1, log sin PII), §3 fila PR-6f, F-PR6E-06, INV-DBR-02.
// Uso (LOCAL, datos sinteticos): CNS_ENVIRONMENT=LOCAL CNS_DATABASE_URL=postgresql://integrity_chain_verifier:...@host:PORT/DB node src/server/entrypoints/chain-verifier/main.ts
// Una corrida por invocacion (la dispara el timer de systemd). Exit: 0 cadena integra en todos los tenants; 2 algun tenant roto o con filas sin eslabon (ver el log, sin PII);
// 1 arranque, configuracion, precondicion (policy/FORCE RLS/privilegios), lectura, o ledger vacio (fail-closed; sin detalles ni secretos).

import { CHAIN_VERIFIER_EXIT, exitCodeFor, formatChainReport, startChainVerifierProcess } from "./chain-verify-process.ts";

let code: number = CHAIN_VERIFIER_EXIT.ERROR;
try {
  const proc = await startChainVerifierProcess();
  try {
    // El reporte se imprime antes de persistir (P2-2); si la persistencia falla con anomalias el exit sigue siendo 2.
    const report = await proc.run({ onReport: (r) => { for (const line of formatChainReport(r)) (r.ok ? console.log : console.error)(line); } });
    code = exitCodeFor(report);
  } finally {
    await proc.stop();
  }
} catch (error) {
  // Solo nombre y codigo (P2-6, seguridad PR #99): el message de un error de pg/de la URL puede llevar host, usuario o fragmentos de datos. Ambos pasan por allowlist.
  const e = error as { name?: unknown; code?: unknown };
  const name = typeof e.name === "string" && /^[A-Za-z]{1,40}$/.test(e.name) ? e.name : "Error";
  const errCode = typeof e.code === "string" && /^[A-Z0-9_]{1,40}$/.test(e.code) ? ` code=${e.code}` : "";
  console.error(`chain-verifier: no verifica (name=${name}${errCode})`);
  code = CHAIN_VERIFIER_EXIT.ERROR;
}
process.exitCode = code;
