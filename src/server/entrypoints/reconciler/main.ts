// Gobierna: ADR-010 rev. 5 §2 (proceso `reconciler`, rol integrity_reconciler; G-9), §4.2.c (exit code != 0 ante divergencia, log sin PII), §10 fila 6e, INV-DBR-02, F-PR6-29.
// Uso (LOCAL, datos sinteticos): CNS_ENVIRONMENT=LOCAL CNS_DATABASE_URL=postgresql://integrity_reconciler:...@host:PORT/DB node src/server/entrypoints/reconciler/main.ts
// Una corrida por invocacion (la dispara el timer de systemd). Exit: 0 conciliado; 2 hay divergencias (ver el log, sin PII); 1 arranque fallido o error de lectura (fail-closed; sin detalles ni secretos).

import { exitCodeFor, formatReport, RECONCILER_EXIT, startReconcilerProcess } from "./reconciler-process.ts";

let code: number = RECONCILER_EXIT.ERROR;
try {
  const proc = await startReconcilerProcess();
  try {
    const report = await proc.run();
    for (const line of formatReport(report)) (report.ok ? console.log : console.error)(line);
    code = exitCodeFor(report);
  } finally {
    await proc.stop();
  }
} catch (error) {
  console.error(`reconciler: no concilia (${(error as Error).name}). ${(error as Error).message}`);
  code = RECONCILER_EXIT.ERROR;
}
process.exitCode = code;
