// Gobierna: ADR-010 rev. 4 §7 fila PR-6 (entrypoint del proceso worker; rol `worker`, sin HTTP, sin escuchar puertos), INV-DBR-02, GRD-CM-15 (R5-R7 solo worker).
// Uso (LOCAL, datos sinteticos): CNS_ENVIRONMENT=LOCAL CNS_DATABASE_URL=postgresql://worker:...@host:PORT/DB node src/server/entrypoints/worker/main.ts
// Exit: 0 parada ordenada (SIGTERM/SIGINT), 1 arranque fallido (fail-closed; sin detalles ni secretos).

import { runWorkerLoop, startWorkerProcess } from "./worker-process.ts";

try {
  const proc = await startWorkerProcess();
  const abort = new AbortController();
  for (const sig of ["SIGINT", "SIGTERM"] as const) process.once(sig, () => abort.abort());
  console.log("worker: arrancado (rol worker)");
  await runWorkerLoop(proc, abort.signal);
  await proc.stop();
} catch (error) {
  console.error(`worker: no arranca (${(error as Error).name}). ${(error as Error).message}`);
  process.exitCode = 1;
}
