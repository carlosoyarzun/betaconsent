// Gobierna: ADR-010 rev. 4 §7 fila PR-6 (entrypoint del proceso verifier; rol integrity_verifier, sin HTTP, sin escuchar puertos), INV-DBR-02, F-A10-23.
// Uso (LOCAL, datos sinteticos): CNS_ENVIRONMENT=LOCAL CNS_DATABASE_URL=postgresql://integrity_verifier:...@host:PORT/DB CNS_VERIFIER_ISSUER=... CNS_VERIFIER_AUDIENCE=...
//   CNS_VERIFIER_MAX_AUTH_AGE_SECONDS=N CNS_VERIFIER_SUB_HMAC_KEY_HEX=<64 hex> node src/server/entrypoints/verifier/main.ts
// Exit: 0 parada ordenada (SIGTERM/SIGINT), 1 arranque fallido o configuracion invalida (fail-closed; sin detalles ni secretos).

import { runVerifierLoop, startVerifierProcess } from "./verifier-process.ts";

try {
  const proc = await startVerifierProcess();
  const abort = new AbortController();
  for (const sig of ["SIGINT", "SIGTERM"] as const) process.once(sig, () => abort.abort());
  console.log("verifier: arrancado (rol integrity_verifier)");
  await runVerifierLoop(proc, abort.signal);
  await proc.stop();
} catch (error) {
  console.error(`verifier: no arranca (${(error as Error).name}). ${(error as Error).message}`);
  process.exitCode = 1;
}
