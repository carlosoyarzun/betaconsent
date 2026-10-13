// Gobierna: ADR-010 rev. 4 §7 fila PR-6 (entrypoint del proceso web; rol app_rw), INV-DBR-02 (web = app_rw). Hasta que exista un servidor web fuera de LOCAL (no hay produccion
// ni staging aprovisionados, DEC-BR-014), el unico servidor web es el de dev.ts (LOCAL, datos sinteticos): este entrypoint fija el contrato de proceso (rol por URL ANTES de cualquier
// otra cosa; el pool de app_rw lo abre openPostgresStore con expectedRole = app_rw) y delega en dev.ts, que a su vez aborta si CNS_ENVIRONMENT != LOCAL.
// Uso: CNS_ENVIRONMENT=LOCAL [CONSENT_STORE=postgres CNS_DATABASE_URL=postgresql://app_rw:...@host:PORT/DB] node src/server/entrypoints/web/main.ts

import { parseRuntimeEnvironment, readProcessDatabaseUrl } from "../../../infra/adapters/postgres/runtime-process.ts";

try {
  parseRuntimeEnvironment(process.env.CNS_ENVIRONMENT);
  // Con store Postgres el proceso web solo puede conectar como app_rw (no platform_rw, worker ni integrity_verifier).
  if (process.env.CONSENT_STORE === "postgres") readProcessDatabaseUrl("web", process.env);
} catch (error) {
  console.error(`web: no arranca (${(error as Error).name}). ${(error as Error).message}`);
  process.exit(1);
}
await import("../dev.ts");
