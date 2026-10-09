// Gobierna: SEC-CNS-021 PR-3 (aceptada por Carlos 2026-10-08; §4.3), P-34 (placeholder; LD-15 abierta), INV-21-07/08/10.
// CLI del job de retencion. Conectado como el rol `worker` (nunca el migrador ni un superusuario):
//   CNS_ENVIRONMENT=LOCAL|DEV|STAGING CNS_DATABASE_URL=postgresql://worker:...@host:PORT/DB \
//   CNS_RETENTION_SECURITY_EVENT_DAYS=N CNS_RETENTION_OTP_VERIFICATION_DAYS=N CNS_RETENTION_PURGE_RUN_DAYS=N \
//     node src/infra/adapters/postgres/retention-purge-cli.ts
// Salida: una linea por store con run_id y conteos (sin tenant_id, refs ni filas). Exit: 0 purga ok, 1 error/uso/arranque fallido,
// 3 DISABLED_LOCAL (LOCAL/DEV sin CNS_RETENTION_*: la purga queda deshabilitada). La programacion diaria (cron del host) va en la primera
// historia de infraestructura de IT0b.

import { loadRetentionConfig } from "../../../server/modules/common/retention.config.ts";
import { createPool } from "./pool.ts";
import { executeRetentionPurge, formatPurgeLine } from "./retention-purge.ts";
import { assertStartupChecks } from "./startup-checks.ts";

const environment = process.env.CNS_ENVIRONMENT ?? "";
const url = process.env.CNS_DATABASE_URL;
let user = "";
try {
  user = url === undefined ? "" : decodeURIComponent(new URL(url).username);
} catch {
  user = "";
}
if ((environment !== "LOCAL" && environment !== "DEV" && environment !== "STAGING") || !url || user !== "worker") {
  console.error("Purga de retencion: requiere CNS_ENVIRONMENT=LOCAL|DEV|STAGING y CNS_DATABASE_URL con el rol worker. Abortando.");
  process.exit(1);
}

let loaded;
try {
  loaded = loadRetentionConfig(process.env, environment);
} catch (error) {
  console.error((error as Error).message);
  process.exit(1);
}
if (loaded.status === "DISABLED_LOCAL") {
  console.log("DISABLED_LOCAL: sin CNS_RETENTION_*; la purga queda deshabilitada en este entorno.");
  process.exit(3);
}

const pool = createPool({ connectionString: url, max: 1, applicationName: "retention-purge-cli" });
try {
  const client = await pool.connect();
  try {
    await assertStartupChecks(client, { expectedEnvironment: environment, expectedRole: "worker", retention: loaded.config });
    for (const result of await executeRetentionPurge(client, loaded.config)) console.log(formatPurgeLine(result));
  } finally {
    client.release();
  }
} catch (error) {
  // Solo el nombre del error: el mensaje del servidor podria citar valores.
  console.error(`Purga de retencion fallo (${(error as Error).name}).`);
  process.exitCode = 1;
} finally {
  await pool.end();
}
