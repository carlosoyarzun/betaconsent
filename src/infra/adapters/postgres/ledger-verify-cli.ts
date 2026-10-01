// Gobierna: CA-128, DEC-BR-014 rev. 8 §3 X6 (subconjunto IT0 de ADR-011 / S4-16: recomputacion de
// la cadena SHA-256 por tenant). CLI LOCAL/CI del verificador:
//   CNS_ENVIRONMENT=LOCAL CNS_DATABASE_URL=postgresql://app_rw:...@localhost:PORT/DB \
//     node src/infra/adapters/postgres/ledger-verify-cli.ts <tenantId>
// Conecta como el rol de runtime (app_rw, bajo RLS por tenant; nunca el migrador ni superusuario).
// Salida sin PII: solo conteos, chainSeq y motivo. Exit: 0 integra, 2 cadena rota, 1 error de uso/conexion.
// HMAC y ancla externa: ADR-011/DEC-BR-009 (fuera de IT0).

import { verifyLedgerChain } from "../../../server/modules/common/ledger-chain.ts";
import { createPool } from "./pool.ts";
import { PgUnitOfWork } from "./unit-of-work.ts";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const environment = process.env.CNS_ENVIRONMENT ?? "";
const url = process.env.CNS_DATABASE_URL;
const tenantId = process.argv[2] ?? "";

if (environment !== "LOCAL" || !url || !UUID_RE.test(tenantId)) {
  console.error("Verificador del ledger: requiere CNS_ENVIRONMENT=LOCAL, CNS_DATABASE_URL (app_rw) y un tenantId UUID como argumento. Abortando.");
  process.exit(1);
}

const pool = createPool({ connectionString: url, max: 1, applicationName: "ledger-verify-cli" });
try {
  const uow = new PgUnitOfWork(pool);
  const report = await uow.inTenant(tenantId, ({ ledger }) => verifyLedgerChain(ledger, tenantId));
  if (report.ok) {
    console.log(`Ledger verificado: ${report.verified} eslabones integros.`);
  } else {
    const b = report.brokenAt;
    console.error(`Cadena ROTA en chainSeq=${b.chainSeq} (agregado sequence=${b.sequence}): ${b.reason}; ${report.verified} eslabones previos integros.`);
    process.exitCode = 2;
  }
} catch (error) {
  console.error(`Verificador del ledger fallo (${(error as Error).name}).`);
  process.exitCode = 1;
} finally {
  await pool.end();
}
