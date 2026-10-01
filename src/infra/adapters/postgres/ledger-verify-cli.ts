// Gobierna: CA-128, DEC-BR-014 rev. 8 §3 X6 (subconjunto IT0 de ADR-011 / S4-16: recomputacion de
// la cadena SHA-256 por tenant). CLI LOCAL/CI del verificador:
//   CNS_ENVIRONMENT=LOCAL CNS_DATABASE_URL=postgresql://app_rw:...@localhost:PORT/DB \
//     node src/infra/adapters/postgres/ledger-verify-cli.ts <tenantId> [--expect-min-seq=N] [--expect-tail=<eventHash>]
// Conecta como el rol de runtime (app_rw, bajo RLS por tenant; nunca el migrador ni superusuario).
// Salida sin PII: conteos, chainSeq, eventHash de la cola y motivo. Exit: 0 integra, 2 cadena rota o
// expectativa incumplida, 1 error de uso/conexion.
//   --expect-min-seq=N     falla si la cola tiene chainSeq < N (detecta truncamiento de la cola con un valor
//                          recordado de una corrida anterior; sin ancla externa es el unico control, ADR-011).
//   --expect-tail=<hash>   falla si el eventHash de la cola no es exactamente ese.
// Tambien falla si existe una fila sin eslabon (chain_seq NULL) POSTERIOR al inicio de la cadena (primer eslabon
// del tenant): las anteriores a 0013 son legado fuera de la cadena (0013), las posteriores evaden el verificador.
// HMAC y ancla externa: ADR-011/DEC-BR-009 (fuera de IT0).

import { verifyChainRows } from "../../../server/modules/common/ledger-chain.ts";
import { createPool } from "./pool.ts";
import { PgUnitOfWork } from "./unit-of-work.ts";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const environment = process.env.CNS_ENVIRONMENT ?? "";
const url = process.env.CNS_DATABASE_URL;
const tenantId = process.argv[2] ?? "";
const flags = process.argv.slice(3);
const expectMinSeqRaw = flags.find((f) => f.startsWith("--expect-min-seq="))?.slice("--expect-min-seq=".length);
const expectTail = flags.find((f) => f.startsWith("--expect-tail="))?.slice("--expect-tail=".length);
const expectMinSeq = expectMinSeqRaw === undefined ? undefined : Number(expectMinSeqRaw);
const unknownFlag = flags.some((f) => !f.startsWith("--expect-min-seq=") && !f.startsWith("--expect-tail="));

if (environment !== "LOCAL" || !url || !UUID_RE.test(tenantId) || unknownFlag || (expectMinSeq !== undefined && !Number.isInteger(expectMinSeq)) || (expectTail !== undefined && !/^[0-9a-f]{64}$/.test(expectTail))) {
  console.error("Verificador del ledger: requiere CNS_ENVIRONMENT=LOCAL, CNS_DATABASE_URL (app_rw) y un tenantId UUID como argumento. Abortando.");
  process.exit(1);
}

const pool = createPool({ connectionString: url, max: 1, applicationName: "ledger-verify-cli" });
try {
  const uow = new PgUnitOfWork(pool);
  const { report, rows } = await uow.inTenant(tenantId, async ({ ledger }) => {
    const rows = await ledger.readChain(tenantId);
    return { report: verifyChainRows(rows), rows };
  });
  const unchainedAfterStart = await uow.withTenantTx(tenantId, async (tx) =>
    (await tx.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM integrity.audit_event
        WHERE tenant_id = $1 AND chain_seq IS NULL
          AND occurred_at > (SELECT min(occurred_at) FROM integrity.audit_event WHERE tenant_id = $1 AND chain_seq = 1)`,
      [tenantId],
    )).rows[0]?.n ?? 0,
  );
  const tail = rows[rows.length - 1];
  if (report.ok) {
    console.log(`Ledger verificado: ${report.verified} eslabones integros. cola: chainSeq=${tail?.chainSeq ?? 0} eventHash=${tail?.eventHash ?? "-"}`);
    const problems: string[] = [];
    if (expectMinSeq !== undefined && (tail?.chainSeq ?? 0) < expectMinSeq) problems.push(`cola chainSeq=${tail?.chainSeq ?? 0} < --expect-min-seq=${expectMinSeq} (posible truncamiento)`);
    if (expectTail !== undefined && tail?.eventHash !== expectTail) problems.push("eventHash de la cola distinto de --expect-tail");
    if (unchainedAfterStart > 0) problems.push(`${unchainedAfterStart} filas sin eslabon (chain_seq NULL) posteriores al inicio de la cadena`);
    if (problems.length > 0) {
      console.error(`Expectativas incumplidas: ${problems.join("; ")}.`);
      process.exitCode = 2;
    }
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
