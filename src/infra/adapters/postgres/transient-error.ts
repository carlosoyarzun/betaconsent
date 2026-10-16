// Gobierna: ADR-010 rev. 5 (enmienda rev. c) §4.2.a punto 4 (G-3: reintentos acotados de la tx completa ante errores TRANSITORIOS: 40001, 40P01, 55P03; commit ambiguo = conexion perdida despues del COMMIT);
// src/server/modules/revocation/apply-guard.ts. ADR-001 §11: la clasificacion por SQLSTATE vive en infraestructura; el dominio solo recibe el predicado.

import { LedgerSequenceConflictError } from "../../../server/ports/ledger.port.ts";

const TRANSIENT_SQLSTATES: ReadonlySet<string> = new Set(["40001", "40P01", "55P03", "57P01", "57P02", "57P03"]);
const CONNECTION_MESSAGE = /connection terminated|connection.*(closed|reset|lost)|ECONNRESET|EPIPE|timeout exceeded when trying to connect/i;

/** true = transitorio o de commit ambiguo (se lee el estado antes de reintentar). Un guard de dominio, un rechazo de privilegio o un error de programa NO lo son. */
export function isTransientTxError(error: unknown): boolean {
  if (error instanceof LedgerSequenceConflictError) return true;
  const e = error as { code?: unknown; message?: unknown } | null;
  const code = typeof e?.code === "string" ? e.code : undefined;
  if (code !== undefined) return TRANSIENT_SQLSTATES.has(code) || code.startsWith("08") || code === "ECONNRESET" || code === "EPIPE";
  return error instanceof Error && CONNECTION_MESSAGE.test(error.message);
}
