// Gobierna: plan v2 H1-04. Traduce los errores de las funciones SQL de 0003 (SQLSTATE P0001, mensaje estable) a DomainError.
// Cualquier otro error (permisos, timeouts, conexión) se relanza tal cual: no se disfraza de error de dominio.
import { DOMAIN_ERROR_CODES, DomainError } from "../domain/errors.ts";
import type { DomainErrorCode } from "../domain/errors.ts";

const KNOWN = new Set<string>(DOMAIN_ERROR_CODES);

export function mapPgError(error: unknown): unknown {
  const e = error as { code?: unknown; message?: unknown } | null;
  if (e?.code === "P0001" && typeof e.message === "string" && KNOWN.has(e.message)) return new DomainError(e.message as DomainErrorCode);
  return error;
}

/** Ejecuta `work` y traduce el error. La transacción ya hizo ROLLBACK cuando el error llega aquí. */
export async function translating<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    throw mapPgError(error);
  }
}
