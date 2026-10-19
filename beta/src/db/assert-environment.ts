// Gobierna: plan v2 H1-01 ("el arranque aborta si el entorno != catálogo"). Único gate de entorno:
// no hay CHECK data_class='SYNTHETIC' por tabla, el catálogo ops.db_catalog es la fuente.

import type { Config } from "../config.ts";

/** Superficie mínima de consulta (Pool, Client o PoolClient de pg). */
export interface Queryable {
  query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<{ rows: R[] }>;
}

export class EnvironmentMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvironmentMismatchError";
  }
}

/**
 * Compara CNS_ENVIRONMENT con la fila única de ops.db_catalog. LOCAL exige data_class SYNTHETIC y REAL exige data_class REAL.
 * Aborta (lanza) ante cualquier diferencia o si el catálogo no tiene exactamente una fila.
 */
export async function assertEnvironment(db: Queryable, config: Pick<Config, "environment">): Promise<void> {
  const { rows } = await db.query<{ environment: string; data_class: string }>("SELECT environment, data_class FROM ops.db_catalog");
  if (rows.length !== 1 || rows[0] === undefined) throw new EnvironmentMismatchError("ops.db_catalog debe tener exactamente una fila. Abortando (fail-closed).");
  const { environment, data_class } = rows[0];
  const expectedClass = config.environment === "LOCAL" ? "SYNTHETIC" : "REAL";
  if (environment !== config.environment || data_class !== expectedClass) {
    throw new EnvironmentMismatchError(
      `CNS_ENVIRONMENT=${config.environment} no coincide con el catálogo de la base (environment=${environment}, data_class=${data_class}). Abortando (fail-closed).`,
    );
  }
}
