// Gobierna: plan v2 H1-06 (allowlist de destinatarios mientras el catálogo sea SYNTHETIC) + DEC "correo real solo a destinatarios de prueba".
// data_class se lee UNA vez al arrancar desde ops.db_catalog. SYNTHETIC => solo se envía a la allowlist; REAL => la allowlist se ignora.

export type DataClass = "SYNTHETIC" | "REAL";

export interface RecipientPolicy {
  readonly dataClass: DataClass;
  /** Entradas `correo@dominio` o `@dominio`, en minúsculas. */
  readonly allowlist: readonly string[];
}

export const SUPPRESSED_REASON = "SUPPRESSED_ALLOWLIST";

export interface Queryable {
  query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<{ rows: R[] }>;
}

export async function readDataClass(db: Queryable): Promise<DataClass> {
  const { rows } = await db.query<{ data_class: string }>("SELECT data_class FROM ops.db_catalog");
  const v = rows.length === 1 ? rows[0]?.data_class : undefined;
  if (v !== "SYNTHETIC" && v !== "REAL") throw new Error("ops.db_catalog debe tener una fila con data_class SYNTHETIC o REAL. Abortando (fail-closed).");
  return v;
}

export function isRecipientAllowed(to: string, policy: RecipientPolicy): boolean {
  if (policy.dataClass === "REAL") return true;
  const addr = to.trim().toLowerCase();
  const at = addr.lastIndexOf("@");
  if (at < 1) return false;
  const domain = addr.slice(at);
  return policy.allowlist.some((e) => e === addr || (e.startsWith("@") && e === domain));
}
