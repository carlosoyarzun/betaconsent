// Gobierna: ADR-010 rev. 6 §1-§3 (fila PR-6f: aserciones C5/C6/C13 al arrancar; fila PR-7: checkpoints), F-PR6E-05, SEC-06-3; db/migrations/0072-0073 y 0076; specs/db-roles.spec.yaml (integrity_chain_verifier).
//
// Precondiciones del proceso `chain-verifier` (error de precondicion con enum fijo y aserciones sobre las tablas de checkpoints). Se separan del lector (chain-verifier-reader.ts), cuyo texto un test (TEST-CNS-1754)
// exige sin DML ni DDL: aqui se NOMBRAN privilegios de escritura solo para comprobar que existen (has_*_privilege), nunca se escribe. Todo valor variable va como parametro $n.
// ADAPTADOR (ADR-001 §11).

import type { Queryable } from "./pool.ts";

export type ChainPreconditionCode =
  | "READ_ONLY_NOT_ENFORCED"
  | "POLICY_MISSING_OR_ALTERED"
  | "RLS_NOT_FORCED"
  | "COLUMN_PRIVILEGE_MISSING"
  | "CATALOG_UNREADABLE"
  | "CHECKPOINT_POLICY_MISSING_OR_ALTERED"
  | "CHECKPOINT_PRIVILEGE_MISSING";

/** Una precondicion de lectura no se cumple (policy/FORCE RLS/privilegios/solo lectura). Fail-closed: el proceso sale con exit 1. El mensaje es un enum fijo: sin datos ni nombres de filas. */
export class ChainVerifierPreconditionError extends Error {
  readonly code: ChainPreconditionCode;
  constructor(code: ChainPreconditionCode) {
    super(`precondicion de lectura de la cadena incumplida: ${code}`);
    this.name = "ChainVerifierPreconditionError";
    this.code = code;
  }
}

interface PolicyRow {
  polname: string;
  polcmd: string;
  permissive: boolean;
  qual: string | null;
  has_check: boolean;
  roles: string[];
}

/**
 * PR-7b: las tablas de checkpoints deben estar como las dejo 0076 (policies exactas que alcanzan al rol, FORCE RLS y privilegios). Sin esto, una policy de SELECT borrada dejaria al proceso viendo 0 checkpoints
 * (y la deteccion de truncamiento de cola en verde falso) y un INSERT sin policy fallaria recien al escribir. Todo es legible por PUBLIC (pg_policy, pg_class, has_*_privilege).
 */
export async function assertCheckpointWritable(db: Queryable): Promise<void> {
  const rows = async (table: string): Promise<PolicyRow[]> =>
    (
      await db.query<PolicyRow>(
        `SELECT p.polname::text AS polname, p.polcmd::text AS polcmd, p.polpermissive AS permissive, pg_catalog.pg_get_expr(p.polqual, p.polrelid) AS qual, p.polwithcheck IS NOT NULL AS has_check,
                ARRAY(SELECT CASE WHEN r = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(r)::text END FROM pg_catalog.unnest(p.polroles) AS r) AS roles
           FROM pg_catalog.pg_policy p
          WHERE p.polrelid = $1::pg_catalog.regclass AND (0::pg_catalog.oid = ANY (p.polroles) OR (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) = ANY (p.polroles))
          ORDER BY p.polname::text`,
        [table],
      )
    ).rows;
  const only = (p: PolicyRow | undefined, name: string, cmd: string, qual: string | null, check: boolean): boolean =>
    p !== undefined && p.polname === name && p.polcmd === cmd && p.permissive && p.qual === qual && p.has_check === check && p.roles.length === 1 && p.roles[0] === "integrity_chain_verifier";
  const ckp = await rows("integrity.chain_checkpoint");
  const run = await rows("integrity.chain_run");
  if (
    ckp.length !== 2 || !only(ckp[0], "chain_checkpoint_verifier_insert", "a", null, true) || !only(ckp[1], "chain_checkpoint_verifier_select", "r", "true", false) ||
    run.length !== 1 || !only(run[0], "chain_run_verifier_insert", "a", null, true)
  ) {
    throw new ChainVerifierPreconditionError("CHECKPOINT_POLICY_MISSING_OR_ALTERED");
  }
  const rls = await db.query<{ ok: boolean }>(
    `SELECT pg_catalog.bool_and(c.relrowsecurity AND c.relforcerowsecurity) AS ok FROM pg_catalog.pg_class c WHERE c.oid IN ('integrity.chain_checkpoint'::pg_catalog.regclass, 'integrity.chain_run'::pg_catalog.regclass)`,
  );
  if (rls.rows[0]?.ok !== true) throw new ChainVerifierPreconditionError("RLS_NOT_FORCED");
  const priv = await db.query<{ ok: boolean }>(
    `SELECT pg_catalog.has_table_privilege(current_user, 'integrity.chain_checkpoint'::pg_catalog.regclass, 'SELECT')
        AND pg_catalog.has_column_privilege(current_user, 'integrity.chain_checkpoint'::pg_catalog.regclass, 'head_event_hash', 'INSERT')
        AND pg_catalog.has_column_privilege(current_user, 'integrity.chain_run'::pg_catalog.regclass, 'merkle_root', 'INSERT') AS ok`,
  );
  if (priv.rows[0]?.ok !== true) throw new ChainVerifierPreconditionError("CHECKPOINT_PRIVILEGE_MISSING");
}
