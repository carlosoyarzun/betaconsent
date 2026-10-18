// Gobierna: CA-124 (H09). Dobles mínimos de pg para tests unitarios (sin Postgres).

import { EventEmitter } from "node:events";
import type { PoolClient, QueryResult } from "pg";
import { BREAKGLASS_EXPECTED_FACTS } from "../../../src/infra/adapters/postgres/database-level.ts";

export interface RecordedQuery {
  text: string;
  values?: readonly unknown[];
}

export type Responder = (text: string, values?: readonly unknown[]) => Partial<QueryResult> | Error | undefined;

export class FakeClient extends EventEmitter {
  readonly queries: RecordedQuery[] = [];
  releases: Array<Error | boolean | undefined> = [];
  tenantSetting: string | null = null;
  private readonly responder: Responder;

  constructor(responder: Responder = () => undefined) {
    super();
    this.responder = responder;
  }

  async query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<QueryResult<R>> {
    this.queries.push(values === undefined ? { text } : { text, values });
    if (text.includes("current_setting('app.tenant_id'")) {
      return { rows: [{ tenant: this.tenantSetting }], rowCount: 1 } as unknown as QueryResult<R>;
    }
    const response = this.responder(text, values);
    if (response instanceof Error) throw response;
    // El runner toma sus locks con pg_try_advisory_lock (F-PR7D-09): por defecto el doble los concede.
    if (response === undefined && text.includes("pg_try_advisory_lock")) return { rows: [{ locked: true }], rowCount: 1 } as unknown as QueryResult<R>;
    return { rows: [], rowCount: 0, ...response } as unknown as QueryResult<R>;
  }

  release(destroy?: Error | boolean): void {
    this.releases.push(destroy);
  }

  asPoolClient(): PoolClient {
    return this as unknown as PoolClient;
  }
}

export function sqlError(code: string, message = "fallo simulado"): Error {
  return Object.assign(new Error(message), { code });
}

export function fakePool(clients: FakeClient[]): { connect(): Promise<PoolClient>; connects: number } {
  const state = {
    connects: 0,
    async connect(): Promise<PoolClient> {
      const next = clients[Math.min(state.connects, clients.length - 1)];
      state.connects += 1;
      if (next === undefined) throw new Error("sin clientes simulados");
      return next.asPoolClient();
    },
  };
  return state;
}

/**
 * ADR-010 rev. 6 PR-7d: respuestas "sanas" de checkDatabaseLevel (database-level.ts) para dobles que ya responden la aserción de membresía. Devuelve undefined si la consulta no es del estado a nivel de base.
 */
export function databaseLevelRows(text: string, mode: "IT0B_SYNTHETIC" | "REAL_DATA" = "IT0B_SYNTHETIC"): Partial<QueryResult> | undefined {
  if (text.includes("'schema|owner='")) return { rows: BREAKGLASS_EXPECTED_FACTS.map((fact) => ({ fact })) };
  if (text.includes("FROM pg_catalog.pg_db_role_setting s") && text.includes("for_role")) return { rows: [] };
  if (text.includes("AS datdba_name")) return { rows: [{ datdba_name: "db_owner_nologin", public_privileges: ["USAGE"], owner_create: mode === "IT0B_SYNTHETIC", missing_connect: null }] };
  if (text.includes("'db_owner_nologin', 'breakglass_log_owner', 'ddl_breakglass')")) {
    const base = { rolcanlogin: false, rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false, rolinherit: false, rolconnlimit: -1, rolconfig: null, members: 0 };
    return {
      rows: [
        { ...base, rolname: "db_owner_nologin" },
        { ...base, rolname: "breakglass_log_owner" },
        { ...base, rolname: "ddl_breakglass", rolconnlimit: 1, rolconfig: ["log_statement=ddl", "log_parameter_max_length=0", "log_parameter_max_length_on_error=0", "idle_in_transaction_session_timeout=10min"] },
      ],
    };
  }
  return undefined;
}
