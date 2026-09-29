// Gobierna: CA-124 (H09). Dobles mínimos de pg para tests unitarios (sin Postgres).

import type { PoolClient, QueryResult } from "pg";

export interface RecordedQuery {
  text: string;
  values?: readonly unknown[];
}

export type Responder = (text: string, values?: readonly unknown[]) => Partial<QueryResult> | Error | undefined;

export class FakeClient {
  readonly queries: RecordedQuery[] = [];
  releases: Array<Error | boolean | undefined> = [];
  tenantSetting: string | null = null;
  private readonly responder: Responder;

  constructor(responder: Responder = () => undefined) {
    this.responder = responder;
  }

  async query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<QueryResult<R>> {
    this.queries.push(values === undefined ? { text } : { text, values });
    if (text.includes("current_setting('app.tenant_id'")) {
      return { rows: [{ tenant: this.tenantSetting }], rowCount: 1 } as unknown as QueryResult<R>;
    }
    const response = this.responder(text, values);
    if (response instanceof Error) throw response;
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
