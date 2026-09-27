// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), JIRA CA-118 (H03).
//
// Declaración ambiente MÍNIMA de "pg" (solo lo que usa postgres-smoke.test.ts), para
// evitar la dependencia @types/pg (ADR-001 §5: minimizar dependencias directas). No es
// una definición completa del paquete; si un test futuro necesita más superficie de
// "pg", ampliar aquí (o pasar a @types/pg con su propia entrada en el allowlist).

declare module "pg" {
  export interface ClientConfig {
    connectionString?: string;
  }

  export interface QueryResult<T = Record<string, unknown>> {
    rows: T[];
  }

  export class Client {
    constructor(config?: ClientConfig);
    connect(): Promise<void>;
    query<T = Record<string, unknown>>(text: string): Promise<QueryResult<T>>;
    end(): Promise<void>;
  }

  const pg: { Client: typeof Client };
  export default pg;
}
