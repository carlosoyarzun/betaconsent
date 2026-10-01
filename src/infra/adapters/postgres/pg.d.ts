// Gobierna: CA-124 (H09), ADR-002 (PostgreSQL), ADR-001 §5 (sin @types/pg: minimizar dependencias).
//
// Declaración ambiente MÍNIMA de "pg" 8.23.0: solo la superficie que usan el adaptador
// Postgres (pool, unit-of-work, startup-checks) y los tests de integración. No es la
// definición completa del paquete; si hace falta más superficie, ampliar aquí (o pasar a
// @types/pg con su propia entrada en la allowlist). Reemplaza tests/integration/pg-minimal.d.ts.

declare module "pg" {
  export interface QueryResult<R = Record<string, unknown>> {
    rows: R[];
    rowCount: number | null;
  }

  export interface ClientConfig {
    connectionString?: string;
    application_name?: string;
    connectionTimeoutMillis?: number;
  }

  export interface PoolConfig extends ClientConfig {
    max?: number;
    idleTimeoutMillis?: number;
  }

  export class Client {
    constructor(config?: ClientConfig);
    connect(): Promise<void>;
    query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<QueryResult<R>>;
    end(): Promise<void>;
    escapeLiteral(value: string): string;
    escapeIdentifier(value: string): string;
    on(event: "error", listener: (error: Error) => void): this;
  }

  export interface PoolClient {
    query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<QueryResult<R>>;
    /** `true` (o un Error) destruye la conexión en vez de devolverla al pool. */
    release(destroy?: Error | boolean): void;
    /** pg-pool quita su listener de error al prestar el cliente; ver guardBorrowedClient (pool.ts). */
    on(event: "error", listener: (error: Error) => void): this;
    removeListener(event: "error", listener: (error: Error) => void): this;
  }

  export class Pool {
    constructor(config?: PoolConfig);
    connect(): Promise<PoolClient>;
    end(): Promise<void>;
    on(event: "error", listener: (error: Error) => void): this;
  }

  const pg: { Client: typeof Client; Pool: typeof Pool };
  export default pg;
}
