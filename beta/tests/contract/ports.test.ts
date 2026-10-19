// Gobierna: plan v2 H1-04. Ejecuta la suite de contrato contra el adaptador en memoria y contra el adaptador PG (Postgres temporal; TEST_DATABASE_URL).
import { randomBytes } from "node:crypto";
import { after, before, describe } from "node:test";

import { createMemoryPorts } from "../../src/db/adapters/memory/memory-ports.ts";
import { createPgPorts } from "../../src/db/adapters/index.ts";
import { createPool } from "../../src/db/pool.ts";
import { PgUnitOfWork } from "../../src/db/unit-of-work.ts";
import { migrate } from "../../src/db/migrate.ts";
import { connect, createTestDb, MIGRATIONS_DIR, type TestDb } from "../integration/pg-harness.ts";
import { runPortsContract } from "./ports.contract.ts";
import type { ContractEnv } from "./ports.contract.ts";

const otpSecret = randomBytes(32);

describe("contrato de puertos: memoria", () => {
  runPortsContract("memoria", async (): Promise<ContractEnv> => {
    let t = Date.now();
    const now = (): number => t;
    const ports = createMemoryPorts({ otpSecret, now });
    return {
      ports,
      now,
      advance: async function advanceFake(ms: number): Promise<void> {
        t += ms;
      },
    };
  });
});

describe("contrato de puertos: PostgreSQL", () => {
  let db: TestDb;
  let pool: ReturnType<typeof createPool>;
  let env: ContractEnv;

  before(async () => {
    db = await createTestDb();
    const m = await connect(db.migratorUrl);
    try {
      await migrate(m, MIGRATIONS_DIR);
    } finally {
      await m.end();
    }
    pool = createPool({ connectionString: db.appUrl, max: 4 });
    env = {
      ports: createPgPorts(new PgUnitOfWork(pool), { otpSecret }),
      now: () => Date.now(),
      advance: (ms) => new Promise((r) => setTimeout(r, ms)),
    };
  });
  after(async () => {
    await pool.end();
    await db.drop();
  });

  runPortsContract("postgres", async () => env);
});
