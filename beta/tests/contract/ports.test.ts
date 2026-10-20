// Gobierna: plan v2 H1-04. Ejecuta la suite de contrato contra el adaptador en memoria y contra el adaptador PG (Postgres temporal; TEST_DATABASE_URL).
import { after, before, describe } from "node:test";

import { createMemoryPorts } from "../../src/db/adapters/memory/memory-ports.ts";
import { createPgPorts } from "../../src/db/adapters/index.ts";
import { createPool } from "../../src/db/pool.ts";
import { PgUnitOfWork } from "../../src/db/unit-of-work.ts";
import { migrate } from "../../src/db/migrate.ts";
import { connect, connectAsOwner, createTestDb, MIGRATIONS_DIR, type TestDb } from "../integration/pg-harness.ts";
import { runPortsContract } from "./ports.contract.ts";
import type { ContractEnv } from "./ports.contract.ts";

describe("contrato de puertos: memoria", () => {
  runPortsContract("memoria", async (): Promise<ContractEnv> => {
    let t = Date.now();
    const now = (): number => t;
    const ports = createMemoryPorts({ now });
    return {
      ports,
      now,
      advance: async function advanceFake(ms: number): Promise<void> {
        t += ms;
      },
      expireOtp: async () => {
        t += 10 * 60_000 + 1000; // P-02: vence a los 10 min
      },
    };
  });
});

describe("contrato de puertos: PostgreSQL", () => {
  let db: TestDb;
  let pool: ReturnType<typeof createPool>;
  let mailerPool: ReturnType<typeof createPool>;
  let env: ContractEnv;
  let owner: Awaited<ReturnType<typeof connect>>;

  before(async () => {
    db = await createTestDb();
    const m = await connect(db.migratorUrl);
    try {
      await migrate(m, MIGRATIONS_DIR);
    } finally {
      await m.end();
    }
    owner = await connectAsOwner(db);
    pool = createPool({ connectionString: db.appUrl, max: 4 });
    mailerPool = createPool({ connectionString: db.mailerUrl, max: 2 });
    env = {
      ports: createPgPorts(new PgUnitOfWork(pool), { mailerUow: new PgUnitOfWork(mailerPool) }),
      now: () => Date.now(),
      advance: (ms) => new Promise((r) => setTimeout(r, ms)),
      // La base fija expires_at = now() + 10 min: para vencerlo se desactiva el guard del dueño solo dentro de la tx (igual que tests/integration/functions.test.ts).
      expireOtp: async (ref) => {
        await owner.query("BEGIN");
        try {
          await owner.query("ALTER TABLE app.otp_challenge DISABLE TRIGGER otp_challenge_ledger_guard");
          await owner.query("UPDATE app.otp_challenge SET expires_at = now() - interval '1 second', created_at = created_at - interval '2 hours' WHERE verification_ref = $1", [ref]);
          await owner.query("ALTER TABLE app.otp_challenge ENABLE ALWAYS TRIGGER otp_challenge_ledger_guard");
          await owner.query("COMMIT");
        } catch (e) {
          await owner.query("ROLLBACK");
          throw e;
        }
      },
    };
  });
  after(async () => {
    await owner.end();
    await pool.end();
    await mailerPool.end();
    await db.drop();
  });

  runPortsContract("postgres", async () => env);
});
