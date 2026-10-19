// Gobierna: plan v2 H1-02. Uso: CNS_MIGRATOR_DATABASE_URL=postgresql://consent_migrator:...@host/consent npm run migrate
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import pg from "pg";

import { migrate } from "./migrate.ts";

const url = process.env.CNS_MIGRATOR_DATABASE_URL;
if (!url) {
  console.error("CNS_MIGRATOR_DATABASE_URL es obligatoria (credencial del migrador; nunca la del proceso web). Abortando.");
  process.exit(2);
}
const client = new pg.Client({ connectionString: url });
await client.connect();
try {
  const result = await migrate(client, join(dirname(fileURLToPath(import.meta.url)), "..", "..", "db", "migrations"));
  console.log(`aplicadas: ${result.applied.length} (${result.applied.join(", ") || "-"}); sin cambios: ${result.skipped.length}`);
} finally {
  await client.end();
}
