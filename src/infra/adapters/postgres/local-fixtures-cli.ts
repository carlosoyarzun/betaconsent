// Gobierna: CA-124 (H09), SEC-CNS-017 finding (c). CLI LOCAL-only del paso de fixtures:
//   CNS_ENVIRONMENT=LOCAL CNS_MIGRATOR_DATABASE_URL=postgresql://consent_migrator:...@localhost:PORT/DB \
//     node src/infra/adapters/postgres/local-fixtures-cli.ts
// La credencial del migrador solo por entorno y solo existe en este paso (nunca en el proceso web).

import pg from "pg";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyLocalFixtures, loadLocalFixtures } from "./local-fixtures.ts";

const environment = process.env.CNS_ENVIRONMENT ?? "";
const url = process.env.CNS_MIGRATOR_DATABASE_URL;
if (environment !== "LOCAL" || !url) {
  console.error("Fixtures locales: requiere CNS_ENVIRONMENT=LOCAL y CNS_MIGRATOR_DATABASE_URL (consent_migrator). Abortando.");
  process.exit(1);
}
const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..", "db", "fixtures", "local");
const client = new pg.Client({ connectionString: url });
try {
  await client.connect();
  const applied = await applyLocalFixtures(client, loadLocalFixtures(dir), { environment });
  console.log(`Fixtures locales aplicadas: ${applied.join(", ") || "(ninguna)"}`);
} catch (error) {
  console.error(`Fixtures locales fallaron (${(error as Error).name}).`);
  process.exitCode = 1;
} finally {
  await client.end();
}
