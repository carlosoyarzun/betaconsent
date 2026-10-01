# db/

Esquemas y migraciones de base de datos.

Gobierna: `RULE-CNS-###`, `SEC-CNS-###` (tenancy, integridad).

- `migrations/`: SQL versionado e inmutable una vez mergeado (runner: `src/infra/adapters/postgres/migrate.ts`).
- `fixtures/local/`: paso LOCAL-ONLY / SYNTHETIC DATA ONLY, separado de las migraciones (SEC-CNS-017 c). Lo corre
  `applyLocalFixtures` como `consent_migrator` (nunca superusuario, nunca desde el proceso web); se niega si
  `CNS_ENVIRONMENT != LOCAL` o `ops.db_catalog` no es LOCAL/SYNTHETIC. CLI:
  `CNS_ENVIRONMENT=LOCAL CNS_MIGRATOR_DATABASE_URL=... node src/infra/adapters/postgres/local-fixtures-cli.ts`.
