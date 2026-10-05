// Gobierna: CA-138. Registra la suite de contrato de StaffSessionStorePort contra el adaptador in-memory (TEST-CNS-1141, 1142).
// El registro contra Postgres vive en tests/integration/postgres/staff-session.test.ts.

import test from "node:test";

import { createInMemoryStaffSessionStore } from "../../../src/infra/adapters/in-memory-staff-session-store.adapter.ts";
import { runStaffSessionStoreContract } from "./staff-session-store.contract.ts";

runStaffSessionStoreContract((name, body) => {
  test(name, () => body(createInMemoryStaffSessionStore()));
});
