// Gobierna: ADR-010 rev. 6 PR-7c (F-PR7-01, decision de Carlos 2026-10-17, C-3). Sin Postgres.
// TEST-CNS-1808: diffInventory (fila de mas, fila de menos, igualdad), la allowlist es unica y sin V1/V4, y el modo REAL_DATA queda bloqueado por F-PR7-01 (resolveDbRoleMode).

import test from "node:test";
import assert from "node:assert/strict";
import { diffInventory } from "../../../src/infra/adapters/postgres/consent-owner-inventory.ts";
import { CONSENT_OWNER_INVENTORY_ALLOWLIST } from "../../../src/infra/adapters/postgres/consent-owner-inventory.allowlist.ts";
import { REAL_DATA_BLOCKERS, resolveDbRoleMode, RoleModeError } from "../../../src/infra/adapters/postgres/role-membership.ts";

test("TEST-CNS-1808 diffInventory: igualdad exacta, fila nueva y fila faltante fallan", () => {
  const base = ["V2|fn|app.a|false", "V2|trigger|app.t|x|A|app.a|consent_owner"];
  assert.deepEqual(diffInventory(base, base), []);
  assert.equal(diffInventory([...base, "V1|policy|x|y|z"], base).length, 1);
  assert.match(diffInventory([...base, "V1|policy|x|y|z"], base)[0] ?? "", /fuera de la allowlist/);
  assert.match(diffInventory(base.slice(0, 1), base)[0] ?? "", /falta respecto/);
});

test("TEST-CNS-1808 la allowlist es unica, sin filas V1 ni V4 (esperadas vacias) y las funciones compartidas ya no son de consent_owner", () => {
  assert.equal(new Set(CONSENT_OWNER_INVENTORY_ALLOWLIST).size, CONSENT_OWNER_INVENTORY_ALLOWLIST.length);
  assert.deepEqual(CONSENT_OWNER_INVENTORY_ALLOWLIST.filter((l) => l.startsWith("V1|") || l.startsWith("V4|")), []);
  assert.ok(CONSENT_OWNER_INVENTORY_ALLOWLIST.every((l) => /^V[1-4]\|/.test(l)));
  assert.deepEqual(CONSENT_OWNER_INVENTORY_ALLOWLIST.filter((l) => /current_tenant_id|is_reserved_email|catalog_environment/.test(l) && l.startsWith("V2|fn|")), []);
});

test("TEST-CNS-1808 REAL_DATA queda bloqueado mientras F-PR7-01 siga abierto", () => {
  assert.ok(REAL_DATA_BLOCKERS.includes("F-PR7-01"));
  assert.throws(() => resolveDbRoleMode({ CNS_DB_ROLE_MODE: "REAL_DATA" }, "STAGING"), (e: unknown) => e instanceof RoleModeError && /F-PR7-01/.test(e.message));
  assert.equal(resolveDbRoleMode({}, "LOCAL"), "IT0B_SYNTHETIC");
});
