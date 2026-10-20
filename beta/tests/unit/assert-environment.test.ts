// Gobierna: plan v2 H1-01. assertEnvironment: único gate de entorno contra ops.db_catalog.
import assert from "node:assert/strict";
import test from "node:test";

import { assertEnvironment, EnvironmentMismatchError, type Queryable } from "../../src/db/assert-environment.ts";

function fake(rows: Array<{ environment: string; data_class: string }>): Queryable {
  return { query: async () => ({ rows }) as never };
}

test("coincide LOCAL/SYNTHETIC", async () => {
  await assertEnvironment(fake([{ environment: "LOCAL", data_class: "SYNTHETIC" }]), { environment: "LOCAL" });
});

test("aborta si la config dice REAL y el catálogo LOCAL, y viceversa", async () => {
  await assert.rejects(assertEnvironment(fake([{ environment: "LOCAL", data_class: "SYNTHETIC" }]), { environment: "REAL" }), EnvironmentMismatchError);
  await assert.rejects(assertEnvironment(fake([{ environment: "REAL", data_class: "REAL" }]), { environment: "LOCAL" }), EnvironmentMismatchError);
});

test("aborta si environment coincide pero data_class no, o si el catálogo no tiene exactamente una fila", async () => {
  await assert.rejects(assertEnvironment(fake([{ environment: "REAL", data_class: "SYNTHETIC" }]), { environment: "REAL" }), EnvironmentMismatchError);
  await assert.rejects(assertEnvironment(fake([]), { environment: "LOCAL" }), EnvironmentMismatchError);
  const two = { environment: "LOCAL", data_class: "SYNTHETIC" };
  await assert.rejects(assertEnvironment(fake([two, two]), { environment: "LOCAL" }), EnvironmentMismatchError);
});
