// Gobierna: orden de Carlos 2026-10-18 (PR-F), F-PR-F-01. SYNTHETIC DATA ONLY.
import assert from "node:assert/strict";
import { test } from "node:test";
import { assertLocalSyntheticCatalog } from "../../../tools/deploy/migrate.ts";

test("TEST-CNS-2060 local-grants: acepta solo exactamente una fila LOCAL/SYNTHETIC", () => {
  assert.doesNotThrow(() => assertLocalSyntheticCatalog("1", "1"));
});

test("TEST-CNS-2061 local-grants: se niega con mensaje claro si el catalogo no es LOCAL/SYNTHETIC", () => {
  for (const [local, total] of [["0", "1"], ["1", "2"], ["0", "0"], [undefined, undefined]] as const) {
    assert.throws(() => assertLocalSyntheticCatalog(local, total), /local-grants SE NIEGA.*LOCAL\/SYNTHETIC/);
  }
});
