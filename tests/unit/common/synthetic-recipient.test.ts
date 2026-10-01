// Gobierna: CA-128, EXT-B (i) (Carlos, 2026-10-01); src/server/modules/common/synthetic-recipient.ts. TEST-CNS-970.
import test from "node:test";
import assert from "node:assert/strict";

import { isSyntheticRecipient } from "../../../src/server/modules/common/synthetic-recipient.ts";
import { RESERVED_BAD, RESERVED_OK } from "./synthetic-recipient-vectors.ts";

test("TEST-CNS-970: isSyntheticRecipient acepta solo email de dominio reservado y rechaza no-strings, UUID y dominios reales", () => {
  for (const ok of RESERVED_OK) assert.equal(isSyntheticRecipient(ok), true, ok);
  for (const bad of RESERVED_BAD) assert.equal(isSyntheticRecipient(bad), false, bad);
  for (const nonString of [undefined, null, 42, {}, [], ["a@x.test"]]) assert.equal(isSyntheticRecipient(nonString), false);
  assert.equal(isSyntheticRecipient(`${"a".repeat(250)}@x.test`), false, "longitud > 254");
});
