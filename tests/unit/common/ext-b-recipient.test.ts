// Gobierna: CA-128, EXT-B (i) (Carlos, 2026-10-01); src/server/modules/common/synthetic-recipient.ts. TEST-CNS-975.
import test from "node:test";
import assert from "node:assert/strict";

import { isReservedEmail } from "../../../src/server/modules/common/synthetic-recipient.ts";
import { RESERVED_BAD, RESERVED_OK } from "./synthetic-recipient-vectors.ts";

test("TEST-CNS-975: isReservedEmail acepta solo email de dominio reservado y rechaza UUID/ref opaco y dominios reales", () => {
  for (const ok of RESERVED_OK) assert.equal(isReservedEmail(ok), true, ok);
  for (const bad of RESERVED_BAD) assert.equal(isReservedEmail(bad), false, bad);
});
