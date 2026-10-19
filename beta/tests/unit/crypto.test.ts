// Gobierna: plan v2 H1-04. Primitivas de OTP/token y traducción de errores SQL.
import assert from "node:assert/strict";
import { test } from "node:test";

import { computeOtpHmac, deriveDecisionMakerRef, generateInvitationToken, generateOtpCode, hashInvitationToken } from "../../src/domain/crypto.ts";
import { DomainError } from "../../src/domain/errors.ts";
import { mapPgError } from "../../src/db/map-error.ts";
import { PgUnitOfWork } from "../../src/db/unit-of-work.ts";

const secret = Buffer.alloc(32, 7);

test("el código OTP son 6 dígitos y el HMAC es hex de 64 ligado a scope, padre y código", () => {
  assert.match(generateOtpCode(), /^\d{6}$/);
  const h = computeOtpHmac(secret, "inv-1", "DECISION", "123456");
  assert.match(h, /^[0-9a-f]{64}$/);
  assert.notEqual(h, computeOtpHmac(secret, "inv-2", "DECISION", "123456"));
  assert.notEqual(h, computeOtpHmac(secret, "inv-1", "MANAGE", "123456"));
  assert.notEqual(h, computeOtpHmac(Buffer.alloc(32, 8), "inv-1", "DECISION", "123456"));
});

test("el token de invitación es aleatorio y su hash es sha256 hex", () => {
  const a = generateInvitationToken();
  assert.notEqual(a.token, generateInvitationToken().token);
  assert.match(a.tokenHash, /^[0-9a-f]{64}$/);
  assert.equal(hashInvitationToken(a.token), a.tokenHash);
  assert.ok(!a.tokenHash.includes(a.token));
});

test("decision_maker_ref es estable, normaliza mayúsculas y no contiene el canal", () => {
  const r = deriveDecisionMakerRef(secret, "Padre@Example.test");
  assert.equal(r, deriveDecisionMakerRef(secret, " padre@example.test "));
  assert.match(r, /^dm-[0-9a-f]{32}$/);
});

test("mapPgError traduce P0001 con mensaje conocido y deja pasar el resto", () => {
  const known = mapPgError({ code: "P0001", message: "ALREADY_DECIDED" });
  assert.ok(known instanceof DomainError && known.code === "ALREADY_DECIDED");
  const other = { code: "P0001", message: "otra cosa" };
  assert.equal(mapPgError(other), other);
  const perm = { code: "42501", message: "ALREADY_DECIDED" };
  assert.equal(mapPgError(perm), perm);
});

test("PgUnitOfWork: BEGIN/COMMIT con topes locales; reintenta 40001; ROLLBACK ante error de negocio", async () => {
  const log: string[] = [];
  let failuresLeft = 1;
  const client = {
    query: async (text: string) => {
      log.push(text);
      return { rows: [], rowCount: 0 };
    },
    release: (d?: unknown) => void log.push(`release:${String(d ?? false)}`),
    on: () => client,
    removeListener: () => client,
  };
  const pool = { connect: async () => client as never };
  const uow = new PgUnitOfWork(pool, { sleep: async () => {}, random: () => 0 });
  const out = await uow.withTransaction(async (tx) => {
    await tx.query("SELECT 1");
    if (failuresLeft-- > 0) throw Object.assign(new Error("serialization"), { code: "40001" });
    return "ok";
  });
  assert.equal(out, "ok");
  assert.deepEqual(log.filter((l) => l === "BEGIN" || l === "COMMIT" || l === "ROLLBACK"), ["BEGIN", "ROLLBACK", "BEGIN", "COMMIT"]);
  assert.ok(log.includes("SET LOCAL lock_timeout = 2000") && log.includes("SET LOCAL statement_timeout = 5000"));
  log.length = 0;
  await assert.rejects(uow.withTransaction(async () => { throw new Error("negocio"); }), /negocio/);
  assert.deepEqual(log.filter((l) => l === "BEGIN" || l === "COMMIT" || l === "ROLLBACK"), ["BEGIN", "ROLLBACK"]);
});
