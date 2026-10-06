// Gobierna: CA-138 (SEC-CNS-018 rev. 2 D-3, SEC-CNS-020 P2-3), src/server/ports/staff-session-store.port.ts, db/migrations/0021_staff_session.sql,
// INV-CM-02 (tenant_id unica clave de aislamiento). Suite de contrato compartida memoria/Postgres del registro servidor de sesiones STAFF.
// TEST-CNS-1141 (ciclo de vida: expiracion absoluta, inactividad, revocacion, principal/rol) y TEST-CNS-1142 (aislamiento por tenant y
// limpieza solo de expiradas). Reloj inyectado (nowMs explicito). Solo datos sinteticos.

import assert from "node:assert/strict";

import type { StaffSessionStorePort } from "../../../src/server/ports/staff-session-store.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

export type RegisterStaffSessionStoreTest = (name: string, body: (store: StaffSessionStorePort) => Promise<void>) => void;

const TENANT_A = fixtureUuid("tenant-a-1141");
const TENANT_B = fixtureUuid("tenant-b-1141");
const PRINCIPAL = fixtureUuid("principal-1141");
const hex = (label: string): string => fixtureUuid(label).replaceAll("-", "").padEnd(64, "0").slice(0, 64);
// Reloj real al cargar: en Postgres la policy de DELETE compara contra now() de la base (solo filas YA expiradas).
const T0 = Date.now();
const MIN = 60_000;
const IDLE = 30 * MIN;
const ABS = 8 * 60 * MIN;

const record = (label: string, tenantId = TENANT_A) => ({
  tenantId,
  sidHash: hex(label),
  principalRef: PRINCIPAL,
  role: "TENANT_ADMIN" as const,
  issuedAtMs: T0,
  expiresAtMs: T0 + ABS,
});
const check = (store: StaffSessionStorePort, label: string, nowMs: number, over: Partial<{ tenantId: string; principalRef: string; role: "TENANT_ADMIN" | "APPROVER" }> = {}) =>
  store.validateAndTouch({ tenantId: TENANT_A, sidHash: hex(label), principalRef: PRINCIPAL, role: "TENANT_ADMIN", nowMs, idleTimeoutMs: IDLE, ...over });

export function runStaffSessionStoreContract(register: RegisterStaffSessionStoreTest): void {
  register("TEST-CNS-1141 StaffSessionStore: valida mientras vigente; inactividad (se desliza con cada uso); expiracion absoluta; revocada no revive; principal/rol distintos no validan", async (store) => {
    await store.create(record("s1"));
    assert.equal(await check(store, "s1", T0 + 10 * MIN), true);
    // desliza: 25 min despues del ultimo uso sigue valida aunque hayan pasado 35 min desde la emision
    assert.equal(await check(store, "s1", T0 + 35 * MIN), true);
    assert.equal(await check(store, "s1", T0 + 65 * MIN), false, "30 min sin uso: inactividad");
    assert.equal(await check(store, "s1", T0 + 66 * MIN), false, "la inactividad no se recupera");

    await store.create(record("s2"));
    let t = T0;
    while (t + 20 * MIN < T0 + ABS) {
      t += 20 * MIN;
      assert.equal(await check(store, "s2", t), true);
    }
    assert.equal(await check(store, "s2", T0 + ABS - 1), true, "justo antes de exp");
    assert.equal(await check(store, "s2", T0 + ABS), false, "exp absoluta: exp <= now ya no sirve aunque haya actividad");

    await store.create(record("s3"));
    assert.equal(await check(store, "s3", T0 + MIN, { principalRef: fixtureUuid("otro-1141") }), false);
    assert.equal(await check(store, "s3", T0 + MIN, { role: "APPROVER" }), false);
    assert.equal(await check(store, "s3", T0 + MIN), true);
    await store.revoke(TENANT_A, hex("s3"), T0 + 2 * MIN);
    assert.equal(await check(store, "s3", T0 + 3 * MIN), false, "revocada");
    await store.revoke(TENANT_A, hex("s3"), T0 + 4 * MIN); // idempotente
    assert.equal(await check(store, "s3", T0 + 5 * MIN), false);
    assert.equal(await check(store, "desconocido", T0), false);
    await store.revoke(TENANT_A, hex("desconocido"), T0); // no lanza
    await assert.rejects(() => store.create(record("s1")), "un sid no se reutiliza");
  });

  register("TEST-CNS-1142 StaffSessionStore: un sid de otro tenant no existe (ni valida ni se revoca); purgeExpired solo borra expiradas del tenant, tras la retencion", async (store) => {
    await store.create(record("s4", TENANT_A));
    assert.equal(await check(store, "s4", T0 + MIN, { tenantId: TENANT_B }), false, "tenant B no ve la sesion de A");
    await store.revoke(TENANT_B, hex("s4"), T0 + MIN); // no afecta a A
    assert.equal(await check(store, "s4", T0 + 2 * MIN), true);

    await store.create(record("s5", TENANT_A));
    await store.create({ ...record("s6", TENANT_A), issuedAtMs: T0 - 2 * ABS, expiresAtMs: T0 - ABS });
    await store.create({ ...record("s7", TENANT_B), issuedAtMs: T0 - 2 * ABS, expiresAtMs: T0 - ABS });
    const DAY = 24 * 60 * MIN;
    assert.equal(await store.purgeExpired(TENANT_A, T0, DAY), 0, "dentro de la retencion no se borra nada");
    assert.equal(await store.purgeExpired(TENANT_A, T0 + DAY, DAY), 1, "solo la expirada de A, fuera de la retencion");
    assert.equal(await store.purgeExpired(TENANT_A, T0 + DAY, DAY), 0);
    assert.equal(await check(store, "s5", T0 + 3 * MIN), true, "una sesion vigente nunca se borra");
    await store.revoke(TENANT_A, hex("s5"), T0 + 4 * MIN);
    assert.equal(await store.purgeExpired(TENANT_A, T0 + DAY, DAY), 0, "revocada pero no expirada: se conserva");
    assert.equal(await store.purgeExpired(TENANT_B, T0 + DAY, DAY), 1, "la de B solo la borra B");
  });
}
