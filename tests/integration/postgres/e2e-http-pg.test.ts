// Gobierna: CA-124 (PR-E), postgres-design.md rev. 2 §7, contracts/openapi API-CNS-101/102/103/115/120/121/
// 126/127/130..135/138/139, DEC-BR-014 X5 (evidencia). TEST-CNS-872..875: los flujos HTTP principales
// corren contra Postgres REAL con el servidor armado igual que `CONSENT_STORE=postgres` (openPostgresStore:
// pool de app_rw + chequeos de arranque; puertos "fuera de tx" que rechazan): invitacion /i -> OTP ->
// decision; /m -> verificacion -> retiro -> recibo; recuperacion /r; RH3 confirmacion + co-firma. El estado
// final se verifica en la base. SYNTHETIC DATA ONLY. Requiere Postgres real (harness.ts).

import { deriveChainRefKey } from "../../../src/server/modules/consent-decision/chain-ref.ts";
import { deriveDecisionMakerRefKey } from "../../../src/server/modules/consent-decision/decision-maker-ref.ts";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";

import { createConsentFlowHttpServer, createPostgresFlowPorts } from "../../../src/server/entrypoints/http/consent-flow-server.ts";
import {
  LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY,
  LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY,
  LOCAL_ONLY_DEV_OTHER_TENANT_ID,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_STAFF_ROSTER,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import { RH3_DEV_CASE_REF, RH3_DEV_REVOCATION_REF, seedRh3DevCase } from "../../../src/server/entrypoints/dev-rh3-seed.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import type { InMemoryOtpChannelSink } from "../../../src/infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import type { InMemoryRecoveryLinkChannelSink } from "../../../src/infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { OutsideTransactionError, openPostgresStore } from "../../../src/infra/adapters/postgres/store.ts";
import { registerTenantHandle } from "../../../src/infra/adapters/postgres/tenant-handle.adapter.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { createInvitation, markInvitationReady, sendInvitation } from "../../../src/server/modules/invitation/invitation.ts";
import { loadDecisionRelationshipConfig } from "../../../src/server/modules/consent-decision/decision-relationship.config.ts";
import { loadIdempotencyPolicyConfig } from "../../../src/server/modules/common/idempotency-policy.config.ts";
import { loadOtpPolicyConfig } from "../../../src/server/modules/otp-challenge/otp-policy.config.ts";
import { loadRecoveryTokenPolicyConfig } from "../../../src/server/modules/revocation/recovery-token-policy.config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import { applyLocalFixtures, loadLocalFixtures } from "../../../src/infra/adapters/postgres/local-fixtures.ts";
import { LOCAL_ONLY_DEV_PARTICIPATION_REF, LOCAL_ONLY_DEV_STAFF_CHANNEL_REF, LOCAL_ONLY_DEV_STAFF_SUBJECT_REF, LOCAL_ONLY_DEV_SUBJECT_REF } from "../../../src/server/entrypoints/dev-local-config.ts";
import { listOutboxEnvelopes } from "../../../src/infra/adapters/postgres/outbox.adapter.ts";
import { isReservedEmail } from "../../../src/server/modules/common/synthetic-recipient.ts";
import { RESERVED_BAD, RESERVED_OK } from "../../unit/common/synthetic-recipient-vectors.ts";
import { pgTest } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { TEST_OTP_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY } from "../../helpers/test-ref-keys.ts";

const ORIGIN = "http://consola-consent.test.localhost";
const CSRF = { origin: ORIGIN, csrf: "csrf-token-abcdefgh" };
const T = LOCAL_ONLY_DEV_TENANT_ID;
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));

function cookiesOf(res: Response): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of res.headers.getSetCookie()) {
    const first = raw.split(";", 1)[0] ?? "";
    const eq = first.indexOf("=");
    if (eq > 0 && out[first.slice(0, eq)] === undefined) out[first.slice(0, eq)] = first.slice(eq + 1);
  }
  return out;
}

async function boot(ctx: PgTestContext) {
  // SEC-CNS-017 F5: cualquier throw no capturado de una ruta (p. ej. OutsideTransactionError) pasa por el catch global
  // y deja `request_failed` en el log; close() exige que no haya ninguno en todo el recorrido HTTP del test.
  const failed: string[] = [];
  const realConsoleError = console.error;
  console.error = (...a: unknown[]) => {
    const line = a.join(" ");
    if (line.startsWith("request_failed")) failed.push(line);
    else realConsoleError(...a);
  };
  const store = await openPostgresStore({
    environment: "LOCAL",
    idempotencyPolicy: loadIdempotencyPolicyConfig(LOCAL_ONLY_DEV_IDEMPOTENCY_POLICY),
    env: { CNS_DATABASE_URL: ctx.urlFor("app_rw") },
  });
  const staffIdentity = createInMemoryStaffIdentityAdapter(LOCAL_ONLY_DEV_STAFF_ROSTER);
  const bundle = createPostgresFlowPorts(store, {
    otpPolicy: loadOtpPolicyConfig(LOCAL_ONLY_DEV_OTP_POLICY),
    relationshipConfig: loadDecisionRelationshipConfig(LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG),
    recoveryTokenPolicy: loadRecoveryTokenPolicyConfig(LOCAL_ONLY_DEV_RECOVERY_TOKEN_POLICY),
    staffIdentity,
    chainRefKey: deriveChainRefKey(Buffer.alloc(32, 9)),
    otpSecret: TEST_OTP_SECRET,
    decisionMakerRefKey: deriveDecisionMakerRefKey(Buffer.alloc(32, 8)),
    invitationIssuancePolicy: loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY),
  });
  const server = createConsentFlowHttpServer({ staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
    config: { allowedOrigin: ORIGIN },
    ports: bundle.ports,
    revocationPorts: bundle.revocationPorts,
    sessionSecret: randomBytes(32),
    environment: "LOCAL",
    staffIdentity,
    staffConsole: bundle.staffConsole,
    caseSessions: bundle.caseSessions,
    storeMode: "postgres",
    devOutboxSink: () => store.uow.withTenantTx(T, (tx) => listOutboxEnvelopes(tx)),
  });
  const baseUrl = await new Promise<string>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)),
  );
  const admin = await ctx.connectAsSuperuser();
  return {
    store,
    bundle,
    baseUrl,
    admin,
    otpSink: bundle.ports.otp.channel as InMemoryOtpChannelSink,
    async close() {
      console.error = realConsoleError;
      await new Promise((resolve) => server.close(() => resolve(undefined)));
      await store.close();
      assert.deepEqual(failed, [], "ninguna ruta HTTP debe lanzar (OutsideTransactionError u otro) en Postgres");
    },
  };
}

type Env = Awaited<ReturnType<typeof boot>>;

function post(env: Env, path: string, cookies: Record<string, string>, body: unknown = {}, extra: Record<string, string> = {}): Promise<Response> {
  const jar = { "__Host-cns-csrf": CSRF.csrf, ...cookies };
  return fetch(`${env.baseUrl}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: ORIGIN,
      "x-csrf-token": CSRF.csrf,
      cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; "),
      ...extra,
    },
    body: JSON.stringify(body),
  });
}

const count = async (env: Env, sql: string, values: unknown[]): Promise<number> => (await env.admin.query<{ n: number }>(sql, values)).rows[0]?.n ?? -1;

pgTest("TEST-CNS-872 e2e pg: invitacion /i -> OTP -> decision por HTTP; estado y ledger en la base; el bolso fuera de tx rechaza", async (ctx) => {
  const env = await boot(ctx);
  try {
    const { ports } = env.bundle;
    const inv = fixtureUuid("inv872");
    await createInvitation(ports.invitation, T, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
      invitationRef: inv,
      contextRef: LECTORPRO_BETA_CONFIG.contextRef,
      productRef: LECTORPRO_BETA_CONFIG.productRef,
      subjectRef: fixtureUuid("subj872"),
    });
    await markInvitationReady(ports.invitation, T, "INVITER", inv, { consentVersion: "v1-dev", expiresAt: new Date(Date.now() + 3_600_000), recipientChannelRef: "e2e-872@example.invalid" });
    const { token } = await sendInvitation(ports.invitation, T, "INVITER", inv, { deliveryChannel: "CONSENT_APP_EMAIL" });

    const redeemed = await fetch(`${env.baseUrl}/i/${token}`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    const handle = cookiesOf(redeemed)["__Host-cns-i-handle"]!;
    const welcome = await fetch(`${env.baseUrl}/welcome`, { headers: { cookie: `__Host-cns-i-handle=${handle}` } });
    assert.equal(welcome.status, 200);
    let session = cookiesOf(welcome)["__Host-cns-session"]!;
    const step = async (res: Response): Promise<Response> => {
      session = cookiesOf(res)["__Host-cns-session"] ?? session;
      return res;
    };
    assert.equal((await step(await post(env, "/invitation/open", { "__Host-cns-session": session }))).status, 200);
    assert.equal((await step(await post(env, "/otp/request", { "__Host-cns-session": session }))).status, 202);
    const code = env.otpSink.sent[env.otpSink.sent.length - 1]?.code ?? "";
    assert.ok(code.length > 0);
    assert.equal((await step(await post(env, "/otp/submit", { "__Host-cns-session": session }, { code }))).status, 200);
    for (const body of [
      { stepKind: "CONTEXT_INFORMATION_VIEWED" },
      { stepKind: "CONSENT_VERSION_VIEWED" },
      { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true },
      { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true },
    ]) {
      assert.equal((await step(await post(env, "/decision/steps", { "__Host-cns-session": session }, body))).status, 200);
    }
    const decided = await post(env, "/decision/submit", { "__Host-cns-session": session }, { purposes: GRANT_ALL });
    assert.equal(decided.status, 200);
    const { consentId, state } = (await decided.json()) as { consentId: string; state: string };
    assert.equal(state, "GRANTED");

    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2 AND state = 'GRANTED'", [T, consentId]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2 AND state = 'COMPLETED'", [T, inv]), 1);
    assert.equal(await count(env, "SELECT max(sequence)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2", [T, inv]) > 0, true);
    // SEC-CNS-016: usar un repo del bolso fuera de inTenant falla cerrado.
    await assert.rejects(() => ports.invitation.invitationRepo.findByRef(T, inv), OutsideTransactionError);
  } finally {
    await env.close();
  }
});

async function seedManage(env: Env, label: string): Promise<{ handleToken: string; consentId: string; chain: string }> {
  const consentId = fixtureUuid(`consent-${label}`);
  const chain = fixtureUuid(`chain-${label}`);
  const handleToken = `mgmt-token-${label}`;
  await env.store.uow.inTenant(T, (tx) =>
    tx.consentDecisionRepo.save({
      consentId,
      tenantId: T,
      contextRef: LECTORPRO_BETA_CONFIG.contextRef,
      productRef: LECTORPRO_BETA_CONFIG.productRef,
      subjectRef: fixtureUuid(`subj-${label}`),
      decisionMakerRef: `dm:${label}`,
      invitationRef: fixtureUuid(`inv-${label}`),
      verificationRef: fixtureUuid(`ver-${label}`),
      chainRef: chain,
      state: "GRANTED",
      purposes: GRANT_ALL,
      priorStepsComplete: true,
      stepsRecorded: ["CONTEXT_INFORMATION_VIEWED", "CONSENT_VERSION_VIEWED", "DECISION_MAKER_AUTHORITY_DECLARED", "SUBJECT_CONFIRMED"],
      receiptRef: `receipt-${label}`,
    }),
  );
  await env.store.uow.withTenantTx(T, (tx) => registerTenantHandle(tx, { handle: handleToken, chainRef: chain, revokedDecisionRef: consentId }));
  return { handleToken, consentId, chain };
}

async function manageSession(env: Env, handleToken: string): Promise<string> {
  const redeemed = await fetch(`${env.baseUrl}/m/${handleToken}`, { redirect: "manual" });
  assert.equal(redeemed.status, 303);
  const manage = await fetch(`${env.baseUrl}/manage`, { headers: { cookie: `__Host-cns-m-handle=${cookiesOf(redeemed)["__Host-cns-m-handle"]}` } });
  assert.equal(manage.status, 200);
  return cookiesOf(manage)["__Host-cns-session"]!;
}

pgTest("TEST-CNS-873 e2e pg: /m -> verificacion MANAGE -> retiro R1..R4 -> recibo; consent REVOKED, outbox y ledger en la base; /manage ya-retirado", async (ctx) => {
  const env = await boot(ctx);
  try {
    const { handleToken, consentId, chain } = await seedManage(env, "873");
    let session = await manageSession(env, handleToken);
    const jar = (): Record<string, string> => ({ "__Host-cns-session": session });
    const adv = (res: Response): Response => {
      session = cookiesOf(res)["__Host-cns-session"] ?? session;
      return res;
    };
    assert.equal(adv(await post(env, "/otp/request", jar())).status, 202);
    const manageCode = env.otpSink.sent[env.otpSink.sent.length - 1]!.code;
    assert.equal(adv(await post(env, "/otp/submit", jar(), { code: manageCode })).status, 200);
    const r1 = adv(await post(env, "/manage/revocation", jar()));
    assert.equal(r1.status, 200);
    assert.equal(adv(await post(env, "/otp/request", jar())).status, 202);
    const revCode = env.otpSink.sent[env.otpSink.sent.length - 1]!.code;
    assert.equal(adv(await post(env, "/otp/submit", jar(), { code: revCode })).status, 200);
    assert.equal((await post(env, "/manage/revocation/verify", jar())).status, 200);
    const r3 = await post(env, "/manage/revocation/confirm", jar());
    assert.equal(r3.status, 200);
    const { revocationRef, status } = (await r3.json()) as { revocationRef: string; status: string };
    assert.equal(status, "APPLIED");

    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2 AND state = 'REVOKED'", [T, consentId]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1 AND dedupe_key = $2", [T, `${revocationRef}:consent.revoked`]), 1);
    // SEC-CNS-017 F3 (TEST-CNS-881): /__dev/outbox-sink en pg lee el outbox dentro de withTenantTx del tenant dev (sin TypeError del Proxy).
    const sink = await fetch(`${env.baseUrl}/__dev/outbox-sink`);
    assert.equal(sink.status, 200);
    const sunk = ((await sink.json()) as { enqueued: { eventType: string; tenantRef: string }[] }).enqueued;
    assert.equal(sunk.length, 1);
    assert.equal(sunk[0]?.eventType, "consent.revoked");
    assert.equal(sunk[0]?.tenantRef, T);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type IN ('CONSENT_REVOKED','RECEIPT_CREATED')", [T, revocationRef]), 2);
    assert.ok(chain.length > 0);
    // /manage ya-retirado (C6): sin CTA de retirar.
    const again = await fetch(`${env.baseUrl}/manage`, { headers: { cookie: `__Host-cns-session=${session}` } });
    assert.equal(again.status, 200);
    assert.doesNotMatch(await again.text(), /start-revocation-btn/);
  } finally {
    await env.close();
  }
});

pgTest("TEST-CNS-874 e2e pg: recuperacion /r: enlace por RV0 -> /r/{token} -> /recovery/confirm -> /recovery/revoke -> APPLIED; token de un solo uso", async (ctx) => {
  const env = await boot(ctx);
  try {
    const { handleToken, consentId } = await seedManage(env, "874");
    const session = await manageSession(env, handleToken);
    const issued = await post(env, "/manage/recovery-link", { "__Host-cns-session": session });
    assert.equal(issued.status, 202);
    const sink = env.bundle.revocationPorts.revocation.recoveryLinkChannel as InMemoryRecoveryLinkChannelSink;
    const path = sink.sent[sink.sent.length - 1]!.recoveryPath;
    const redeemed = await fetch(`${env.baseUrl}${path}`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    const handle = cookiesOf(redeemed)["__Host-cns-recovery"]!;
    const confirm = await fetch(`${env.baseUrl}/recovery/confirm`, { headers: { cookie: `__Host-cns-recovery=${handle}` } });
    assert.equal(confirm.status, 200);
    const csrf = cookiesOf(confirm)["__Host-cns-csrf"]!;
    const revoke = (): Promise<Response> =>
      fetch(`${env.baseUrl}/recovery/revoke`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": csrf, cookie: `__Host-cns-recovery=${handle}; __Host-cns-csrf=${csrf}` },
        body: JSON.stringify({ confirmTotalWithdrawal: true }),
      });
    const done = await revoke();
    assert.equal(done.status, 200);
    assert.equal(((await done.json()) as { state: string }).state, "CONFIRMED");
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2 AND state = 'REVOKED'", [T, consentId]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.recovery_token WHERE tenant_id = $1 AND consumed_at IS NOT NULL", [T]), 1);
    // Un solo uso: el segundo POST es uniforme y /recovery/confirm ya no es elegible.
    assert.equal((await revoke()).status, 202);
    assert.equal((await fetch(`${env.baseUrl}/recovery/confirm`, { headers: { cookie: `__Host-cns-recovery=${handle}` } })).status, 404);
  } finally {
    await env.close();
  }
});

pgTest("TEST-CNS-875 e2e pg: RH3 registro + co-firma por dos RIGHTS_OPERATOR distintos -> CONFIRMED/APPLIED en la base", async (ctx) => {
  const env = await boot(ctx);
  try {
    await seedRh3DevCase(env.bundle.ports, env.bundle.revocationPorts, T);
    const login = async (principalRef: string): Promise<{ jar: Record<string, string>; csrf: string }> => {
      const res = await fetch(`${env.baseUrl}/__dev/staff-login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ tenantId: T, caseRef: RH3_DEV_CASE_REF, principalRef }),
      });
      assert.equal(res.status, 200);
      const c = cookiesOf(res);
      return { jar: { "__Host-cns-case": c["__Host-cns-case"]!, "__Host-cns-case-csrf": c["__Host-cns-case-csrf"]! }, csrf: c["__Host-cns-case-csrf"]! };
    };
    const call = (who: { jar: Record<string, string>; csrf: string }, path: string, body: unknown): Promise<Response> =>
      fetch(`${env.baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": who.csrf, cookie: Object.entries(who.jar).map(([k, v]) => `${k}=${v}`).join("; ") },
        body: JSON.stringify(body),
      });
    const op1 = await login(fixtureUuid("staff-synthetic-01"));
    const first = await call(op1, `/platform/rights-cases/${RH3_DEV_CASE_REF}/confirmation`, { confirmationGivenOnCasePage: true });
    assert.equal(first.status, 200);
    assert.deepEqual(await first.json(), { cosign: "AWAITING_COSIGN", revocationState: "VERIFIED" });
    const op2 = await login(fixtureUuid("staff-synthetic-02"));
    const second = await call(op2, `/platform/rights-cases/${RH3_DEV_CASE_REF}/confirmation/cosign`, {});
    assert.equal(second.status, 200);
    assert.equal(((await second.json()) as { cosign: string }).cosign, "COSIGNED");
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2 AND status = 'APPLIED'", [T, RH3_DEV_REVOCATION_REF]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.outbox WHERE tenant_id = $1 AND dedupe_key = $2", [T, `${RH3_DEV_REVOCATION_REF}:consent.revoked`]), 1);
  } finally {
    await env.close();
  }
});

pgTest("TEST-CNS-880 e2e pg: consola STAFF (EN0 enrolar, I1 invitar, ready, send) contra Postgres con el catalogo sembrado por las fixtures LOCAL-only", async (ctx) => {
  // Catalogo (SELECT-only para app_rw): lo provisiona el paso de fixtures como consent_migrator (SEC-CNS-017 c).
  const migrator = await ctx.connectAs("consent_migrator");
  await applyLocalFixtures(migrator, loadLocalFixtures(new URL("../../../db/fixtures/local", import.meta.url).pathname), { environment: "LOCAL" });
  const env = await boot(ctx);
  try {
    const login = await fetch(`${env.baseUrl}/__dev/staff-login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ principalRef: fixtureUuid("staff-synthetic-05") }),
    });
    assert.equal(login.status, 200);
    const c = cookiesOf(login);
    const jar = `__Host-cns-staff=${c["__Host-cns-staff"]}; __Host-cns-staff-csrf=${c["__Host-cns-staff-csrf"]}`;
    const staffPost = (path: string, body: unknown, extra: Record<string, string> = {}): Promise<Response> =>
      fetch(`${env.baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": c["__Host-cns-staff-csrf"]!, cookie: jar, ...extra },
        body: JSON.stringify(body),
      });
    const enrolled = await staffPost("/staff/enrollments", { subjectRef: LOCAL_ONLY_DEV_STAFF_SUBJECT_REF, participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF });
    assert.equal(enrolled.status, 201, await enrolled.clone().text());
    const { enrollmentRef } = (await enrolled.json()) as { enrollmentRef: string };
    const invited = await staffPost(
      "/staff/invitations",
      { subjectRef: LOCAL_ONLY_DEV_STAFF_SUBJECT_REF, enrollmentRef, participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF, contextRef: LECTORPRO_BETA_CONFIG.contextRef },
      { "idempotency-key": "pg-880-idem-key-0001" },
    );
    assert.equal(invited.status, 201, await invited.clone().text());
    const { invitationRef } = (await invited.json()) as { invitationRef: string };
    // Misma Idempotency-Key + mismo cuerpo: repite sin crear otra invitacion (IdempotencyPort en la tx).
    const replay = await staffPost(
      "/staff/invitations",
      { subjectRef: LOCAL_ONLY_DEV_STAFF_SUBJECT_REF, enrollmentRef, participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF, contextRef: LECTORPRO_BETA_CONFIG.contextRef },
      { "idempotency-key": "pg-880-idem-key-0001" },
    );
    assert.equal(replay.status, 201);
    // FINDING (contract<->implementation, EXT-B/LD-21 pendiente de Carlos): RECIPIENT_CHANNEL en la consola STAFF exige
    // recipientChannelRef UUIDv4 (REF_PATTERN) pero app.invitation.recipient_channel_ref solo admite email reservado
    // (0010): en Postgres esa rama no puede persistir. Aqui se ejerce UNBOUND, que no toca esa columna.
    const ready = await staffPost(`/staff/invitations/${invitationRef}/ready`, { consentVersion: "v1-dev", recipientBinding: "UNBOUND" });
    assert.equal(ready.status, 200, await ready.clone().text());
    const sent = await staffPost(`/staff/invitations/${invitationRef}/send`, {});
    assert.equal(sent.status, 200, await sent.clone().text());
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.invitation WHERE tenant_id = $1 AND subject_ref = $2", [T, LOCAL_ONLY_DEV_STAFF_SUBJECT_REF]), 1);
  } finally {
    await env.close();
  }
});

pgTest("TEST-CNS-889 e2e pg: /ready con RECIPIENT_CHANNEL y un UUID responde 422 uniforme (EXT-B (i): solo email reservado; el CHECK 23514 de la BD queda como defensa en profundidad), sin 500 ni request_failed; la invitacion sigue DRAFT y UNBOUND funciona", async (ctx) => {
  const migrator = await ctx.connectAs("consent_migrator");
  await applyLocalFixtures(migrator, loadLocalFixtures(new URL("../../../db/fixtures/local", import.meta.url).pathname), { environment: "LOCAL" });
  const env = await boot(ctx);
  try {
    const login = await fetch(`${env.baseUrl}/__dev/staff-login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ principalRef: fixtureUuid("staff-synthetic-05") }),
    });
    assert.equal(login.status, 200);
    const c = cookiesOf(login);
    const jar = `__Host-cns-staff=${c["__Host-cns-staff"]}; __Host-cns-staff-csrf=${c["__Host-cns-staff-csrf"]}`;
    const staffPost = (path: string, body: unknown, extra: Record<string, string> = {}): Promise<Response> =>
      fetch(`${env.baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": c["__Host-cns-staff-csrf"]!, cookie: jar, ...extra },
        body: JSON.stringify(body),
      });
    const enrolled = await staffPost("/staff/enrollments", { subjectRef: LOCAL_ONLY_DEV_SUBJECT_REF, participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF });
    assert.equal(enrolled.status, 201, await enrolled.clone().text());
    const { enrollmentRef } = (await enrolled.json()) as { enrollmentRef: string };
    const invited = await staffPost("/staff/invitations", { subjectRef: LOCAL_ONLY_DEV_SUBJECT_REF, enrollmentRef, participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF, contextRef: LECTORPRO_BETA_CONFIG.contextRef }, { "idempotency-key": "pg-889-idem-key-0001" });
    assert.equal(invited.status, 201, await invited.clone().text());
    const { invitationRef } = (await invited.json()) as { invitationRef: string };

    // EXT-B (i) (Carlos, 2026-10-01): el contrato exige email reservado; un UUID (valor antiguo) es 422 uniforme en el
    // handler, sin llegar a la BD ni reflejarse en el error.
    const legacyUuid = "f1a5c9e3-4d27-4b68-9e30-2c4e6a8b0d51";
    const ready = await staffPost(`/staff/invitations/${invitationRef}/ready`, { consentVersion: "v1-dev", recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: legacyUuid });
    assert.equal(ready.status, 422);
    const problem = (await ready.json()) as { code: string; status: number };
    assert.equal(problem.status, 422);
    assert.ok(!JSON.stringify(problem).includes(legacyUuid), "el error no refleja el valor");
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2 AND state = 'DRAFT'", [T, invitationRef]), 1, "rollback: sigue DRAFT");

    // La tx abortada no dejo la conexion ni el agregado inutilizables: UNBOUND pasa a READY.
    const unbound = await staffPost(`/staff/invitations/${invitationRef}/ready`, { consentVersion: "v1-dev", recipientBinding: "UNBOUND" });
    assert.equal(unbound.status, 200, await unbound.clone().text());
  } finally {
    await env.close();
  }
});

pgTest("TEST-CNS-882 e2e pg: seed RH3 atomico (una tx: si falla no queda nada) e idempotente por consulta (segunda corrida false, sin captura de errores)", async (ctx) => {
  const env = await boot(ctx);
  const T2 = LOCAL_ONLY_DEV_OTHER_TENANT_ID; // tenant propio: la base se comparte con los tests anteriores del archivo
  try {
    const rp = env.bundle.revocationPorts;
    const realUow = rp.revocation.uow;
    const failing = {
      ...rp,
      revocation: { ...rp.revocation, uow: { ...realUow, inTenant: async <R>(t: string, work: (tx: never) => Promise<R>): Promise<R> => realUow.inTenant(t, async (tx) => { await work(tx as never); throw new Error("boom"); }) } },
    } as typeof rp;
    await assert.rejects(() => seedRh3DevCase(env.bundle.ports, failing, T2), /boom/);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1 AND chain_ref = 'chain-dev-rh3'", [T2]), 0);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.rights_case WHERE tenant_id = $1 AND case_ref = $2", [T2, RH3_DEV_CASE_REF]), 0);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [T2, RH3_DEV_REVOCATION_REF]), 0);
    assert.equal(await seedRh3DevCase(env.bundle.ports, rp, T2), true);
    assert.equal(await seedRh3DevCase(env.bundle.ports, rp, T2), false);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.rights_case WHERE tenant_id = $1 AND case_ref = $2 AND status = 'IN_VERIFICATION'", [T2, RH3_DEV_CASE_REF]), 1);
  } finally {
    await env.close();
  }
});

pgTest("TEST-CNS-886 e2e pg: recorrido de TODAS las rutas HTTP (GET y POST, sin sesion y con basura) no lanza ni responde 500 (OutsideTransactionError)", async (ctx) => {
  const env = await boot(ctx);
  try {
    const gets = ["/welcome", "/verify", "/decision", "/manage", "/manage/verify", "/recovery/confirm", "/i/token-inexistente", "/m/token-inexistente", "/r/token-inexistente", "/__dev/otp-sink", "/__dev/outbox-sink", "/__dev/recovery-sink", "/__dev/invitation-sink"];
    const posts = ["/invitation/open", "/otp/request", "/otp/resend", "/otp/submit", "/decision/steps", "/decision/submit", "/manage/revocation", "/manage/revocation/verify", "/manage/revocation/confirm", "/manage/revocation/withdraw", "/manage/recovery-link", "/recovery/revoke", "/rights-case/open", "/staff/enrollments", "/staff/invitations", "/staff/invitations/00000000-0000-4000-8000-000000000000/ready", "/staff/invitations/00000000-0000-4000-8000-000000000000/send", "/__dev/staff-login"];
    for (const path of gets) {
      const res = await fetch(`${env.baseUrl}${path}`, { redirect: "manual", headers: { cookie: "__Host-cns-session=basura; __Host-cns-i-handle=basura; __Host-cns-m-handle=basura" } });
      assert.notEqual(res.status, 500, `GET ${path}`);
    }
    for (const path of posts) {
      const res = await post(env, path, { "__Host-cns-session": "basura" }, {});
      assert.notEqual(res.status, 500, `POST ${path}`);
    }
  } finally {
    await env.close();
  }
});

pgTest("TEST-CNS-978 e2e pg EXT-B (i): STAFF EN0 -> I1 -> /ready RECIPIENT_CHANNEL (email reservado) -> /send -> participante /i -> OTP al sink del email reservado -> decision -> recibo; la BD persiste el canal", async (ctx) => {
  const migrator = await ctx.connectAs("consent_migrator");
  await applyLocalFixtures(migrator, loadLocalFixtures(new URL("../../../db/fixtures/local", import.meta.url).pathname), { environment: "LOCAL" });
  const env = await boot(ctx);
  const T2 = LOCAL_ONLY_DEV_OTHER_TENANT_ID; // tenant propio: la base se comparte con los tests anteriores del archivo
  try {
    const login = await fetch(`${env.baseUrl}/__dev/staff-login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ principalRef: fixtureUuid("staff-synthetic-06") }),
    });
    assert.equal(login.status, 200);
    const c = cookiesOf(login);
    const jar = `__Host-cns-staff=${c["__Host-cns-staff"]}; __Host-cns-staff-csrf=${c["__Host-cns-staff-csrf"]}`;
    const staffPost = (path: string, body: unknown, extra: Record<string, string> = {}): Promise<Response> =>
      fetch(`${env.baseUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": c["__Host-cns-staff-csrf"]!, cookie: jar, ...extra },
        body: JSON.stringify(body),
      });
    const enrolled = await staffPost("/staff/enrollments", { subjectRef: LOCAL_ONLY_DEV_STAFF_SUBJECT_REF, participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF });
    assert.equal(enrolled.status, 201, await enrolled.clone().text());
    const { enrollmentRef } = (await enrolled.json()) as { enrollmentRef: string };
    const invited = await staffPost("/staff/invitations", { subjectRef: LOCAL_ONLY_DEV_STAFF_SUBJECT_REF, enrollmentRef, participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF, contextRef: LECTORPRO_BETA_CONFIG.contextRef }, { "idempotency-key": "pg-973-idem-key-0001" });
    assert.equal(invited.status, 201, await invited.clone().text());
    const { invitationRef } = (await invited.json()) as { invitationRef: string };
    const channel = "ext-b-973@example.invalid";
    const ready = await staffPost(`/staff/invitations/${invitationRef}/ready`, { consentVersion: "v1-dev", recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: channel });
    assert.equal(ready.status, 200, await ready.clone().text());
    assert.equal((await staffPost(`/staff/invitations/${invitationRef}/send`, {})).status, 200);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2 AND recipient_channel_ref = $3", [T2, invitationRef, channel]), 1);

    const sent = env.bundle.staffConsole.invitationLinkSink.sent;
    const link = sent[sent.length - 1]!;
    const redeemed = await fetch(`${env.baseUrl}${link.invitationPath}`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    const welcome = await fetch(`${env.baseUrl}/welcome`, { headers: { cookie: `__Host-cns-i-handle=${cookiesOf(redeemed)["__Host-cns-i-handle"]}` } });
    assert.equal(welcome.status, 200);
    let session = cookiesOf(welcome)["__Host-cns-session"]!;
    const step = (res: Response): Response => {
      session = cookiesOf(res)["__Host-cns-session"] ?? session;
      return res;
    };
    assert.equal(step(await post(env, "/invitation/open", { "__Host-cns-session": session })).status, 200);
    assert.equal(step(await post(env, "/otp/request", { "__Host-cns-session": session })).status, 202);
    const otp = env.otpSink.sent[env.otpSink.sent.length - 1]!;
    assert.equal(otp.channelRef, channel, "el OTP llega al sink del email reservado");
    assert.equal(step(await post(env, "/otp/submit", { "__Host-cns-session": session }, { code: otp.code })).status, 200);
    for (const body of [
      { stepKind: "CONTEXT_INFORMATION_VIEWED" },
      { stepKind: "CONSENT_VERSION_VIEWED" },
      { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true },
      { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true },
    ]) assert.equal(step(await post(env, "/decision/steps", { "__Host-cns-session": session }, body)).status, 200);
    const decided = await post(env, "/decision/submit", { "__Host-cns-session": session }, { purposes: GRANT_ALL });
    assert.equal(decided.status, 200);
    const out = (await decided.json()) as { consentId: string; state: string; receiptRef: string };
    assert.equal(out.state, "GRANTED");
    assert.ok(out.receiptRef);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2 AND state = 'COMPLETED'", [T2, invitationRef]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2 AND state = 'GRANTED'", [T2, out.consentId]), 1);
  } finally {
    await env.close();
  }
});

pgTest("TEST-CNS-979 pg: paridad entre isReservedEmail (TS) y app.is_reserved_email (SQL) sobre los vectores compartidos", async (ctx) => {
  const admin = await ctx.connectAsSuperuser();
  for (const value of [...RESERVED_OK, ...RESERVED_BAD]) {
    const sql = (await admin.query<{ ok: boolean }>("SELECT app.is_reserved_email($1) AS ok", [value])).rows[0]?.ok;
    assert.equal(isReservedEmail(value), sql, `paridad TS/SQL: ${value}`);
  }
});

pgTest("TEST-CNS-1174 e2e pg: sesion CASE en app.case_session (solo hash del sid); logout revoca en la BD y la cookie robada no sirve; sid de otro tenant no existe; BD sin sid en claro ni PII (CA-139)", async (ctx) => {
  const env = await boot(ctx);
  try {
    await seedRh3DevCase(env.bundle.ports, env.bundle.revocationPorts, T);
    const res = await fetch(`${env.baseUrl}/__dev/staff-login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: T, caseRef: RH3_DEV_CASE_REF, principalRef: fixtureUuid("staff-synthetic-01") }),
    });
    assert.equal(res.status, 200);
    const c = cookiesOf(res);
    const session = c["__Host-cns-case"]!;
    const csrf = c["__Host-cns-case-csrf"]!;
    const call = (path: string, body: unknown): Promise<Response> =>
      fetch(`${env.baseUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN, "x-csrf-token": csrf, cookie: `__Host-cns-case=${session}; __Host-cns-case-csrf=${csrf}` }, body: JSON.stringify(body) });
    const sid = JSON.parse(Buffer.from(session.split(".")[0]!, "base64url").toString("utf8")).sid as string;
    const sidHash = createHash("sha256").update(sid, "utf8").digest("hex");
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.case_session WHERE tenant_id = $1 AND case_ref = $2 AND sid_hash = $3 AND revoked_at IS NULL", [T, RH3_DEV_CASE_REF, sidHash]), 1);
    // El caso RH3 ya pudo confirmarse en otro test de este archivo (misma base): 200 o 409; lo que importa es que la sesion se acepta (ni 404 ni 403).
    assert.ok([200, 409].includes((await call(`/platform/rights-cases/${RH3_DEV_CASE_REF}/confirmation`, { confirmationGivenOnCasePage: true })).status), "la sesion registrada sirve (RLS por tenant)");
    const dump = (await env.admin.query<{ row: string }>("SELECT t::text AS row FROM app.case_session t")).rows.map((r) => r.row).join("\n");
    assert.ok(!dump.includes(sid) && !dump.includes(session) && !dump.includes("@"), "la BD no guarda sid en claro, cookie ni correos");
    assert.match(dump, /[0-9a-f]{64}/);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.case_session WHERE tenant_id = $1 AND sid_hash = $2", [LOCAL_ONLY_DEV_OTHER_TENANT_ID, sidHash]), 0, "otro tenant no tiene (ni ve) esa sesion");

    const out = await call("/platform/case-session/logout", {});
    assert.equal(out.status, 200);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.case_session WHERE tenant_id = $1 AND sid_hash = $2 AND revoked_at IS NOT NULL", [T, sidHash]), 1, "logout revoca en la BD");
    assert.equal((await call(`/platform/rights-cases/${RH3_DEV_CASE_REF}/confirmation/cosign`, {})).status, 404, "cookie robada tras logout");
    assert.equal((await call(`/platform/rights-cases/${RH3_DEV_CASE_REF}/confirmation`, { confirmationGivenOnCasePage: true })).status, 404);
  } finally {
    await env.close();
  }
});
