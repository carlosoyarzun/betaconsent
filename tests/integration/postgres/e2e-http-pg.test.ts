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
import { RH3_DEV_CASE_REF, RH3_DEV_CHAIN_REF, RH3_DEV_REVOCATION_REF, seedRh3DevCase } from "../../../src/server/entrypoints/dev-rh3-seed.ts";
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
import { pgTest, seedFixture } from "./harness.ts";
import type { PgTestContext } from "./harness.ts";
import { TEST_OTP_SECRET, TEST_STAFF_ROSTER_CURSOR_KEY, TEST_GUEST_CHANNEL } from "../../helpers/test-ref-keys.ts";

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

async function boot(ctx: PgTestContext, guestChannel: { send(message: never): Promise<void> } = TEST_GUEST_CHANNEL) {
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
  const server = createConsentFlowHttpServer({ guestMessageChannel: guestChannel as typeof TEST_GUEST_CHANNEL, staffRosterCursorKey: TEST_STAFF_ROSTER_CURSOR_KEY,
    config: { allowedOrigin: ORIGIN },
    ports: bundle.ports,
    revocationPorts: bundle.revocationPorts,
    sessionSecret: randomBytes(32),
    environment: "LOCAL",
    staffIdentity,
    staffConsole: bundle.staffConsole,
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
  await seedFixture(() => env.store.uow.inTenant(T, (tx) =>
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
  )); // ADR-010 rev. 5 PR-b: fixture crudo (decision GRANTED sembrada): seedFixture
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

pgTest("TEST-CNS-875 e2e pg: el caso RH3 sembrado por el camino legal (RC1 -> RC2u -> RC3) queda IN_VERIFICATION con la Revocation REQUESTED y web ya no lo opera (dev-login CASE y /platform/* = 404); RH3 sobre platform: TEST-CNS-1711", async (ctx) => {
  const env = await boot(ctx);
  try {
    await seedRh3DevCase(env.bundle.ports, env.bundle.revocationPorts, T);
    // Camino legal: caso IN_VERIFICATION ligado a la Revocation REQUESTED, sin propuesta RH2 ni aprobador (RH2 solo por platform).
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM case_state.rights_case WHERE tenant_id = $1 AND case_ref = $2 AND status = 'IN_VERIFICATION' AND revocation_ref = $3", [T, RH3_DEV_CASE_REF, RH3_DEV_REVOCATION_REF]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM case_state.revocation WHERE tenant_id = $1 AND revocation_ref = $2 AND status = 'REQUESTED' AND proposal_ref IS NULL AND second_approver_ref IS NULL", [T, RH3_DEV_REVOCATION_REF]), 1);
    const login = await fetch(`${env.baseUrl}/__dev/staff-login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tenantId: T, caseRef: RH3_DEV_CASE_REF, principalRef: fixtureUuid("staff-synthetic-01") }),
    });
    assert.equal(login.status, 404, "sin dev-login CASE en web");
    assert.deepEqual(Object.keys(cookiesOf(login)), []);
    for (const suffix of ["/confirmation", "/confirmation/cosign", "/close"]) {
      const res = await fetch(`${env.baseUrl}/platform/rights-cases/${RH3_DEV_CASE_REF}${suffix}`, { method: "POST", headers: { "content-type": "application/json", origin: ORIGIN }, body: "{}" });
      assert.equal(res.status, 404, suffix);
    }
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM case_state.revocation WHERE tenant_id = $1 AND revocation_ref = $2 AND status = 'REQUESTED'", [T, RH3_DEV_REVOCATION_REF]), 1, "web no cambia el estado");
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
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1 AND chain_ref = $2", [T2, RH3_DEV_CHAIN_REF]), 0);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM case_state.rights_case WHERE tenant_id = $1 AND case_ref = $2", [T2, RH3_DEV_CASE_REF]), 0);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM case_state.revocation WHERE tenant_id = $1 AND revocation_ref = $2", [T2, RH3_DEV_REVOCATION_REF]), 0);
    assert.equal(await seedRh3DevCase(env.bundle.ports, rp, T2), true);
    assert.equal(await seedRh3DevCase(env.bundle.ports, rp, T2), false);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM case_state.rights_case WHERE tenant_id = $1 AND case_ref = $2 AND status = 'IN_VERIFICATION'", [T2, RH3_DEV_CASE_REF]), 1);
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

// TEST-CNS-1174 (sesion CASE de web en app.case_session) se retiro: la sesion CASE vive solo en platform.platform_session (ADR-010 rev. 5, 6d parte 2); equivalente sobre platform: TEST-CNS-1713.

/** Invitación -> OTP -> pasos de C2 hasta dejar la sesión lista para /decision/submit (o para /decision/subject-mismatch). */
async function pgVerifiedSession(env: Env, label: string): Promise<{ inv: string; session: string }> {
  const { ports } = env.bundle;
  const inv = fixtureUuid(`inv-${label}`);
  await createInvitation(ports.invitation, T, "INVITER", { enrollmentRef: fixtureUuid("enr-fixture"), participationRef: fixtureUuid("part-fixture"),
    invitationRef: inv,
    contextRef: LECTORPRO_BETA_CONFIG.contextRef,
    productRef: LECTORPRO_BETA_CONFIG.productRef,
    subjectRef: fixtureUuid(`subj-${label}`),
  });
  await markInvitationReady(ports.invitation, T, "INVITER", inv, { consentVersion: "v1-dev", expiresAt: new Date(Date.now() + 3_600_000), recipientChannelRef: `e2e-${label}@example.invalid` });
  const { token } = await sendInvitation(ports.invitation, T, "INVITER", inv, { deliveryChannel: "CONSENT_APP_EMAIL" });
  const redeemed = await fetch(`${env.baseUrl}/i/${token}`, { redirect: "manual" });
  const handle = cookiesOf(redeemed)["__Host-cns-i-handle"]!;
  const welcome = await fetch(`${env.baseUrl}/welcome`, { headers: { cookie: `__Host-cns-i-handle=${handle}` } });
  let session = cookiesOf(welcome)["__Host-cns-session"]!;
  const step = (res: Response): Response => {
    session = cookiesOf(res)["__Host-cns-session"] ?? session;
    return res;
  };
  assert.equal(step(await post(env, "/invitation/open", { "__Host-cns-session": session })).status, 200);
  assert.equal(step(await post(env, "/otp/request", { "__Host-cns-session": session })).status, 202);
  const code = env.otpSink.sent[env.otpSink.sent.length - 1]?.code ?? "";
  assert.equal(step(await post(env, "/otp/submit", { "__Host-cns-session": session }, { code })).status, 200);
  for (const body of [
    { stepKind: "CONTEXT_INFORMATION_VIEWED" },
    { stepKind: "CONSENT_VERSION_VIEWED" },
    { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true },
    { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true },
  ]) {
    assert.equal(step(await post(env, "/decision/steps", { "__Host-cns-session": session }, body)).status, 200);
  }
  return { inv, session };
}

pgTest("TEST-CNS-1417 e2e pg (app_rw): C3 registra el handle de gestion en la MISMA tx (RECEIPT_CREATED.managementLinkIssued=true, un handle nuevo, el enlace entregado resuelve /m); I9 persiste CANCELLED con exactamente un INVITATION_CANCELLED y una cookie vieja ya no opera (P1-1, P2-2, P2-3)", async (ctx) => {
  const env = await boot(ctx);
  try {
    const handlesBefore = await count(env, "SELECT count(*)::int AS n FROM tenant_resolve.handle WHERE tenant_id = $1", [T]);
    const g = await pgVerifiedSession(env, "1417g");
    const decided = await post(env, "/decision/submit", { "__Host-cns-session": g.session }, { purposes: GRANT_ALL });
    assert.equal(decided.status, 200);
    const { consentId } = (await decided.json()) as { consentId: string };
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = 'RECEIPT_CREATED' AND (payload->>'managementLinkIssued')::boolean IS TRUE", [T, consentId]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM tenant_resolve.handle WHERE tenant_id = $1", [T]), handlesBefore + 1);
    const linkMsg = [...TEST_GUEST_CHANNEL.sent].reverse().find((m) => m.kind === "MANAGEMENT_LINK");
    const path = linkMsg?.text.match(/(\/m\/[A-Za-z0-9_-]{20,})/)?.[1];
    assert.ok(path, "el mensaje de gestión lleva /m/<token>");
    const redeemed = await fetch(`${env.baseUrl}${path}`, { redirect: "manual" });
    assert.equal(redeemed.status, 303);
    const manage = await fetch(`${env.baseUrl}/manage`, { headers: { cookie: `__Host-cns-m-handle=${cookiesOf(redeemed)["__Host-cns-m-handle"]}` } });
    assert.equal(manage.status, 200);
    // COMPLETED: una cookie vieja ya no abre /decision (P-30).
    assert.equal((await fetch(`${env.baseUrl}/decision`, { headers: { cookie: `__Host-cns-session=${g.session}` } })).status, 404);

    // I9 contra la base bajo app_rw (CHECK 0043 + allowlist del ledger).
    const m = await pgVerifiedSession(env, "1417m");
    const first = await post(env, "/decision/subject-mismatch", { "__Host-cns-session": m.session });
    assert.equal(first.status, 200);
    assert.deepEqual(await first.json(), { result: "INVITATION_CANCELLED" });
    assert.equal((await post(env, "/decision/subject-mismatch", { "__Host-cns-session": m.session })).status, 200);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2 AND state = 'CANCELLED'", [T, m.inv]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = 'INVITATION_CANCELLED' AND payload->>'reasonCode' = 'SUBJECT_MISMATCH_REPORTED'", [T, m.inv]), 1);
    assert.equal((await fetch(`${env.baseUrl}/decision`, { headers: { cookie: `__Host-cns-session=${m.session}` } })).status, 404);
    assert.equal((await post(env, "/decision/steps", { "__Host-cns-session": m.session }, { stepKind: "CONTEXT_INFORMATION_VIEWED" })).status, 404);
  } finally {
    await env.close();
  }
});

pgTest("TEST-CNS-1449 e2e pg (app_rw): el fallo de entrega post-commit deja filas persistentes GUEST_MESSAGE_DELIVERY_FAILED en ops.security_event (RECEIPT y MANAGEMENT_LINK, receipt_ref opaca, sin otras columnas) y la decision sigue GRANTED (SEC-CNS-PR94 P2-A)", async (ctx) => {
  const env = await boot(ctx, { send: async (): Promise<void> => { throw new Error("SMTP_CAIDO persona@ejemplo.cl"); } });
  const bootConsoleError = console.error;
  const logs: string[] = [];
  console.error = (...a: unknown[]) => {
    const line = a.join(" ");
    logs.push(line);
    if (line.startsWith("request_failed")) bootConsoleError(...a);
  };
  try {
    const g = await pgVerifiedSession(env, "1449");
    const res = await post(env, "/decision/submit", { "__Host-cns-session": g.session }, { purposes: GRANT_ALL });
    assert.equal(res.status, 200);
    const { consentId, state, receiptRef } = (await res.json()) as { consentId: string; state: string; receiptRef: string };
    assert.equal(state, "GRANTED");
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2 AND state = 'GRANTED'", [T, consentId]), 1);
    const rows = (await env.admin.query<Record<string, string | null>>(
      "SELECT event_type, delivery_kind, receipt_ref::text AS receipt_ref, verification_ref, otp_scope, channel_ref, trigger_kind, chain_ref, recovery_ref, actor_ref, session_ref, case_ref FROM ops.security_event WHERE tenant_id = $1 AND receipt_ref = $2 ORDER BY event_seq",
      [T, receiptRef],
    )).rows;
    assert.deepEqual(rows.map((r) => [r.event_type, r.delivery_kind, r.receipt_ref]), [
      ["GUEST_MESSAGE_DELIVERY_FAILED", "RECEIPT", receiptRef],
      ["GUEST_MESSAGE_DELIVERY_FAILED", "MANAGEMENT_LINK", receiptRef],
    ]);
    for (const r of rows) assert.ok(Object.entries(r).every(([k, v]) => ["event_type", "delivery_kind", "receipt_ref"].includes(k) || v === null), "sin otras columnas pobladas");
    assert.ok(!logs.some((l) => /SMTP_CAIDO|persona@ejemplo|\/m\//.test(l)), "la alerta no lleva PII ni token");
    assert.ok(logs.includes("guest_message_delivery_failed kind=RECEIPT") && logs.includes("guest_message_delivery_failed kind=MANAGEMENT_LINK"));
    assert.ok(!logs.includes("guest_message_delivery_failure_not_persisted"), "los dos eventos se persistieron");
  } finally {
    console.error = bootConsoleError;
    await env.close();
  }
});

pgTest("TEST-CNS-1450 e2e pg (app_rw): rollback con inyeccion de fallo: si el registro del handle de gestion falla dentro de C3, la decision sigue PENDING, sin RECEIPT_CREATED/CONSENT_GRANTED/INVITATION_COMPLETED en el ledger, la invitacion VERIFIED y ningun handle nuevo; el reintento sano concluye (SEC-CNS-PR94 P2-B)", async (ctx) => {
  const env = await boot(ctx);
  const bootConsoleError = console.error;
  const swallowed: string[] = [];
  console.error = (...a: unknown[]) => {
    const line = a.join(" ");
    if (line.startsWith("request_failed")) swallowed.push(line); // el 500 inyectado es lo esperado; boot() no debe contarlo como fallo
    else bootConsoleError(...a);
  };
  try {
    const g = await pgVerifiedSession(env, "1450");
    const handlesBefore = await count(env, "SELECT count(*)::int AS n FROM tenant_resolve.handle WHERE tenant_id = $1", [T]);
    const ledgerBefore = await count(env, "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1", [T]);
    const healthy = env.bundle.ports.decision;
    let consentId = "";
    (env.bundle.ports as { decision: unknown }).decision = {
      ...healthy,
      uow: {
        inTenant: <R>(tenantId: never, work: (tx: never) => Promise<R>) =>
          healthy.uow.inTenant(tenantId, (tx) =>
            work({
              ...tx,
              managementHandles: {
                register: async (input: { revokedDecisionRef: string }) => {
                  consentId = input.revokedDecisionRef;
                  await (tx as { managementHandles: { register(i: unknown): Promise<void> } }).managementHandles.register(input); // el registro REAL ocurre y luego falla
                  throw new Error("fallo inyectado tras el registro del handle");
                },
              },
            } as never),
          ),
      },
    };
    const failed = await post(env, "/decision/submit", { "__Host-cns-session": g.session }, { purposes: GRANT_ALL });
    assert.equal(failed.status, 500);
    assert.equal(swallowed.length, 1);
    assert.ok(consentId, "el registro del handle se alcanzo (ultimo paso del lote C3)");

    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.consent_decision WHERE tenant_id = $1 AND consent_id = $2 AND state = 'PENDING' AND receipt_ref IS NULL", [T, consentId]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type IN ('CONSENT_GRANTED', 'RECEIPT_CREATED', 'CONSENT_DECLINED')", [T, consentId]), 0);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = 'INVITATION_COMPLETED'", [T, g.inv]), 0);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM app.invitation WHERE tenant_id = $1 AND invitation_ref = $2 AND state = 'VERIFIED'", [T, g.inv]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM tenant_resolve.handle WHERE tenant_id = $1", [T]), handlesBefore, "el INSERT real del handle se revirtio");
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1", [T]), ledgerBefore, "el ledger del tenant no cambio");

    // Sin residuo: con el registro sano el reintento concluye y deja RECEIPT_CREATED (managementLinkIssued=true) e INVITATION_COMPLETED.
    (env.bundle.ports as { decision: unknown }).decision = healthy;
    const retried = await post(env, "/decision/submit", { "__Host-cns-session": g.session }, { purposes: GRANT_ALL });
    assert.equal(retried.status, 200);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = 'RECEIPT_CREATED' AND (payload->>'managementLinkIssued')::boolean IS TRUE", [T, consentId]), 1);
    assert.equal(await count(env, "SELECT count(*)::int AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2 AND event_type = 'INVITATION_COMPLETED'", [T, g.inv]), 1);
  } finally {
    console.error = bootConsoleError;
    await env.close();
  }
});
