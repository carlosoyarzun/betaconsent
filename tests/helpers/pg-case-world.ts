// Gobierna: ADR-010 rev. 5 (enmienda rev. c, 2026-10-15) §4.2.a (G-3), §4.2.d, §5.4, §6, §10 fila 6d; GRD-RC-10, GRD-RC-12. Helper de TESTS (no es codigo de produccion): arma, sobre un Postgres real, un "mundo de caso"
// listo para conducir el proceso `platform` (RH2 propuesta/aprobacion/retiro, RH3, cierre) por el camino real: caso IN_VERIFICATION sembrado por el camino legal RC1 -> RC2u -> RC3 (seedRh3DevCase con la unidad de
// trabajo de app_rw), operadores/aprobador con rol ACTIVE, sesiones PLATFORM y CASE vivas (con grant vigente) y step-ups ATTESTED sembrados por superusuario (stand-in del verifier). Todo con refs propias por mundo
// (un case_ref es unico en toda la base: platform.rights_case_of). Solo sinteticos.

import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Client, Pool, PoolClient } from "pg";
import { createApplyGuardConfig } from "../../src/infra/adapters/postgres/apply-guard.adapter.ts";
import { createPgOidcAuthorization } from "../../src/infra/adapters/postgres/oidc-exchange.adapter.ts";
import { createPgPlatformCase } from "../../src/infra/adapters/postgres/platform-case.adapter.ts";
import { createPgPlatformSessionStore } from "../../src/infra/adapters/postgres/platform-session.adapter.ts";
import { createPool } from "../../src/infra/adapters/postgres/pool.ts";
import type { PoolLike } from "../../src/infra/adapters/postgres/pool.ts";
import { PgUnitOfWork } from "../../src/infra/adapters/postgres/unit-of-work.ts";
import { seedRh3DevCase } from "../../src/server/entrypoints/dev-rh3-seed.ts";
import type { Rh3DevRefs } from "../../src/server/entrypoints/dev-rh3-seed.ts";
import type { ConsentFlowPorts } from "../../src/server/entrypoints/http/consent-flow.handler.ts";
import type { RevocationFlowPorts } from "../../src/server/entrypoints/http/revocation-flow.handler.ts";
import { CASE_SESSION_COOKIE, PLATFORM_SESSION_COOKIE } from "../../src/server/entrypoints/platform/http-util.ts";
import { platformRequestHandler } from "../../src/server/entrypoints/platform/platform-process.ts";
import { loadPlatformSettings } from "../../src/server/entrypoints/platform/platform-settings.ts";
import type { ApplyGuardConfig } from "../../src/server/modules/revocation/apply-guard.ts";
import type { PlatformCasePort } from "../../src/server/ports/platform-case.port.ts";
import { fixtureUuid } from "../contract/uuid-fixture.ts";
import type { PgTestContext } from "../integration/postgres/harness.ts";
import { seedOperator } from "./pg-login-flow.ts";
import { seedCaseSession, seedPlatformSession } from "./pg-platform-session.ts";
import type { SeededSession } from "./pg-platform-session.ts";

export { seedOperator, seedCaseSession, seedPlatformSession };
export type { SeededSession };

const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

/** Siembra (superusuario) un nonce de step-up ATTESTED con su asercion del IdP (auth_time = hace `authAgoSeconds`): stand-in del verifier. `target` = proposalRef (RH2) o el recurso de la accion. */
/** P2-6: el destino del step-up de RH2 liga caso Y propuesta (`<caseRef>:<proposalRef>`; 0069/0070). */
export const rh2Target = (caseRef: string, proposalRef: string): string => `${caseRef}:${proposalRef}`;

export async function seedAttestedStepUp(admin: Client, principal: string, action: string, target: string, authAgoSeconds = 0): Promise<string> {
  const hash = sha(randomUUID());
  await admin.query(
    `INSERT INTO platform.action_nonce (nonce_hash, scope, tenant_id, action, refs_digest, principal_ref, expires_at) VALUES ($1, 'PLATFORM', NULL, $2, $3, $4, now() + interval '5 minutes')`,
    [hash, action, sha(target), principal],
  );
  await admin.query("UPDATE platform.action_nonce SET attested_at = now() WHERE nonce_hash = $1", [hash]);
  await admin.query(
    `INSERT INTO platform.grant_assertion (exchange_ref, binding, principal_ref, decision, sub_hmac, assertion_hash, auth_time) VALUES ($1, $2, $3, 'ATTESTED', $4, $5, now() - make_interval(secs => $6))`,
    [randomUUID(), hash, principal, sha(`sub-${principal}`), sha(randomUUID()), authAgoSeconds],
  );
  return hash;
}

export interface WorldActor {
  readonly principal: string;
  readonly sub: string;
  /** Sesion PLATFORM viva. */
  readonly platform: SeededSession;
}

export interface CaseWorld {
  readonly label: string;
  readonly tenantId: string;
  readonly caseRef: string;
  readonly revocationRef: string;
  readonly consentId: string;
  readonly chainRef: string;
  readonly refs: Rh3DevRefs;
  /** RIGHTS_OPERATOR con sesion CASE (propone, retira, registra RH3). */
  readonly op1: WorldActor & { readonly caseSession: SeededSession };
  /** Segundo RIGHTS_OPERATOR con sesion CASE (co-firma RH3: cuatro ojos). */
  readonly op2: WorldActor & { readonly caseSession: SeededSession };
  /** APPROVER con sesion PLATFORM (aprueba RH2). */
  readonly approver: WorldActor;
}

export function worldRefs(label: string): Rh3DevRefs {
  const u = (part: string): string => fixtureUuid(`world-${label}-${part}`);
  return {
    chainRef: u("chain"), consentId: u("consent"), caseRef: u("case"), revocationRef: u("revocation"), subjectRef: u("subject"), invitationRef: u("invitation"), verificationRef: u("verification"),
    dmRef: u("dm"), enrollmentRef: u("enrollment"), participationRef: u("participation"), receiptRef: u("receipt"),
  };
}

/** Abre un pool de app_rw, siembra el caso por el camino legal (RC1 -> RC2u -> RC3) con refs propias y lo cierra. */
async function seedCase(ctx: PgTestContext, tenantId: string, refs: Rh3DevRefs): Promise<void> {
  const pool = createPool({ connectionString: ctx.urlFor("app_rw"), max: 2 });
  try {
    const uow = new PgUnitOfWork(pool);
    // seedRh3DevCase solo usa `revocationPorts.revocation.uow`; los demas puertos no intervienen.
    const seeded = await seedRh3DevCase({} as ConsentFlowPorts, { revocation: { uow } } as unknown as RevocationFlowPorts, tenantId, refs);
    if (!seeded) throw new Error(`el mundo ${refs.caseRef} ya existia`);
  } finally {
    await pool.end();
  }
}

async function actor(admin: Client, principal: string, role: string): Promise<WorldActor> {
  const sub = await seedOperator(admin, principal, role);
  return { principal, sub, platform: await seedPlatformSession(admin, principal, { absoluteSeconds: 14400, idleSeconds: 900 }) };
}

/**
 * Mundo de caso completo con refs propias por `label` (unico por test). El tenant por defecto es propio del mundo (fixtureUuid) para no mezclar tests del mismo archivo (la base se comparte).
 */
export async function seedCaseWorld(ctx: PgTestContext, label: string, opts: { tenantId?: string } = {}): Promise<CaseWorld> {
  const admin = await ctx.fixtureAdmin();
  const tenantId = opts.tenantId ?? fixtureUuid(`world-${label}-tenant`);
  const refs = worldRefs(label);
  await seedCase(ctx, tenantId, refs);
  const withCase = async (principal: string, role: string): Promise<WorldActor & { caseSession: SeededSession }> => {
    const a = await actor(admin, principal, role);
    return { ...a, caseSession: await seedCaseSession(admin, principal, a.platform, refs.caseRef, tenantId) };
  };
  return {
    label, tenantId, caseRef: refs.caseRef, revocationRef: refs.revocationRef, consentId: refs.consentId, chainRef: refs.chainRef, refs,
    op1: await withCase(fixtureUuid(`world-${label}-op1`), "RIGHTS_OPERATOR"),
    op2: await withCase(fixtureUuid(`world-${label}-op2`), "RIGHTS_OPERATOR"),
    approver: await actor(admin, fixtureUuid(`world-${label}-approver`), "APPROVER"),
  };
}

export interface PlatformHttp {
  readonly base: string;
  readonly origin: string;
  readonly pool: Pool;
  readonly server: Server;
  readonly cases: PlatformCasePort;
  /** POST JSON con la cookie de sesion indicada (CASE por defecto) y el Origin del proceso. */
  post(path: string, sid: string | null, body?: unknown, opts?: { kind?: "PLATFORM" | "CASE"; headers?: Record<string, string> }): Promise<{ status: number; body: string; setCookie: string[] }>;
  close(): Promise<void>;
}

export interface PlatformHttpOptions {
  /** Guardia de R4 (G-3). Por defecto: 3 intentos, sin espera, alerta por la sesion CASE (la fabrica de platform-process). */
  readonly applyGuard?: Partial<{ maxAttempts: number; log: (line: string) => void }>;
  /** Envuelve el puerto de casos (p. ej. para observar o decorar llamadas). */
  readonly wrapCases?: (cases: PlatformCasePort) => PlatformCasePort;
  /** Pool que usa SOLO el adaptador de casos (las sesiones usan el pool real): p. ej. `ambiguousCommitPool` para inyectar un commit ambiguo. */
  readonly casePool?: (pool: Pool) => PoolLike;
}

/** Proceso platform en memoria del test (puerto efimero) sobre un pool de platform_rw REAL: sesiones, step-up y acciones de caso contra Postgres. */
export async function startPlatformHttp(ctx: PgTestContext, options: PlatformHttpOptions = {}): Promise<PlatformHttp> {
  const pool = createPool({ connectionString: ctx.urlFor("platform_rw"), max: 4 });
  const origin = "http://127.0.0.1:8788";
  const settings = loadPlatformSettings({
    CNS_PLATFORM_P49_MAX: "100000", CNS_PLATFORM_P50_MAX: "100000", CNS_PLATFORM_IDP_AUTHORIZATION_ENDPOINT: "http://127.0.0.1:9000/authorize", CNS_PLATFORM_IDP_CLIENT_ID: "consent-platform",
    CNS_PLATFORM_REDIRECT_URI: `${origin}/platform/auth/callback`,
  }, "LOCAL");
  const base: PlatformCasePort = createPgPlatformCase(options.casePool === undefined ? pool : options.casePool(pool), {
    applyGuard: createApplyGuardConfig(async () => {}, { maxAttempts: options.applyGuard?.maxAttempts ?? 3, sleep: async () => {}, log: options.applyGuard?.log ?? (() => {}) }),
  });
  const cases = options.wrapCases === undefined ? base : options.wrapCases(base);
  const server = createServer(platformRequestHandler({ authorization: createPgOidcAuthorization(pool), sessions: createPgPlatformSessionStore(pool), cases, settings }));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    base: url, origin, pool, server, cases,
    async post(path, sid, body = {}, opts = {}) {
      const cookieName = (opts.kind ?? "CASE") === "PLATFORM" ? PLATFORM_SESSION_COOKIE : CASE_SESSION_COOKIE;
      const res = await fetch(`${url}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", origin, ...(sid === null ? {} : { cookie: `${cookieName}=${sid}` }), ...(opts.headers ?? {}) },
        body: JSON.stringify(body),
      });
      return { status: res.status, body: await res.text(), setCookie: res.headers.getSetCookie() };
    },
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await pool.end();
    },
  };
}

export type { ApplyGuardConfig };

/** Rutas de las acciones de caso del proceso platform. */
export const casePath = (caseRef: string) => ({
  proposals: `/platform/rights-cases/${caseRef}/verification-proposals`,
  approval: (proposalRef: string) => `/platform/rights-cases/${caseRef}/verification-proposals/${proposalRef}/approval`,
  withdrawal: (proposalRef: string) => `/platform/rights-cases/${caseRef}/verification-proposals/${proposalRef}/withdrawal`,
  confirmation: `/platform/rights-cases/${caseRef}/confirmation`,
  cosign: `/platform/rights-cases/${caseRef}/confirmation/cosign`,
  close: `/platform/rights-cases/${caseRef}/close`,
});

/** Lleva el caso a RH2 atestada (propuesta del operador 1 + aprobacion del APPROVER) por las rutas HTTP de platform. */
export async function attestRh2(admin: Client, http: PlatformHttp, w: CaseWorld, label = "rh2"): Promise<string> {
  const proposalRef = fixtureUuid(`world-${w.label}-${label}`);
  await seedAttestedStepUp(admin, w.op1.principal, "PROPOSE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
  const proposed = await http.post(casePath(w.caseRef).proposals, w.op1.caseSession.sid, { proposalRef, verificationScriptVersion: "guion-1" });
  if (proposed.status !== 201) throw new Error(`propuesta RH2 rechazada: ${proposed.status} ${proposed.body}`);
  await seedAttestedStepUp(admin, w.approver.principal, "APPROVE_CASE_VERIFICATION", rh2Target(w.caseRef, proposalRef));
  const approved = await http.post(casePath(w.caseRef).approval(proposalRef), w.approver.platform.sid, {}, { kind: "PLATFORM" });
  if (approved.status !== 200) throw new Error(`aprobacion RH2 rechazada: ${approved.status} ${approved.body}`);
  return proposalRef;
}

/** RH2 atestada + RH3 paso 1 (registro del operador 1): deja la Revocation VERIFIED lista para la co-firma del operador 2. */
export async function recordRh3(admin: Client, http: PlatformHttp, w: CaseWorld): Promise<void> {
  await attestRh2(admin, http, w);
  const recorded = await http.post(casePath(w.caseRef).confirmation, w.op1.caseSession.sid, { confirmationGivenOnCasePage: true });
  if (recorded.status !== 200) throw new Error(`registro RH3 rechazado: ${recorded.status} ${recorded.body}`);
}

export interface OutboxFailure {
  /** Intentos de insercion en app.outbox del tenant observados (incluye los que fallaron y se revirtieron). */
  attempts(): Promise<number>;
  remove(): Promise<void>;
}

/**
 * Fallo inyectado: trigger BEFORE INSERT en app.outbox (el ULTIMO paso de R4/C6) que lanza `sqlstate` en los primeros `failures` intentos del tenant. El contador es una SECUENCIA (no transaccional:
 * sobrevive al rollback de cada intento). Solo en la base descartable del archivo de test. `failures` grande = fallo permanente.
 */
export async function injectOutboxFailure(admin: Client, o: { name: string; tenantId: string; failures: number; sqlstate: string }): Promise<OutboxFailure> {
  if (!/^[a-z0-9_]+$/.test(o.name) || !/^[0-9A-Z]{5}$/.test(o.sqlstate) || !/^[0-9a-f-]{36}$/.test(o.tenantId)) throw new Error("parametros de inyeccion invalidos");
  await admin.query("CREATE SCHEMA IF NOT EXISTS qa_inject");
  await admin.query("GRANT USAGE ON SCHEMA qa_inject TO PUBLIC");
  await admin.query(`CREATE SEQUENCE qa_inject.${o.name}_seq`);
  await admin.query(`GRANT USAGE ON SEQUENCE qa_inject.${o.name}_seq TO PUBLIC`);
  await admin.query(`CREATE OR REPLACE FUNCTION qa_inject.fail_fn() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $f$
    BEGIN
      IF nextval(TG_ARGV[0]::regclass) <= TG_ARGV[1]::integer THEN RAISE EXCEPTION 'fallo inyectado' USING ERRCODE = TG_ARGV[2]; END IF;
      RETURN NEW;
    END $f$`);
  await admin.query("GRANT EXECUTE ON FUNCTION qa_inject.fail_fn() TO PUBLIC");
  await admin.query(`CREATE TRIGGER ${o.name}_trg BEFORE INSERT ON app.outbox FOR EACH ROW WHEN (NEW.tenant_id = '${o.tenantId}') EXECUTE FUNCTION qa_inject.fail_fn('qa_inject.${o.name}_seq', '${o.failures}', '${o.sqlstate}')`);
  return {
    async attempts() {
      const r = (await admin.query<{ last_value: string; is_called: boolean }>(`SELECT last_value, is_called FROM qa_inject.${o.name}_seq`)).rows[0]!;
      return r.is_called ? Number(r.last_value) : 0;
    },
    async remove() {
      await admin.query(`DROP TRIGGER IF EXISTS ${o.name}_trg ON app.outbox`);
    },
  };
}

/**
 * Commit ambiguo: el COMMIT SI se ejecuta en la base, pero al cliente le llega una conexion perdida (SQLSTATE 08006). Se arma con `times` cuantos COMMIT consecutivos fallan asi. Envuelve el pool que
 * recibe el adaptador de casos (opcion `casePool` de startPlatformHttp).
 */
export function ambiguousCommitPool(times = 0): { wrap: (pool: Pool) => PoolLike; fired(): number; arm(n: number): void } {
  let remaining = times;
  let fired = 0;
  const PATCHED = Symbol.for("qa.ambiguousCommit");
  return {
    fired: () => fired,
    arm: (n) => { remaining = n; },
    wrap: (pool) => ({
      async connect(): Promise<PoolClient> {
        const client = await pool.connect();
        const tagged = client as PoolClient & { [PATCHED]?: boolean };
        if (tagged[PATCHED] !== true) {
          tagged[PATCHED] = true;
          const original = client.query.bind(client) as (...args: unknown[]) => Promise<unknown>;
          // El pool es compartido con las sesiones: solo falla el COMMIT de la tx que llamo a la co-firma.
          let sawCosign = false;
          (client as unknown as { query: unknown }).query = async (...args: unknown[]): Promise<unknown> => {
            if (typeof args[0] === "string" && args[0].includes("cosign_case_confirmation")) sawCosign = true;
            if (args[0] === "ROLLBACK") sawCosign = false;
            if (args[0] === "COMMIT" && sawCosign && remaining > 0) {
              sawCosign = false;
              remaining -= 1;
              fired += 1;
              await original("COMMIT");
              throw Object.assign(new Error("connection terminated unexpectedly"), { code: "08006" });
            }
            return original(...args);
          };
        }
        return client;
      },
    }),
  };
}

/**
 * Anomalia de R4 (fila anterior a 0066 o fallo de infraestructura): deja la Revocation CONFIRMED (co-firma aplicada) SIN APPLIED, con su evento REVOCATION_CONFIRMED, escrita por superusuario con las mismas funciones de
 * la base. Requiere RH2 atestada y RH3 paso 1 (`recordRh3`). Es el unico estado que el respaldo del worker debe recuperar. Solo tests.
 */
export async function seedConfirmedWithoutApplied(admin: Client, w: CaseWorld): Promise<void> {
  await admin.query("BEGIN");
  try {
    await admin.query("SELECT set_config('app.tenant_id', $1, true)", [w.tenantId]);
    await admin.query("SELECT set_config('case_state.effect', 'cosign_case_confirmation', true)");
    const seq = Number((await admin.query<{ n: number }>("SELECT COALESCE(max(sequence), 0)::integer AS n FROM integrity.audit_event WHERE tenant_id = $1 AND aggregate_id = $2", [w.tenantId, w.revocationRef])).rows[0]!.n);
    // El guard INV-RV-12 solo deja escribir a las funciones case_state: se deshabilita DENTRO de esta tx de fixture y se vuelve a dejar ENABLE ALWAYS antes del COMMIT (solo tests).
    await admin.query("ALTER TABLE case_state.revocation DISABLE TRIGGER revocation_transition_guard");
    await admin.query("UPDATE case_state.revocation SET status = 'CONFIRMED', cosigned_by_ref = $3 WHERE tenant_id = $1 AND revocation_ref = $2", [w.tenantId, w.revocationRef, w.op2.principal]);
    await admin.query("ALTER TABLE case_state.revocation ENABLE ALWAYS TRIGGER revocation_transition_guard");
    await admin.query(
      "SELECT case_state.ledger_append('Revocation', $1::text, 'REVOCATION_CONFIRMED', 'HUMAN', 'DECISION_MAKER', $2::text, $3::text, jsonb_build_object('revocationRef', $1::text, 'recordedByRef', $2::text, 'cosignedByRef', $3::text), $1::text || ':rh3', $4::integer)",
      [w.revocationRef, w.op1.principal, w.op2.principal, seq],
    );
    await admin.query("COMMIT");
  } catch (error) {
    await admin.query("ROLLBACK");
    throw error;
  }
}
