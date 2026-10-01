// Gobierna: ADR-001 §11 (adaptadores solo importados por src/server/entrypoints/**). Único
// punto de cableado in-memory IT0 del flujo invitación -> OTP -> decisión sobre node:http
// puro (sin frameworks, sin dependencias nuevas), análogo a server.ts (RC2u).

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";

import { deriveChainRefKey } from "../../modules/consent-decision/chain-ref.ts";
import { deriveDecisionMakerRefKey } from "../../modules/consent-decision/decision-maker-ref.ts";
import type { OutboxEnvelope } from "../../ports/outbox.port.ts";
import { createInMemoryConsentDecisionRepository } from "../../../infra/adapters/in-memory-consent-decision-repository.adapter.ts";
import { createInMemoryEligibilityAdapter } from "../../../infra/adapters/in-memory-eligibility.adapter.ts";
import { createInMemoryInvitationRepository } from "../../../infra/adapters/in-memory-invitation-repository.adapter.ts";
import { createInMemoryLedgerAdapter } from "../../../infra/adapters/in-memory-ledger.adapter.ts";
import { createInMemoryTenancy } from "../../../infra/adapters/in-memory-tenancy.ts";
import { createInMemoryOtpChannelSink } from "../../../infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryOtpVerificationRepository } from "../../../infra/adapters/in-memory-otp-verification-repository.adapter.ts";
import type { InMemoryOtpChannelSink } from "../../../infra/adapters/in-memory-otp-channel-sink.adapter.ts";
import { createInMemoryOutboxAdapter } from "../../../infra/adapters/in-memory-outbox.adapter.ts";
import type { InMemoryOutbox } from "../../../infra/adapters/in-memory-outbox.adapter.ts";
import { createInMemoryRecoveryLinkChannelSink } from "../../../infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import type { InMemoryRecoveryLinkChannelSink } from "../../../infra/adapters/in-memory-recovery-link-channel-sink.adapter.ts";
import { createInMemoryRecoveryTokenRepository } from "../../../infra/adapters/in-memory-recovery-token-repository.adapter.ts";
import { createInMemoryRevocationRepository } from "../../../infra/adapters/in-memory-revocation-repository.adapter.ts";
import { createInMemoryRightsCaseRepository } from "../../../infra/adapters/in-memory-rights-case-repository.adapter.ts";
import { createInMemoryTenantHandleAdapter } from "../../../infra/adapters/in-memory-tenant-handle.adapter.ts";
import { createInMemoryStaffIdentityAdapter } from "../../../infra/adapters/in-memory-staff-identity.adapter.ts";
import { createInMemoryEnrollmentRepository } from "../../../infra/adapters/in-memory-enrollment-repository.adapter.ts";
import { createInMemoryIdempotencyAdapter, LOCAL_ONLY_IN_MEMORY_IDEMPOTENCY_TTL_MS } from "../../../infra/adapters/in-memory-idempotency.adapter.ts";
import {
  createInMemoryInvitationLinkChannelSink,
  type InMemoryInvitationLinkChannelSink,
} from "../../../infra/adapters/in-memory-invitation-link-channel-sink.adapter.ts";
import { createInMemoryTenantCatalogAdapter, type FixtureTenantCatalogPort } from "../../../infra/adapters/in-memory-tenant-catalog.adapter.ts";
import type { IdempotencyPolicy } from "../../modules/common/idempotency-policy.config.ts";
import type { PostgresStore } from "../../../infra/adapters/postgres/store.ts";
import type { InvitationIssuancePolicy } from "../../modules/invitation/invitation-issuance-policy.config.ts";
import { LECTORPRO_BETA_CONFIG } from "../../modules/consent-decision/lectorpro-beta.config.ts";
import type { DecisionRelationshipConfig } from "../../modules/consent-decision/decision-relationship.config.ts";
import type { Environment } from "../../modules/common/types.ts";
import type { InvitationPorts } from "../../modules/invitation/invitation.ts";
import type { OtpChallengePorts, OtpPolicy } from "../../modules/otp-challenge/otp-challenge.ts";
import type { ConsentDecisionPorts } from "../../modules/consent-decision/consent-decision.ts";
import type { RecoveryTokenPolicy } from "../../modules/revocation/recovery-token-policy.config.ts";
import type { RecoveryHandlePolicy } from "../../modules/revocation/recovery-handle-policy.config.ts";
import type { InvitationHandlePolicy } from "../../modules/invitation/invitation-handle-policy.config.ts";
import type { ManageHandlePolicy } from "../../modules/revocation/manage-handle-policy.config.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { ConsentDecisionRepositoryPort } from "../../ports/consent-decision-repository.port.ts";
import type { StaffIdentityPort } from "../../ports/staff-identity.port.ts";
import { loadRightsCaseHttpConfig, type RightsCaseHttpConfig } from "./config.ts";
import {
  handleOpenInvitation,
  handleRecordDecisionStep,
  handleRedeemInvitationLink,
  handleRequestOtp,
  handleResendOtp,
  handleSubmitDecision,
  handleSubmitOtp,
  resolveWelcomeLandingSession,
  type ConsentFlowPorts,
  type HttpResult,
  type RawConsentRequest,
} from "./consent-flow.handler.ts";
import {
  handleConfirmRevocation,
  handleIssueRecoveryLink,
  handleOpenRightsCase,
  handleRecoveryRevoke,
  handleRedeemManagementLink,
  handleRedeemRecoveryLink,
  handleRequestRevocation,
  handleVerifyRevocation,
  handleWithdrawRevocation,
  resolveManageLandingSession,
  resolveRecoveryConfirmView,
  type RevocationFlowPorts,
} from "./revocation-flow.handler.ts";
import {
  handleApproveCaseVerification,
  handleWithdrawCaseVerificationProposal,
  handleCosignCaseConfirmation,
  handleDevStaffLogin,
  handleProposeCaseVerification,
  handleRecordCaseConfirmation,
  type CaseConfirmationPorts } from "./case-confirmation.handler.ts";
import { parseCookies } from "./cookies.ts";
import { decodeSession } from "./consent-session.ts";
import { deriveCaseSessionKey } from "./case-session.ts";
import { deriveStaffSessionKey } from "./staff-session.ts";
import {
  handleCreateInvitation,
  handleDevStaffConsoleLogin,
  handleMarkInvitationReady,
  handleOpenEnrollment,
  handleSendInvitation,
  type StaffConsolePorts,
} from "./staff-console.handler.ts";
import { generateCsrfToken, serializeCsrfCookie } from "./csrf.ts";
import { deriveRecoveryCsrfKey, deriveRecoveryHandleKey, generateRecoveryCsrfToken } from "./recovery-handle.ts";
import { deriveLinkHandleKey } from "./link-handle.ts";
import { renderWelcomePage, renderWelcomeUniformErrorPage } from "./welcome-page.ts";
import { renderVerifyPage, renderVerifyUniformErrorPage } from "./verify-page.ts";
import { renderDecisionPage, renderDecisionUniformErrorPage } from "./decision-page.ts";
import { renderManageEntryPage, renderManageRevokedPage, renderManageStatusPage, renderManageUniformErrorPage } from "./manage-page.ts";
import { renderRevocationConfirmPage, renderRevocationUniformErrorPage } from "./revocation-page.ts";
import { renderRecoveryConfirmPage, renderRecoveryUniformErrorPage } from "./recovery-page.ts";
import { getServedConsentVersion } from "./served-consent-version.ts";
import { resolveStaticAsset } from "./static-assets.ts";
import { handleDevStaffConsole, isDevStaffConsolePath, type DevStaffConsoleFixture } from "./dev-staff-console.handler.ts";

export interface ConsentFlowHttpServerOptions {
  readonly config?: Partial<RightsCaseHttpConfig>;
  readonly ports?: ConsentFlowPorts;
  /** CA-116 (revocación IT0): ports de GET /m/{token} y el flujo self-service R1-R3/R8/RV0/RC1.
   * Si se omite junto con `ports`, se construye con createDefaultRevocationFlowPorts (mismo
   * ledger que `ports.decision.ledger`, TenantHandlePort in-memory vacío: dev.ts/los tests
   * siembran handles explícitamente con `.issue()`). */
  readonly revocationPorts?: RevocationFlowPorts;
  /** Secreto HMAC de la sesión (D5). Si se omite, se genera uno aleatorio por proceso (solo
   * válido mientras el proceso vive; nunca se persiste ni se loguea). */
  readonly sessionSecret?: Buffer;
  /** P-01/P-02/P-03 (otp-policy.config.ts); requerido si no se inyectan `ports` propios. */
  readonly otpPolicy?: OtpPolicy;
  /** GRD-CD-04 (decision-relationship.config.ts); requerido si no se inyectan `ports` propios. */
  readonly relationshipConfig?: DecisionRelationshipConfig;
  /** P-15 (recovery-token-policy.config.ts, CA-116 PR 2); si se omite junto con
   * `revocationPorts`, createDefaultRevocationFlowPorts exige pasarlo explícito (fail-closed,
   * mismo patrón que otpPolicy). */
  readonly recoveryTokenPolicy?: RecoveryTokenPolicy;
  /** P-18 (recovery-handle-policy.config.ts, ADR-006 §6.2, SEC-CNS-014). Si se omite, este
   * servidor usa DEFAULT_TEST_RECOVERY_HANDLE_POLICY (mismo criterio D4 que
   * DEFAULT_TEST_RECOVERY_TOKEN_POLICY: LOCAL/test-only, nunca un default de producción). */
  readonly recoveryHandlePolicy?: RecoveryHandlePolicy;
  /** SEC-CNS-014 patrón (Carlos, 2026-09-28), link-handle.ts: TTL de la cookie
   * `__Host-cns-i-handle` que fija GET /i/{token} sin leer la BD. Si se omite, este servidor usa
   * DEFAULT_TEST_INVITATION_HANDLE_POLICY (mismo criterio D4 LOCAL/test-only que
   * DEFAULT_TEST_RECOVERY_HANDLE_POLICY). */
  readonly invitationHandlePolicy?: InvitationHandlePolicy;
  /** SEC-CNS-014 patrón (Carlos, 2026-09-28), link-handle.ts: TTL de la cookie
   * `__Host-cns-m-handle` que fija GET /m/{token} sin leer la BD. Si se omite, este servidor usa
   * DEFAULT_TEST_MANAGE_HANDLE_POLICY (mismo criterio D4 LOCAL/test-only). */
  readonly manageHandlePolicy?: ManageHandlePolicy;
  /**
   * Entorno de ejecución (GRD-CM-13). Solo cuando es exactamente "LOCAL" este servidor expone
   * GET /__dev/otp-sink (dev.ts, D4/D5 report a Carlos: sink de depuración, cero PII más allá
   * de la ya presente en el canal sintético de la invitación). Cualquier otro valor, incluido
   * "undefined", deja la ruta fuera (fail-closed).
   */
  readonly environment?: Environment;
  /**
   * CA-128 (API-CNS-138, RH3 paso 1). StaffIdentityPort: lista nominal sintética de RIGHTS_OPERATOR
   * y aprobadores (GRD-RC-15), inyectada por dev.ts (LOCAL_ONLY_DEV_STAFF_ROSTER) o los tests.
   * Si se omite, un adaptador in-memory con roster vacío: fail-closed por defecto (GRD-RC-15
   * ERR-RC-10 siempre, mismo criterio D4 que tenantHandle vacío en createDefaultRevocationFlowPorts),
   * nunca una lista de producción hardcodeada.
   */
  readonly staffIdentity?: StaffIdentityPort;
  /**
   * CA-125 (API-CNS-105/110/111/112): ports de la consola STAFF (enrolar e invitar). Si se omite,
   * createDefaultStaffConsolePorts los cablea sobre el mismo `ports.invitation` del flujo del
   * portador (así una invitación creada por staff se abre por GET /i/{token}), con catálogo de
   * tenant VACÍO y sin `invitationIssuancePolicy` (fail-closed: EN0/I1 responden 404/409 y
   * I2/I3 ERR-CM-12). dev.ts y los tests inyectan catálogo y política LOCAL-only.
   */
  readonly staffConsole?: StaffConsolePorts;
  /** SEC-CNS-017 F3: modo de almacenamiento, explicito (no se infiere del Proxy de puertos). `memory` por defecto. */
  readonly storeMode?: "memory" | "postgres";
  /** Solo storeMode=postgres + LOCAL: lector del outbox del tenant de dev (dentro de inTenant/withTenantTx de ese
   * tenant, RLS). Sin el, GET /__dev/outbox-sink responde 404 en postgres. */
  readonly devOutboxSink?: () => Promise<readonly OutboxEnvelope[]>;
  /** CA-125 (Carlos 2026-10-01): datos sintéticos de la consola dev GET /__dev/staff-console. Sin esto, o fuera de
   * LOCAL, la ruta no existe (404, GRD-CM-13). */
  readonly devStaffConsole?: DevStaffConsoleFixture;
}

/** CA-125: cableado por defecto (in-memory) de la consola STAFF. `policy` (P-10 + deliveryChannel,
 * EXT-B) no tiene default de producción: sin él, I2/I3 fallan cerrado. */
export function createDefaultStaffConsolePorts(
  invitation: InvitationPorts,
  staffIdentity: StaffIdentityPort,
  policy?: InvitationIssuancePolicy,
  idempotencyPolicy?: IdempotencyPolicy,
): StaffConsolePorts & { readonly invitationLinkSink: InMemoryInvitationLinkChannelSink; readonly catalog: FixtureTenantCatalogPort } {
  const enrollmentRepo = createInMemoryEnrollmentRepository();
  // CA-124: UoW de EN0 sobre el MISMO enrollmentRepo (y el ledger/invitationRepo compartidos).
  const tenantCatalog = createInMemoryTenantCatalogAdapter();
  const idempotency = createInMemoryIdempotencyAdapter({ ttlMs: idempotencyPolicy ? idempotencyPolicy.ttlMs : LOCAL_ONLY_IN_MEMORY_IDEMPOTENCY_TTL_MS });
  const tenancy = createInMemoryTenancy({ ledger: invitation.ledger, enrollmentRepo, invitationRepo: invitation.invitationRepo, tenantCatalog, idempotency });
  const invitationLinkSink = createInMemoryInvitationLinkChannelSink();
  return {
    issuance: { invitation, enrollmentRepo, tenantCatalog, invitationLinkChannel: invitationLinkSink, ...(policy ? { policy } : {}) },
    enrollment: { enrollmentRepo, tenantCatalog, ledger: invitation.ledger, uow: tenancy.uow },
    uow: tenancy.uow,
    staffIdentity,
    invitationLinkSink,
    catalog: tenantCatalog,
  };
}

/** `relationshipConfig` es obligatorio, mismo patrón fail-closed que `otpPolicy` (D4,
 * decision-relationship.config.ts): sin default de producción en esta función; el caller
 * (dev.ts LOCAL, o tests) siempre pasa un override explícito. */
export function createDefaultConsentFlowPorts(
  otpPolicy: OtpPolicy,
  relationshipConfig: DecisionRelationshipConfig,
  chainRefKey: Buffer = deriveChainRefKey(randomBytes(32)),
  decisionMakerRefKey: Buffer = deriveDecisionMakerRefKey(randomBytes(32)),
): ConsentFlowPorts {
  const ledger = createInMemoryLedgerAdapter();
  const invitationRepo = createInMemoryInvitationRepository();
  const otpRepo = createInMemoryOtpVerificationRepository();
  const decisionRepo = createInMemoryConsentDecisionRepository();
  // CA-124: UoW + resolver in-memory sobre los MISMOS adaptadores del flujo de consentimiento.
  const tenancy = createInMemoryTenancy({ ledger, invitationRepo, otpRepo, consentDecisionRepo: decisionRepo });
  const invitation: InvitationPorts = {
    invitationRepo,
    eligibility: createInMemoryEligibilityAdapter(),
    ledger,
    ...tenancy,
  };
  const otp: OtpChallengePorts = {
    otpRepo,
    channel: createInMemoryOtpChannelSink(),
    ledger,
    invitation,
    uow: tenancy.uow,
    policy: otpPolicy,
    secret: randomBytes(32),
  };
  const decision: ConsentDecisionPorts = {
    repo: decisionRepo,
    ledger,
    invitation,
    uow: tenancy.uow,
    config: LECTORPRO_BETA_CONFIG,
    relationships: relationshipConfig,
    chainRefKey,
  };
  return { invitation, otp, decision, decisionMakerRefKey };
}

/** Convenience LOCAL/test-only (nunca de producción real: esta función entera solo construye
 * adaptadores in-memory): a diferencia de `loadRecoveryTokenPolicyConfig` (fail-closed, D4, sin
 * default), la mayoría de los tests HTTP de este repo no ejercitan recovery y no deberían tener
 * que pasar un P-15 explícito solo para construir el servidor. Mismo criterio que el default
 * `sessionSecret ?? randomBytes(32)` de createConsentFlowHttpServer: válido solo mientras el
 * proceso vive, nunca persistido ni usado como recomendación de producto. dev.ts y los tests que
 * SÍ prueban recovery pasan su propio override vía `loadRecoveryTokenPolicyConfig`. */
const DEFAULT_TEST_RECOVERY_TOKEN_POLICY: RecoveryTokenPolicy = { ttlMs: 15 * 60_000 };

/** Mismo criterio D4/LOCAL-test-only que DEFAULT_TEST_RECOVERY_TOKEN_POLICY (arriba), pero para
 * P-18 (handle RECOVERY de la cookie, ADR-006 §6.2: 10 minutos), no P-15 (token en BD). */
const DEFAULT_TEST_RECOVERY_HANDLE_POLICY: RecoveryHandlePolicy = { ttlMs: 10 * 60_000 };

/** Mismo criterio D4/LOCAL-test-only que arriba, pero para el handle INVITATION_LANDING
 * (link-handle.ts, GET /i/{token}, SEC-CNS-014 patrón, Carlos 2026-09-28): solo necesita
 * sobrevivir el 303 inmediato a GET /welcome, no la vigencia real de la invitación. */
const DEFAULT_TEST_INVITATION_HANDLE_POLICY: InvitationHandlePolicy = { ttlMs: 10 * 60_000 };

/** Mismo criterio D4/LOCAL-test-only que arriba, pero para el handle MANAGE_ENTRY
 * (link-handle.ts, GET /m/{token}, SEC-CNS-014 patrón, Carlos 2026-09-28). */
const DEFAULT_TEST_MANAGE_HANDLE_POLICY: ManageHandlePolicy = { ttlMs: 10 * 60_000 };

/** HKDF `info` de cada handle (P2-02, mismo criterio que recovery-handle.ts): distintos entre sí
 * y de los de recovery-handle.ts/consent-session.ts, para que comprometer una clave nunca
 * comprometa las otras. */
const INVITATION_HANDLE_HKDF_INFO = "CNS-INVITATION-HANDLE-v1";
const MANAGE_ENTRY_HANDLE_HKDF_INFO = "CNS-MANAGE-ENTRY-HANDLE-v1";

/** CA-116: ports de GET /m/{token} + R1-R3/R8/RV0(BEARER)/RC1(BEARER), y (PR 2) GET /r/{token}
 * + POST /recovery/revoke (R1r/R2r/R3r/R10/R11). `ledger` compartido con
 * `createDefaultConsentFlowPorts` (mismo proceso in-memory) si el caller lo pasa; si no, uno
 * nuevo. El `TenantHandlePort` nace vacío: dev.ts y los tests siembran handles con `.issue()`
 * (import { createInMemoryTenantHandleAdapter } directamente para poder sembrar).
 * `consentDecisionRepo` (SEC-CNS-014, FINDING P1-01): por defecto uno in-memory vacío, propio
 * de este proceso (suficiente para los tests que nunca ejercitan revokeWithRecoveryLink); los
 * callers que SÍ lo hacen (createConsentFlowHttpServer, dev.ts, recovery-http.test.ts) deben
 * pasar el mismo `ports.decision.repo` del flujo de consentimiento, para que
 * `findActiveGrantByChain` vea la GRANTED real de la cadena. */
export function createDefaultRevocationFlowPorts(
  recoveryTokenPolicy: RecoveryTokenPolicy = DEFAULT_TEST_RECOVERY_TOKEN_POLICY,
  ledger: LedgerPort = createInMemoryLedgerAdapter(),
  consentDecisionRepo: ConsentDecisionRepositoryPort = createInMemoryConsentDecisionRepository(),
): RevocationFlowPorts {
  const tenantHandle = createInMemoryTenantHandleAdapter();
  const revocationRepo = createInMemoryRevocationRepository();
  const outbox = createInMemoryOutboxAdapter();
  const recoveryTokenRepo = createInMemoryRecoveryTokenRepository();
  const rightsCaseRepo = createInMemoryRightsCaseRepository();
  const tenancy = createInMemoryTenancy({ revocationRepo, ledger, outbox, recoveryTokenRepo, consentDecisionRepo, rightsCaseRepo, tenantHandle });
  return {
    tenantHandle,
    revocation: {
      revocationRepo,
      ledger,
      outbox,
      recoveryTokenRepo,
      recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
      recoveryTokenPolicy,
      consentDecisionRepo,
      // CA-124: UoW + resolver in-memory sobre los MISMOS adaptadores del proceso.
      ...tenancy,
    },
    rightsCase: { rightsCaseRepo, ledger, uow: tenancy.uow },
  };
}

export type ConsentStoreMode = "memory" | "postgres";

/**
 * CONSENT_STORE=memory|postgres (CA-124 PR-E). Fail-closed: valor inválido -> lanza siempre; ausente ->
 * lanza fuera de LOCAL; en LOCAL el default es `memory` (comportamiento histórico de dev y tests).
 */
export function resolveConsentStoreMode(raw: string | undefined, environment: string | undefined): ConsentStoreMode {
  if (raw === undefined || raw === "") {
    if (environment === "LOCAL") return "memory";
    throw new Error("CONSENT_STORE es obligatorio fuera de LOCAL (memory|postgres). Abortando (fail-closed).");
  }
  if (raw === "memory") {
    // SEC-CNS-017 F7: el almacen en memoria es solo LOCAL (dev/tests); fuera de LOCAL no arranca.
    if (environment !== "LOCAL") throw new Error("CONSENT_STORE=memory solo se admite en LOCAL. Abortando (fail-closed).");
    return raw;
  }
  if (raw === "postgres") return raw;
  throw new Error(`CONSENT_STORE inválido ("${raw.slice(0, 20)}"): solo memory|postgres. Abortando (fail-closed).`);
}

export interface PostgresFlowConfig {
  readonly otpPolicy: OtpPolicy;
  readonly relationshipConfig: DecisionRelationshipConfig;
  readonly recoveryTokenPolicy: RecoveryTokenPolicy;
  readonly staffIdentity: StaffIdentityPort;
  /** SEC-CNS-017 F2: clave HMAC del chainRef (chain-ref.ts), derivada de CNS_CHAIN_REF_SECRET. */
  readonly chainRefKey: Buffer;
  /** CA-128: clave HMAC del decisionMakerRef (decision-maker-ref.ts), de CNS_DECISION_MAKER_REF_SECRET. */
  readonly decisionMakerRefKey: Buffer;
  readonly invitationIssuancePolicy?: InvitationIssuancePolicy;
}

/** Cableado Postgres de los tres bolsos de puertos. Repos/ledger/outbox/catálogo del bolso son los
 * "prohibidos fuera de tx" del store: el dominio los sustituye por los de `uow.inTenant`; cualquier uso
 * suelto falla cerrado (OutsideTransactionError). Los sinks de canal (OTP, enlaces) siguen en memoria. */
export function createPostgresFlowPorts(
  store: PostgresStore,
  cfg: PostgresFlowConfig,
): {
  ports: ConsentFlowPorts;
  revocationPorts: RevocationFlowPorts;
  staffConsole: StaffConsolePorts & { readonly invitationLinkSink: InMemoryInvitationLinkChannelSink };
} {
  const o = store.outsideTx;
  const invitation: InvitationPorts = {
    invitationRepo: o.invitationRepo,
    eligibility: createInMemoryEligibilityAdapter(),
    ledger: o.ledger,
    uow: store.uow,
    tenantResolver: store.tenantResolver,
  };
  const otp: OtpChallengePorts = {
    otpRepo: o.otpRepo,
    channel: createInMemoryOtpChannelSink(),
    ledger: o.ledger,
    invitation,
    uow: store.uow,
    policy: cfg.otpPolicy,
    secret: randomBytes(32),
  };
  const decision: ConsentDecisionPorts = {
    repo: o.consentDecisionRepo,
    ledger: o.ledger,
    invitation,
    uow: store.uow,
    config: LECTORPRO_BETA_CONFIG,
    relationships: cfg.relationshipConfig,
    chainRefKey: cfg.chainRefKey,
  };
  const revocationPorts: RevocationFlowPorts = {
    tenantHandle: store.tenantHandle,
    revocation: {
      revocationRepo: o.revocationRepo,
      ledger: o.ledger,
      outbox: o.outbox,
      recoveryTokenRepo: o.recoveryTokenRepo,
      recoveryLinkChannel: createInMemoryRecoveryLinkChannelSink(),
      recoveryTokenPolicy: cfg.recoveryTokenPolicy,
      consentDecisionRepo: o.consentDecisionRepo,
      uow: store.uow,
      tenantResolver: store.tenantResolver,
    },
    rightsCase: { rightsCaseRepo: o.rightsCaseRepo, ledger: o.ledger, uow: store.uow },
  };
  const invitationLinkSink = createInMemoryInvitationLinkChannelSink();
  const staffConsole = {
    issuance: {
      invitation,
      enrollmentRepo: o.enrollmentRepo,
      tenantCatalog: o.tenantCatalog,
      invitationLinkChannel: invitationLinkSink,
      ...(cfg.invitationIssuancePolicy ? { policy: cfg.invitationIssuancePolicy } : {}),
    },
    enrollment: { enrollmentRepo: o.enrollmentRepo, tenantCatalog: o.tenantCatalog, ledger: o.ledger, uow: store.uow },
    uow: store.uow,
    staffIdentity: cfg.staffIdentity,
    invitationLinkSink,
  };
  return { ports: { invitation, otp, decision, decisionMakerRefKey: cfg.decisionMakerRefKey }, revocationPorts, staffConsole };
}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

/** Cuerpo application/x-www-form-urlencoded (consola dev), tope 8 KiB. */
function readFormBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= 8192) chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

/** SEC-CNS-014 (APROBADO CON CAMBIOS, FINDING P1-02; Carlos 2026-09-28, opción b):
 * SameSite=Lax, no Strict. Sin esto, la cookie de sesión nunca llega en la navegación GET de
 * nivel superior que sigue a la redirección 303 de GET /r/{token} (o GET /i/, /m/) cuando el
 * enlace se abre desde fuera del origen de la app (p. ej. un cliente de correo): con Strict el
 * navegador la omite en esa primera navegación cross-site. Lax sigue sin enviar la cookie en un
 * POST cross-site (solo en navegación GET de nivel superior), así que GRD-CM-10
 * (csrf_and_origin: token CSRF double-submit + Origin exacto) sigue siendo la única defensa
 * real de los POST, sin debilitarse. */
function serializeSessionCookie(config: RightsCaseHttpConfig, value: string): string {
  return `${config.sessionCookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

/** FINDING P1 (Carlos, prueba en navegador): invalida una cookie de sesión previa que ya no
 * corresponde al handle recién resuelto (o al handle inválido) de GET /welcome/GET /manage —
 * Max-Age=0 fuerza al navegador a borrarla, para que "el último enlace abierto manda" (mismo
 * criterio que /recovery/confirm, PR #23) y una recarga posterior no la reviva. */
function serializeClearSessionCookie(config: RightsCaseHttpConfig): string {
  return `${config.sessionCookieName}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

/** P1: contracts/openapi/consent-it0.openapi.yaml fija application/problem+json en
 * components.responses.CsrfRejected (403), components.responses.Problem (409/422 genérico) y
 * en el 422 de /otp/submit (OtpRejected); el resto (incluida UniformNotFound, 404) es
 * application/json. En los dos entrypoints de este repo (consent-flow-server.ts, server.ts)
 * los únicos usos de 403/409/422 son, precisamente, esos tres. */
function contentTypeForStatus(status: number): string {
  return status === 403 || status === 409 || status === 422 ? "application/problem+json" : "application/json";
}

/** Cabeceras de las páginas HTML servidas por este entrypoint (/welcome, /verify): CLAUDE.md
 * UX-CNS-001. CSP estricta sin scripts inline (todo el JS/CSS de la app va como estático bajo
 * /assets/**, static-assets.ts); `no-store` evita que un proxy/navegador cachee una pantalla
 * ligada a una sesión de un solo uso; `no-referrer` evita filtrar la URL a terceros. */
function writeHtmlSecurityHeaders(res: ServerResponse): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
}

/** GET /recovery/confirm (SEC-CNS-014): además de las cabeceras de writeHtmlSecurityHeaders,
 * frame-ancestors 'none' (nunca en un iframe de terceros) y COOP same-origin (aísla el
 * `window` de esta pestaña de cualquier ventana abierta por un origen ajeno). Ambas páginas
 * (200 y 404) las llevan. */
function writeRecoveryHtmlSecurityHeaders(res: ServerResponse): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
}

/** Piso de tiempo (ms) para la rama UniformNotFound de GET /recovery/confirm (SEC-CNS-014):
 * intento de mitigación de canal lateral de temporización entre las causas (inexistente,
 * consumido, expirado, otro ciclo, sin cookie) — no es una garantía criptográfica de tiempo
 * constante, solo un piso mínimo sobre trabajo que ya es mayormente uniforme (un solo lookup en
 * memoria por causa). */
const RECOVERY_CONFIRM_UNIFORM_FLOOR_MS = 5;

function floorDelay(startedAt: bigint, floorMs: number): Promise<void> {
  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
  const remaining = floorMs - elapsedMs;
  if (remaining <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, remaining));
}

function writeResult(res: ServerResponse, config: RightsCaseHttpConfig, result: HttpResult): void {
  // CA-128: setCaseSessionCookie/setCaseCsrfCookie pueden coexistir entre sí (dos cookies del
  // mismo /__dev/staff-login); nunca con setSessionCookie/setRecoveryHandleCookie (documentado
  // en consent-flow.handler.ts). Node admite un arreglo para varias líneas Set-Cookie.
  const cookies: string[] = [];
  if (result.setSessionCookie) cookies.push(serializeSessionCookie(config, result.setSessionCookie));
  if (result.setRecoveryHandleCookie) cookies.push(result.setRecoveryHandleCookie);
  if (result.setCaseSessionCookie) cookies.push(result.setCaseSessionCookie);
  if (result.setCaseCsrfCookie) cookies.push(result.setCaseCsrfCookie);
  if (result.setStaffSessionCookie) cookies.push(result.setStaffSessionCookie);
  if (result.setStaffCsrfCookie) cookies.push(result.setStaffCsrfCookie);
  if (cookies.length > 0) {
    res.setHeader("Set-Cookie", cookies);
  }
  if (result.setLinkHandleCookie) {
    res.setHeader("Set-Cookie", result.setLinkHandleCookie);
  }
  if (result.extraHeaders) {
    for (const [name, value] of Object.entries(result.extraHeaders)) {
      res.setHeader(name, value);
    }
  }
  if (result.location) {
    res.setHeader("Location", result.location);
  }
  res.writeHead(result.status, { "content-type": contentTypeForStatus(result.status) });
  res.end(JSON.stringify(result.body));
}

export function createConsentFlowHttpServer(options: ConsentFlowHttpServerOptions = {}): Server {
  const config = loadRightsCaseHttpConfig(options.config);
  const sessionSecret = options.sessionSecret ?? randomBytes(32);
  const ports =
    options.ports ??
    (() => {
      if (!options.otpPolicy || !options.relationshipConfig) {
        throw new Error(
          "createConsentFlowHttpServer requiere `ports` o ambos `otpPolicy` (D4, otp-policy.config.ts) y " +
            "`relationshipConfig` (GRD-CD-04, decision-relationship.config.ts).",
        );
      }
      return createDefaultConsentFlowPorts(options.otpPolicy, options.relationshipConfig);
    })();
  const revocationPorts =
    options.revocationPorts ?? createDefaultRevocationFlowPorts(options.recoveryTokenPolicy, ports.decision.ledger, ports.decision.repo);
  const recoveryHandlePolicy = options.recoveryHandlePolicy ?? DEFAULT_TEST_RECOVERY_HANDLE_POLICY;
  const invitationHandlePolicy = options.invitationHandlePolicy ?? DEFAULT_TEST_INVITATION_HANDLE_POLICY;
  const manageHandlePolicy = options.manageHandlePolicy ?? DEFAULT_TEST_MANAGE_HANDLE_POLICY;
  // P2-02 (SEC-CNS-014): claves HKDF propias derivadas de sessionSecret, cada una con un `info`
  // distinto (recovery-handle.ts, link-handle.ts) y distinto también de la firma HMAC de
  // consent-session.ts: comprometer una nunca compromete las otras.
  const recoveryHandleKey = deriveRecoveryHandleKey(sessionSecret);
  const recoveryCsrfKey = deriveRecoveryCsrfKey(sessionSecret);
  const invitationHandleKey = deriveLinkHandleKey(sessionSecret, INVITATION_HANDLE_HKDF_INFO);
  const manageEntryHandleKey = deriveLinkHandleKey(sessionSecret, MANAGE_ENTRY_HANDLE_HKDF_INFO);
  // CA-128: clave propia de la sesión CASE (case-session.ts), aislada de las de arriba.
  const caseSessionKey = deriveCaseSessionKey(sessionSecret);
  // LOCAL + CI / SYNTHETIC DATA ONLY — APR-IDP PENDING: roster vacío por defecto (fail-closed,
  // GRD-RC-15 ERR-RC-10 siempre sin override explícito).
  const staffIdentity: StaffIdentityPort = options.staffIdentity ?? createInMemoryStaffIdentityAdapter([]);
  // CA-125: clave propia de la sesión STAFF (staff-session.ts), aislada de las de arriba.
  const staffSessionKey = deriveStaffSessionKey(sessionSecret);
  const staffConsolePorts: StaffConsolePorts = options.staffConsole ?? createDefaultStaffConsolePorts(ports.invitation, staffIdentity);
  const caseConfirmationPorts: CaseConfirmationPorts = {
    revocation: revocationPorts.revocation,
    staffIdentity,
  };

  const handleRequest = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = req.url ?? "";
    const path = url.split("?", 1)[0] ?? "";

    if (req.method === "GET" && path.startsWith("/i/") && path.length > "/i/".length) {
      // API-CNS-101 (P-12, SEC-CNS-014): único GET de canje de este entrypoint IT0 (INV-CM-08
      // reforzado, Carlos 2026-09-28 opción a). SIEMPRE el mismo 303, sin leer la BD: un
      // segmento vacío tras decodificar es el único caso que ni siquiera hashea (URL con /i/
      // exacto, ruta distinta por construcción, ya cubierta por path.length arriba).
      let token: string;
      const rawSegment = path.slice("/i/".length);
      try {
        token = decodeURIComponent(rawSegment);
      } catch {
        token = rawSegment;
      }
      const result = handleRedeemInvitationLink(token, invitationHandlePolicy, invitationHandleKey, config.invitationHandleCookieName);
      writeResult(res, config, result);
      return;
    }

    if (req.method === "GET" && path === "/welcome") {
      // UX-CNS-001 (SEC-CNS-014, INV-CM-08, FINDING P1): GET /welcome resuelve en solo lectura.
      // El handle INVITATION_LANDING vigente (fijado por el GET /i/{token} MÁS RECIENTE) SIEMPRE
      // manda sobre una sesión previa (resolveWelcomeLandingSession, "el último enlace abierto
      // manda"); GRD-IV-07 se evalúa AQUÍ, no en el GET de canje. Sin sesión ni handle elegible:
      // 404 byte-idéntico (INV-CM-05: sin distinguir inexistente/expirado/de otro tenant), nunca
      // un 404 crudo del framework, y cualquier sesión previa queda invalidada.
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const existingSession = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      const view = await resolveWelcomeLandingSession(ports, sessionSecret, existingSession, invitationHandleKey, cookies, config.invitationHandleCookieName);
      writeHtmlSecurityHeaders(res);
      if (!view.session) {
        if (view.clearSessionCookie) res.setHeader("Set-Cookie", serializeClearSessionCookie(config));
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderWelcomeUniformErrorPage());
        return;
      }
      // Cookie CSRF del double-submit (csrf.ts): legible por welcome.js, distinta de la cookie
      // de sesión (siempre HttpOnly). Si esta llamada recién resolvió una sesión NUEVA (primera
      // visita, o un enlace distinto al de la sesión previa), también fija la cookie de sesión
      // real (view.sessionCookieToSet), que sobrescribe cualquier sesión previa por sí sola.
      const cookiesToSet = [serializeCsrfCookie(config.csrfCookieName, generateCsrfToken())];
      if (view.sessionCookieToSet) cookiesToSet.push(serializeSessionCookie(config, view.sessionCookieToSet));
      res.setHeader("Set-Cookie", cookiesToSet);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderWelcomePage());
      return;
    }

    if (req.method === "GET" && path === "/verify") {
      // UX-CNS-002: GET /verify exige la sesión con el OTP ya solicitado (V1, session.
      // verificationRef); sin ella, se sirve el estado de error uniforme de la propia pantalla
      // (INV-CM-05), nunca un 404 crudo (mismo patrón que /welcome).
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.verificationRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderVerifyUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderVerifyPage());
      return;
    }

    if (req.method === "GET" && path === "/decision") {
      // UX-CNS-003: GET /decision exige la sesión verificada (post-V3, session.decisionMakerRef);
      // sin ella, se sirve el estado de error uniforme de la propia pantalla (INV-CM-05), mismo
      // patrón que /welcome y /verify. verify.js redirige acá cuando /otp/submit responde 200.
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.verificationRef || !session.decisionMakerRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderDecisionUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderDecisionPage(ports.decision.relationships.allowedRelationshipRefs, getServedConsentVersion()));
      return;
    }

    // -------------------------------------------------------------------
    // CA-116 (revocación IT0, UX-CNS-004): GET /m/{token} + páginas MANAGE/REVOCATION.
    // -------------------------------------------------------------------
    if (req.method === "GET" && path.startsWith("/m/") && path.length > "/m/".length) {
      // API-CNS-102 (P-14, SEC-CNS-014): único GET de canje del handle MANAGE_ENTRY (INV-CM-08
      // reforzado, Carlos 2026-09-28 opción a). SIEMPRE el mismo 303, sin leer la BD.
      let token: string;
      const rawSegment = path.slice("/m/".length);
      try {
        token = decodeURIComponent(rawSegment);
      } catch {
        token = rawSegment;
      }
      const result = handleRedeemManagementLink(token, manageHandlePolicy, manageEntryHandleKey, config.manageEntryHandleCookieName);
      writeResult(res, config, result);
      return;
    }

    if (req.method === "GET" && path.startsWith("/r/") && path.length > "/r/".length) {
      // API-CNS-103 (P-18, SEC-CNS-014): único GET de canje del token de recuperación
      // (INV-CM-08 reforzado: no lee la BD, no valida, no transiciona ni consume). Un token no
      // decodificable se hashea igual, tal cual llega en el path (P2-04): SIEMPRE el mismo 303,
      // nunca un 404 crudo ni una rama distinta.
      const rawSegment = path.slice("/r/".length);
      let token: string;
      try {
        token = decodeURIComponent(rawSegment);
      } catch {
        token = rawSegment;
      }
      const result = handleRedeemRecoveryLink(token, recoveryHandlePolicy, recoveryHandleKey, config.recoveryHandleCookieName);
      writeResult(res, config, result);
      return;
    }

    if (req.method === "GET" && path === "/manage") {
      // UX-CNS-004 §1 (33:2 entrada / 33:21 estado / 59:3 error, SEC-CNS-014, FINDING P1): una
      // sola ruta, que resuelve en solo lectura. El handle MANAGE_ENTRY vigente (fijado por el
      // GET /m/{token} MÁS RECIENTE) SIEMPRE manda sobre una sesión previa
      // (resolveManageLandingSession, "el último enlace abierto manda"); GRD-CM-01 se evalúa
      // AQUÍ, no en el GET de canje. Sin sesión ni handle elegible: 404 byte-idéntico (frame
      // 59:3), nunca un 404 crudo, y cualquier sesión previa queda invalidada.
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const existingSession = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      const view = await resolveManageLandingSession(
        revocationPorts,
        sessionSecret,
        existingSession,
        manageEntryHandleKey,
        cookies,
        config.manageEntryHandleCookieName,
      );
      writeHtmlSecurityHeaders(res);
      if (!view.session) {
        if (view.clearSessionCookie) res.setHeader("Set-Cookie", serializeClearSessionCookie(config));
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderManageUniformErrorPage());
        return;
      }
      const cookiesToSet = [serializeCsrfCookie(config.csrfCookieName, generateCsrfToken())];
      if (view.sessionCookieToSet) cookiesToSet.push(serializeSessionCookie(config, view.sessionCookieToSet));
      res.setHeader("Set-Cookie", cookiesToSet);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      // C6 (INV-5): con la decisión de la sesión ya REVOKED, estado neutro sin CTA de retirar.
      // SEC-CNS-016: la lectura de la decisión corre BAJO el tenant de la sesión (inTenant).
      const revokedDecisionRef = view.session.revokedDecisionRef;
      const decisionRevoked =
        revokedDecisionRef !== undefined &&
        (await revocationPorts.revocation.uow.inTenant(view.session.tenantId, (tx) =>
          tx.consentDecisionRepo.findByConsentId(view.session!.tenantId, revokedDecisionRef),
        ))?.state === "REVOKED";
      res.end(
        !view.session.manageDecisionMakerRef
          ? renderManageEntryPage()
          : decisionRevoked
            ? renderManageRevokedPage()
            : renderManageStatusPage(),
      );
      return;
    }

    if (req.method === "GET" && path === "/manage/verify") {
      // Exige el OTP scope MANAGE ya solicitado (V1); mismo patrón de error uniforme que /verify.
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.manageVerificationRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderVerifyUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderVerifyPage("MANAGE"));
      return;
    }

    if (req.method === "GET" && path === "/manage/revocation/verify") {
      // Exige el OTP scope REVOCATION ya solicitado (V1, posterior a R1).
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.revocationVerificationRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderVerifyUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderVerifyPage("REVOCATION"));
      return;
    }

    if (req.method === "GET" && path === "/manage/revocation/confirm") {
      // Exige V3 scope REVOCATION ya correcto (R2 lo ejecuta revocation.js al cargar).
      const cookies = parseCookies(headerValue(req.headers.cookie));
      const session = decodeSession(sessionSecret, cookies[config.sessionCookieName]);
      writeHtmlSecurityHeaders(res);
      if (!session || !session.revocationOtpVerified || !session.revocationRef || !session.manageDecisionMakerRef) {
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderRevocationUniformErrorPage());
        return;
      }
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateCsrfToken()));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderRevocationConfirmPage());
      return;
    }

    if (req.method === "GET" && path === "/recovery/confirm") {
      // SEC-CNS-014 (UX-CNS-004 33:87/33:106): GRD-RV-06 se evalúa AQUÍ, en solo lectura
      // (resolveRecoveryConfirmView -> evaluateRecoveryTokenEligibilityByHash), a partir del
      // hash fijado por GET /r/{token} en la cookie __Host-cns-recovery (nunca de la sesión de
      // consent-session.ts, que ya no lleva recoveryTokenHash). Sin handle válido, inexistente,
      // consumido, expirado o de otro ciclo: 404 byte-idéntico (UniformNotFound, mismo criterio
      // INV-CM-05), con un piso de tiempo común para no distinguir la causa por temporización.
      const startedAt = process.hrtime.bigint();
      const view = await resolveRecoveryConfirmView(revocationPorts, recoveryHandleKey, headerValue(req.headers.cookie), config.recoveryHandleCookieName);
      writeRecoveryHtmlSecurityHeaders(res);
      if (!view.eligible || !view.tokenHash) {
        await floorDelay(startedAt, RECOVERY_CONFIRM_UNIFORM_FLOOR_MS);
        res.writeHead(404, { "content-type": "text/html; charset=utf-8" });
        res.end(renderRecoveryUniformErrorPage());
        return;
      }
      // P2 (fijación de cookie): el CSRF de esta página queda ligado al hash vigente ahora
      // mismo; POST /recovery/revoke lo recalcula contra la cookie __Host-cns-recovery ACTUAL
      // (recovery-handle.ts verifyRecoveryCsrfToken).
      res.setHeader("Set-Cookie", serializeCsrfCookie(config.csrfCookieName, generateRecoveryCsrfToken(recoveryCsrfKey, view.tokenHash)));
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(renderRecoveryConfirmPage());
      return;
    }

    if (req.method === "GET" && path.startsWith("/assets/")) {
      // Lista blanca cerrada (static-assets.ts): el lookup es por igualdad exacta, nunca por
      // join de filesystem, así que un intento de traversal (`../`, codificado o no) nunca
      // resuelve a una entrada y cae directo al 404 de abajo.
      let decodedPath: string | undefined;
      try {
        decodedPath = decodeURIComponent(path);
      } catch {
        decodedPath = undefined;
      }
      const asset = decodedPath ? resolveStaticAsset(decodedPath) : null;
      if (!asset) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
      }
      res.writeHead(200, { "content-type": asset.contentType, "cache-control": "no-store" });
      res.end(asset.content);
      return;
    }

    if (req.method === "GET" && path === "/__dev/otp-sink") {
      if (options.environment !== "LOCAL") {
        // Fail-closed (GRD-CM-13): fuera de LOCAL esta ruta no existe, ni siquiera como 403.
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
      }
      const sink = ports.otp.channel as InMemoryOtpChannelSink;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ sent: sink.sent }));
      return;
    }

    if (req.method === "GET" && path === "/__dev/outbox-sink") {
      // CA-127: mismo guard fail-closed que /__dev/otp-sink (GRD-CM-13). Solo refs opacas y enums;
      // no está en OpenAPI.
      if (options.environment !== "LOCAL") {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
      }
      if (options.storeMode === "postgres") {
        // El outbox vive en la base: el bolso fuera de tx es un Proxy que rechaza, no un InMemoryOutbox.
        if (!options.devOutboxSink) {
          res.writeHead(404, { "content-type": "application/json" });
          res.end(JSON.stringify({ status: 404 }));
          return;
        }
        const envelopes = await options.devOutboxSink();
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ enqueued: envelopes }));
        return;
      }
      const outbox = revocationPorts.revocation.outbox as InMemoryOutbox;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ enqueued: outbox.enqueued.map((r) => r.envelope) }));
      return;
    }

    if (req.method === "GET" && path === "/__dev/recovery-sink") {
      // Mismo patrón fail-closed que /__dev/otp-sink (GRD-CM-13): CA-116 PR 2, único lugar
      // donde el enlace /r/<token> en claro es legible en LOCAL (Cero PII: nunca en la
      // respuesta HTTP de /manage/recovery-link ni en logs).
      if (options.environment !== "LOCAL") {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
      }
      const sink = revocationPorts.revocation.recoveryLinkChannel as InMemoryRecoveryLinkChannelSink;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ sent: sink.sent }));
      return;
    }

    if (req.method === "GET" && path === "/__dev/invitation-sink") {
      // CA-125: mismo patrón fail-closed que /__dev/recovery-sink (GRD-CM-13). Único lugar donde
      // el enlace /i/<token> en claro es legible en LOCAL (nunca en la respuesta de /send, ni en
      // ledger, eventos o logs). No está en OpenAPI.
      if (options.environment !== "LOCAL") {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
      }
      const sink = staffConsolePorts.issuance.invitationLinkChannel as InMemoryInvitationLinkChannelSink;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ sent: sink.sent }));
      return;
    }

    if (isDevStaffConsolePath(path)) {
      // CA-125: consola dev (HTML). El gating GRD-CM-13 (LOCAL + fixture) vive en handleDevStaffConsole:
      // fuera de LOCAL responde el mismo 404 JSON que los demás /__dev/*. Nunca se registra el cuerpo.
      const formBody = req.method === "POST" ? await readFormBody(req) : "";
      const consoleResponse = await handleDevStaffConsole(
        { method: req.method ?? "GET", path, originHeader: headerValue(req.headers.origin), cookieHeader: headerValue(req.headers.cookie), formBody },
        { environment: options.environment, fixture: options.devStaffConsole, staffIdentity, staffConsole: staffConsolePorts, config, staffSessionKey },
        () => (staffConsolePorts.issuance.invitationLinkChannel as InMemoryInvitationLinkChannelSink).sent ?? [],
      );
      if (consoleResponse.status === 404) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
      }
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Referrer-Policy", "no-referrer");
      res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'");
      if (consoleResponse.setCookies && consoleResponse.setCookies.length > 0) res.setHeader("Set-Cookie", [...consoleResponse.setCookies]);
      if (consoleResponse.location) res.setHeader("Location", consoleResponse.location);
      res.writeHead(consoleResponse.status, { "content-type": "text/html; charset=utf-8" });
      res.end(consoleResponse.html);
      return;
    }

    if (req.method !== "POST") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ status: 404 }));
      return;
    }

    const body = await readBody(req);
    const request: RawConsentRequest = {
      originHeader: headerValue(req.headers.origin),
      csrfHeaderToken: headerValue(req.headers[config.csrfHeaderName]),
      cookieHeader: headerValue(req.headers.cookie),
      body,
      idempotencyKeyHeader: headerValue(req.headers["idempotency-key"]),
    };

    if (path === "/__dev/staff-login") {
      // CA-125: un principal TENANT_ADMIN recibe la sesión STAFF (staff-session.ts); cualquier
      // otro rol sigue el login CASE de CA-128. El rol lo decide el roster, no el body.
      const requestedPrincipal = (request.body as { principalRef?: unknown } | undefined)?.principalRef;
      const requestedRole = typeof requestedPrincipal === "string" ? (await staffIdentity.findByPrincipalRef(requestedPrincipal))?.role : undefined;
      if (requestedRole === "TENANT_ADMIN") {
        writeResult(res, config, await handleDevStaffConsoleLogin(request, options.environment ?? "DEV", staffIdentity, config, staffSessionKey));
        return;
      }
      // CA-128 (Carlos 2026-09-28, opción (ii)): mismo guard GRD-CM-13 que /__dev/otp-sink;
      // handleDevStaffLogin ya rechaza fuera de LOCAL, aquí solo se enruta.
      const result = await handleDevStaffLogin(
        request,
        options.environment ?? "DEV",
        { staffIdentity, uow: revocationPorts.revocation.uow },
        config,
        caseSessionKey,
      );
      writeResult(res, config, result);
      return;
    }

    if (path.startsWith("/platform/rights-cases/") && path.includes("/verification-proposals")) {
      // API-CNS-136/137: .../{caseRef}/verification-proposals y .../{caseRef}/verification-proposals/{proposalRef}/approval.
      const rest = path.slice("/platform/rights-cases/".length);
      const parts = rest.split("/");
      if (parts.length === 2 && parts[0] && parts[1] === "verification-proposals") {
        writeResult(res, config, await handleProposeCaseVerification(request, parts[0], caseConfirmationPorts, config, caseSessionKey));
        return;
      }
      if (parts.length === 4 && parts[0] && parts[1] === "verification-proposals" && parts[2] && parts[3] === "approval") {
        writeResult(res, config, await handleApproveCaseVerification(request, parts[0], parts[2], caseConfirmationPorts, config, caseSessionKey, options.environment ?? "DEV"));
        return;
      }
      if (parts.length === 4 && parts[0] && parts[1] === "verification-proposals" && parts[2] && parts[3] === "withdrawal") {
        // API-CNS-140: retiro de la propuesta PENDING por su proponente.
        writeResult(res, config, await handleWithdrawCaseVerificationProposal(request, parts[0], parts[2], caseConfirmationPorts, config, caseSessionKey));
        return;
      }
    }

    if (path.startsWith("/platform/rights-cases/") && path.endsWith("/confirmation/cosign")) {
      // API-CNS-139: mismo criterio de un solo segmento intermedio que API-CNS-138.
      const caseRef = path.slice("/platform/rights-cases/".length, path.length - "/confirmation/cosign".length);
      if (caseRef.length > 0 && !caseRef.includes("/")) {
        const result = await handleCosignCaseConfirmation(request, caseRef, caseConfirmationPorts, config, caseSessionKey);
        writeResult(res, config, result);
        return;
      }
    }

    if (path.startsWith("/platform/rights-cases/") && path.endsWith("/confirmation")) {
      // API-CNS-138: caseRef es el único segmento intermedio; un path con "/" adicional
      // (intento de traversal o de apuntar a otra sub-ruta) nunca resuelve, cae al 404 genérico.
      const caseRef = path.slice("/platform/rights-cases/".length, path.length - "/confirmation".length);
      if (caseRef.length > 0 && !caseRef.includes("/")) {
        const result = await handleRecordCaseConfirmation(request, caseRef, caseConfirmationPorts, config, caseSessionKey);
        writeResult(res, config, result);
        return;
      }
    }

    // CA-125: consola STAFF (API-CNS-105/110/111/112). invitationRef es el único segmento
    // intermedio; un path con "/" adicional nunca resuelve (cae al 404 genérico).
    if (path === "/staff/enrollments") {
      writeResult(res, config, await handleOpenEnrollment(request, staffConsolePorts, config, staffSessionKey));
      return;
    }
    if (path === "/staff/invitations") {
      writeResult(res, config, await handleCreateInvitation(request, staffConsolePorts, config, staffSessionKey));
      return;
    }
    if (path.startsWith("/staff/invitations/")) {
      const rest = path.slice("/staff/invitations/".length);
      const slash = rest.indexOf("/");
      const invitationRef = slash === -1 ? "" : rest.slice(0, slash);
      const action = slash === -1 ? "" : rest.slice(slash + 1);
      if (invitationRef.length > 0 && action === "ready") {
        writeResult(res, config, await handleMarkInvitationReady(request, invitationRef, staffConsolePorts, config, staffSessionKey));
        return;
      }
      if (invitationRef.length > 0 && action === "send") {
        writeResult(res, config, await handleSendInvitation(request, invitationRef, staffConsolePorts, config, staffSessionKey));
        return;
      }
    }

    let result: HttpResult;
    switch (path) {
      case "/invitation/open":
        result = await handleOpenInvitation(request, ports, config, sessionSecret);
        break;
      case "/otp/request":
        result = await handleRequestOtp(request, ports, config, sessionSecret);
        break;
      case "/otp/resend":
        result = await handleResendOtp(request, ports, config, sessionSecret);
        break;
      case "/otp/submit":
        result = await handleSubmitOtp(request, ports, config, sessionSecret);
        break;
      case "/decision/steps":
        result = await handleRecordDecisionStep(request, ports, config, sessionSecret);
        break;
      case "/decision/submit":
        result = await handleSubmitDecision(request, ports, config, sessionSecret);
        break;
      case "/manage/revocation":
        result = await handleRequestRevocation(request, revocationPorts, config, sessionSecret);
        break;
      case "/manage/revocation/verify":
        result = await handleVerifyRevocation(request, revocationPorts, config, sessionSecret);
        break;
      case "/manage/revocation/confirm":
        result = await handleConfirmRevocation(request, revocationPorts, config, sessionSecret);
        break;
      case "/manage/revocation/withdraw":
        result = await handleWithdrawRevocation(request, revocationPorts, config, sessionSecret);
        break;
      case "/manage/recovery-link":
        result = await handleIssueRecoveryLink(request, revocationPorts, config, sessionSecret);
        break;
      case "/recovery/revoke":
        result = await handleRecoveryRevoke(request, revocationPorts, config, recoveryHandleKey, recoveryCsrfKey);
        break;
      case "/rights-case/open":
        result = await handleOpenRightsCase(request, revocationPorts, config, sessionSecret);
        break;
      default:
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: 404 }));
        return;
    }
    writeResult(res, config, result);
  };

  // SEC-CNS-017 F1: catch global. Un rechazo no capturado del callback async mata el proceso en Node
  // 24 e imprime el error de pg completo (detail/valores de fila = posible PII). Respuesta 500
  // uniforme sin message/detail; se registra solo `name` y `code` (nunca message/stack/detail).
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    handleRequest(req, res).catch((error: unknown) => {
      const e = error as { name?: unknown; code?: unknown } | null;
      const name = typeof e?.name === "string" ? e.name.slice(0, 60) : "UnknownError";
      const code = typeof e?.code === "string" ? e.code.slice(0, 20) : undefined;
      console.error(`request_failed name=${name}${code ? ` code=${code}` : ""}`);
      try {
        if (res.headersSent) {
          res.destroy();
          return;
        }
        const wantsHtml = (headerValue(req.headers.accept) ?? "").includes("text/html");
        if (wantsHtml) {
          writeHtmlSecurityHeaders(res);
          res.writeHead(500, { "content-type": "text/html; charset=utf-8" });
          res.end("<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\"><title>Error</title></head><body><p>Error interno.</p></body></html>");
        } else {
          res.writeHead(500, { "content-type": "application/json", "cache-control": "no-store" });
          res.end(JSON.stringify({ code: "INTERNAL_ERROR", status: 500, correlationId: randomUUID() }));
        }
      } catch {
        res.destroy();
      }
    });
  });
}
