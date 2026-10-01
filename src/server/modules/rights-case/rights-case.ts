// Gobierna: specs/state-machines/rights-case.spec.yaml (RC1 fuente BEARER, RC2u, RC3, RC3a,
// RC4/RC5/RC6), specs/state-machines/revocation.spec.yaml (RC3 lado Revocation, R12).
// Alcance IT0 de este archivo (subconjunto mínimo, ver traceability/test-matrix.csv
// TEST-CNS-458..462, TEST-CNS-464..465, TEST-CNS-468..470): resolución del caso desde el
// handle del portador (GRD-CM-01, GRD-RC-14), RC2u (confirmCaseReturnViaHandle, CA-116
// CA-116-rc2u-http) y el cierre del caso (RC4/RC5/RC6), sin las demás ramas de la spec
// completa (SLA, case_contact, escalamiento por sistema, etc.), que quedan fuera de este
// slice y se implementan en historias posteriores. GRD-CM-10 (CSRF/Origin) se aplica en el
// entrypoint HTTP (src/server/entrypoints/http/**), no aquí: esta capa nunca ve la request
// cruda (ADR-001 §11).

import { randomUUID } from "node:crypto";

import { DomainError } from "../common/errors.ts";
import { resolveHandleOrReject } from "../common/guards.ts";
import { UNVERIFIED_BEARER_ACTOR } from "../common/types.ts";
import type { TenantHandlePort } from "../../ports/tenant-handle.port.ts";
import type { RightsCaseRecord, RightsCaseRepositoryPort } from "../../ports/rights-case-repository.port.ts";
import type { RevocationRecord, RevocationRepositoryPort } from "../../ports/revocation-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";
import type { UnitOfWorkPort } from "../../ports/unit-of-work.port.ts";
import { lastLedgerSequence } from "../common/ledger-append.ts";

export interface RightsCasePorts {
  readonly tenantHandle: TenantHandlePort;
  readonly rightsCaseRepo: RightsCaseRepositoryPort;
  readonly revocationRepo: RevocationRepositoryPort;
  readonly ledger: LedgerPort;
  /** CA-124 (diseño §5, SEC-CNS-015 P2-E): RC2u/RC3/RC4-6 y la apertura del caso corren en UNA unidad de
   * trabajo del tenant (caso + Revocation + ledger). Su tenancy comparte `rightsCaseRepo` y `revocationRepo`. */
  readonly uow: UnitOfWorkPort;
}

type RightsCaseTxBag = Pick<RightsCasePorts, "rightsCaseRepo" | "ledger" | "uow"> & Partial<Pick<RightsCasePorts, "revocationRepo" | "tenantHandle">>;

/** Ejecuta `fn` en una unidad de trabajo del tenant; dentro, repos y ledger son los de la tx
 * (SEC-CNS-015 P2-E). No se anida `inTenant`; `fn` puede reejecutarse si la unidad se reintenta. */
function inTx<P extends RightsCaseTxBag, T>(ports: P, tenantId: string, fn: (txPorts: P) => Promise<T>): Promise<T> {
  return ports.uow.inTenant(tenantId, (tx) =>
    fn({ ...ports, rightsCaseRepo: tx.rightsCaseRepo, ledger: tx.ledger, ...(ports.revocationRepo ? { revocationRepo: tx.revocationRepo } : {}) }),
  );
}

/** Relee el caso CON lock de fila (SEC-CNS-015 P2-E); la decision se toma sobre el estado bloqueado. */
async function lockCase(ports: Pick<RightsCasePorts, "rightsCaseRepo">, tenantId: string, caseRef: string): Promise<RightsCaseRecord> {
  const found = await ports.rightsCaseRepo.findByRefForUpdate(tenantId, caseRef);
  if (!found) {
    throw new DomainError("ERR-CM-01");
  }
  return found;
}

/**
 * GRD-RC-14 (case_bound_to_handle_chain) + GRD-CM-01: el caso se resuelve SIEMPRE en
 * servidor desde el (tenant_id, chainRef) del handle de la request; un caseRef enviado por
 * el cliente se ignora (no se usa ni para desambiguar). Handle inválido/rotado -> ERR-CM-01
 * (404 uniforme, sin evento; TEST-CNS-458). Un caseRef de otro tenant nunca se resuelve
 * porque este método nunca lo consulta (TEST-CNS-459).
 */
export async function resolveCaseForHandle(
  ports: Pick<RightsCasePorts, "tenantHandle" | "uow">,
  handle: string,
  _clientSuppliedCaseRef?: string,
): Promise<RightsCaseRecord> {
  // Resolver (sin tenant) -> inTenant (SEC-CNS-016): el caso se lee SIEMPRE bajo el tenant del handle.
  const resolved = await resolveHandleOrReject(ports.tenantHandle, handle);
  const found = await ports.uow.inTenant(resolved.tenantId, (tx) =>
    tx.rightsCaseRepo.findOpenByChain(resolved.tenantId, resolved.chainRef, resolved.revokedDecisionRef),
  );
  if (!found) {
    // GRD-RC-14 onFail: respuesta uniforme sin efecto (ERR-RC-09), tratada aquí como
    // ausencia de caso ligado al handle. No se consulta jamás _clientSuppliedCaseRef.
    throw new DomainError("ERR-RC-09");
  }
  return found;
}

export interface RevocationIntentResult {
  readonly rightsCase: RightsCaseRecord;
  readonly revocation: RevocationRecord;
}

/** Caso abierto de la cadena del handle, dentro de la tx (GRD-RC-14); el handle ya se resolvio en servidor. */
async function openCaseForResolvedHandle(
  ports: Pick<RightsCasePorts, "rightsCaseRepo">,
  resolved: { readonly tenantId: string; readonly chainRef: string; readonly revokedDecisionRef: string },
): Promise<RightsCaseRecord> {
  const found = await ports.rightsCaseRepo.findOpenByChain(resolved.tenantId, resolved.chainRef, resolved.revokedDecisionRef);
  if (!found) {
    throw new DomainError("ERR-RC-09"); // GRD-RC-14 onFail: uniforme, sin efecto
  }
  return found;
}

/**
 * RC3 (rights-case + revocation) / R12: intención expresa del DecisionMaker en la página del
 * caso, resuelto siempre desde el handle (GRD-RC-14; TEST-CNS-459). El actor registrado en el
 * ledger es SIEMPRE {actorType: HUMAN, actorRole: UNVERIFIED_BEARER} (P-v7-3, R14-A): esta
 * función no acepta ni deriva el actor de ningún parámetro del llamador, así que no puede
 * registrar SYSTEM_GUARD ni ningún otro actorRole (TEST-CNS-460).
 * CA-124 PR-D: una tx; el caso se bloquea (dos RC3 concurrentes: la segunda adjunta por R12) y el
 * evento sobre una Revocation existente declara la base capturada antes de su lock.
 */
export async function expressRevocationIntentInCase(
  ports: RightsCasePorts,
  handle: string,
  _clientSuppliedCaseRef?: string,
): Promise<RevocationIntentResult> {
  const resolved = await resolveHandleOrReject(ports.tenantHandle, handle);
  return inTx(ports, resolved.tenantId, async (p) => {
    const open = await openCaseForResolvedHandle(p, resolved);
    const rightsCase = await lockCase(p, resolved.tenantId, open.caseRef);

    if (!rightsCase.revocationRef) {
      // RC3: no hay Revocation abierta -> crea REQUESTED en el mismo lote.
      const revocationRef = randomUUID(); // Ref UUIDv4 (common.schema.json); antes `rv-${caseRef}` (FINDING P1).
      const revocation: RevocationRecord = {
        revocationRef,
        tenantId: rightsCase.tenantId,
        chainRef: rightsCase.chainRef,
        caseRef: rightsCase.caseRef,
        revokedDecisionRef: rightsCase.revokedDecisionRef, // fuente de CONSENT_REVOKED.revokedDecisionRef en R4
        status: "REQUESTED",
      };
      await p.revocationRepo.save(revocation);
      const updatedCase: RightsCaseRecord = {
        ...rightsCase,
        revocationRef,
        status: "IN_VERIFICATION",
      };
      await p.rightsCaseRepo.save(updatedCase);
      await p.ledger.append({
        expectedSequence: 0, // Revocation nueva
        eventType: "REVOCATION_REQUESTED",
        tenantId: rightsCase.tenantId,
        aggregateType: "Revocation",
        aggregateId: revocationRef,
        actorType: UNVERIFIED_BEARER_ACTOR.actorType,
        actorRole: UNVERIFIED_BEARER_ACTOR.actorRole,
        payload: {
          revocationRef,
          revokedDecisionRef: rightsCase.revokedDecisionRef,
          scope: "ALL",
          authPath: "RECOVERY",
          recoveryMethod: "HUMAN_ASSISTED",
          originPurposeRef: "ALL",
          // GRD-RV-25: SCHOOL_REPORT si y solo si el caso nace con origin SCHOOL_REPORTED.
          initiatedVia: rightsCase.origin === "SCHOOL_REPORTED" ? "SCHOOL_REPORT" : "DECISION_MAKER",
          caseRef: rightsCase.caseRef,
        },
        // ":rc3" evita colisionar con el idempotencyKey plano `revocationRef` de R4 (CONSENT_REVOKED,
        // mismo aggregateId): el ledger dedupea por (tenant, aggregateType, aggregateId, key), no por
        // eventType, y con la key plana R4 devolvía este REQUESTED en vez de emitir CONSENT_REVOKED
        // (CA-127, FINDING P1).
        idempotencyKey: `${revocationRef}:rc3`,
      });
      return { rightsCase: updatedCase, revocation };
    }

    // R12: ya hay Revocation abierta de la decisión vigente -> se adjunta, no crea otra.
    const base = await lastLedgerSequence(p.ledger, rightsCase.tenantId, rightsCase.revocationRef);
    const existing = await p.revocationRepo.findByRefForUpdate(rightsCase.tenantId, rightsCase.revocationRef);
    if (!existing) {
      throw new DomainError("ERR-CM-01");
    }
    await p.ledger.append({
      expectedSequence: base,
      eventType: "REVOCATION_REQUESTED",
      tenantId: rightsCase.tenantId,
      aggregateType: "Revocation",
      aggregateId: existing.revocationRef,
      actorType: UNVERIFIED_BEARER_ACTOR.actorType,
      actorRole: UNVERIFIED_BEARER_ACTOR.actorRole,
      payload: {
        revocationRef: existing.revocationRef,
        revokedDecisionRef: rightsCase.revokedDecisionRef,
        scope: "ALL",
        authPath: "RECOVERY",
        recoveryMethod: "HUMAN_ASSISTED",
        originPurposeRef: "ALL",
        initiatedVia: rightsCase.origin === "SCHOOL_REPORTED" ? "SCHOOL_REPORT" : "DECISION_MAKER",
        caseRef: rightsCase.caseRef,
      },
      idempotencyKey: `${existing.revocationRef}:r12:${rightsCase.caseRef}`,
    });
    return { rightsCase, revocation: existing };
  });
}

/**
 * RC2u (rights-case.spec.yaml): ConfirmCaseReturnViaHandle — POST explícito del solicitante
 * desde la página del caso servida por /m/, tras GRD-CM-10 (CSRF/Origin, aplicado por el
 * entrypoint HTTP antes de llamar esta función). El caso se resuelve SIEMPRE del handle
 * (GRD-RC-14); nunca de un caseRef del cliente. GRD-RC-07: solo
 * transiciona si origin = CHANNEL_UNREACHABLE; si no, respuesta uniforme ERR-RC-01 sin evento
 * (TEST-CNS-399). Idempotente por caseRef (idempotencyKey: caseRef): con el caso ya en
 * CONTACTING, un reintento devuelve el mismo resultado sin reemitir RIGHTS_CASE_CONTACTING ni
 * consumir el handle (TEST-CNS-470); el handle de /m/ nunca se rota ni invalida aquí.
 * CA-124 PR-D: una tx con lock de fila y base previa; dos RC2u concurrentes: una transiciona, la otra ve
 * CONTACTING y devuelve el mismo resultado sin evento (SEC-CNS-015 P2-E).
 */
export async function confirmCaseReturnViaHandle(
  ports: Pick<RightsCasePorts, "tenantHandle" | "rightsCaseRepo" | "ledger" | "uow">,
  handle: string,
): Promise<RightsCaseRecord> {
  const resolved = await resolveHandleOrReject(ports.tenantHandle, handle);
  return inTx(ports, resolved.tenantId, async (p) => {
    const open = await openCaseForResolvedHandle(p, resolved);
    const base = await lastLedgerSequence(p.ledger, resolved.tenantId, open.caseRef);
    const rightsCase = await lockCase(p, resolved.tenantId, open.caseRef);

    if (rightsCase.status === "CONTACTING") {
      // Reintento tras un POST previo ya aplicado: mismo resultado, sin nuevo evento
      // (idempotencyKey: caseRef; TEST-CNS-470).
      return rightsCase;
    }

    if (rightsCase.status !== "OPEN") {
      throw new DomainError("ERR-CM-06");
    }

    if (rightsCase.origin !== "CHANNEL_UNREACHABLE") {
      // GRD-RC-07 onFail: respuesta uniforme ERR-RC-01, sin evento (SEC-CNS-013).
      throw new DomainError("ERR-RC-01");
    }

    const updated: RightsCaseRecord = { ...rightsCase, status: "CONTACTING" };
    await p.rightsCaseRepo.save(updated);
    await p.ledger.append({
      expectedSequence: base,
      eventType: "RIGHTS_CASE_CONTACTING",
      tenantId: rightsCase.tenantId,
      aggregateType: "RightsCase",
      aggregateId: rightsCase.caseRef,
      actorType: UNVERIFIED_BEARER_ACTOR.actorType,
      actorRole: UNVERIFIED_BEARER_ACTOR.actorRole,
      // ledger-event-payloads.schema.json#/$defs/RIGHTS_CASE_CONTACTING exige caseRef (P1:
      // faltaba); recoveryRef se omite porque origin es siempre CHANNEL_UNREACHABLE en RC2u.
      payload: { caseRef: rightsCase.caseRef },
      // ":contacting": la key plana `caseRef` colisionaba con otros eventos del mismo agregado (SEC-CNS-016 P2-5).
      idempotencyKey: `${rightsCase.caseRef}:contacting`,
    });
    return updated;
  });
}

export interface OpenRightsCaseInput {
  readonly caseRef: string;
  readonly chainRef: string;
  readonly revokedDecisionRef: string;
  readonly origin: "LIMIT_REACHED" | "CHANNEL_UNREACHABLE" | "REQUESTER_ASKED";
}

/**
 * RC1 fuente BEARER (rights-case.spec.yaml): null -> OPEN, POST explícito desde el handle
 * MANAGE_ENTRY de /m/ (CA-116 UX-CNS-004 §3 "bloqueado→caso humano"). Alcance IT0 de este
 * slice: idempotente por (tenantId, chainRef, revokedDecisionRef) — GRD-RC-02, ≤1 caso no
 * terminal por ciclo — devolviendo el caso ya abierto sin duplicar el evento; no implementa
 * case_contact opcional (CHANNEL_UNREACHABLE) ni FLAG-escalated/REVOCATION_ESCALATED sobre una
 * Revocation ya abierta (eso pertenece a R12/RC3a, fuera de alcance de este slice).
 * CA-124 PR-D: una tx; agregado nuevo (expectedSequence 0), la carrera la resuelve el UNIQUE parcial
 * GRD-RC-02 y el reintento del UoW (la perdedora devuelve el caso ya abierto).
 */
export function openRightsCase(
  ports: Pick<RightsCasePorts, "rightsCaseRepo" | "ledger" | "uow">,
  tenantId: string,
  input: OpenRightsCaseInput,
): Promise<RightsCaseRecord> {
  return inTx(ports, tenantId, async (p) => {
    const existing = await p.rightsCaseRepo.findOpenByChain(tenantId, input.chainRef, input.revokedDecisionRef);
    if (existing) return existing;

    const record: RightsCaseRecord = {
      caseRef: input.caseRef,
      tenantId,
      chainRef: input.chainRef,
      revokedDecisionRef: input.revokedDecisionRef,
      status: "OPEN",
      origin: input.origin,
    };
    await p.rightsCaseRepo.save(record);
    await p.ledger.append({
      expectedSequence: 0, // agregado nuevo
      eventType: "RIGHTS_CASE_OPENED",
      tenantId,
      aggregateType: "RightsCase",
      aggregateId: input.caseRef,
      actorType: UNVERIFIED_BEARER_ACTOR.actorType,
      actorRole: UNVERIFIED_BEARER_ACTOR.actorRole,
      payload: { reasonCode: input.origin, initiatedVia: "DECISION_MAKER" },
      idempotencyKey: `${tenantId}:${input.chainRef}:${input.revokedDecisionRef}`,
    });
    return record;
  });
}

export type CaseCloseOutcome = "RESOLVED" | "WITHDRAWN";

/**
 * RC4/RC5/RC6 (close_case), simplificado a lo que exigen los tests de este slice: cierra un
 * caso ya en CONTACTING o IN_VERIFICATION. GRD-CM-06 (route_class_rights): esta función
 * nunca lee tenant.active, Study.active, SchoolParticipation ni Enrollment (INV-CM-06); de
 * hecho no recibe ningún puerto de esos agregados, así que un tenant SUSPENDED en un
 * registro aparte no puede afectarla (TEST-CNS-461).
 * CA-124 PR-D: una tx con lock de fila y base previa (SEC-CNS-015 P2-E).
 */
export function closeCase(
  ports: Pick<RightsCasePorts, "rightsCaseRepo" | "ledger" | "uow">,
  tenantId: string,
  caseRef: string,
  outcome: CaseCloseOutcome,
): Promise<RightsCaseRecord> {
  return inTx(ports, tenantId, async (p) => {
    const base = await lastLedgerSequence(p.ledger, tenantId, caseRef);
    const found = await lockCase(p, tenantId, caseRef);
    if (found.status !== "CONTACTING" && found.status !== "IN_VERIFICATION") {
      throw new DomainError("ERR-CM-06");
    }
    const closed: RightsCaseRecord = { ...found, status: outcome };
    await p.rightsCaseRepo.save(closed);
    await p.ledger.append({
      expectedSequence: base,
      eventType: "RIGHTS_CASE_CLOSED",
      tenantId,
      aggregateType: "RightsCase",
      aggregateId: caseRef,
      actorType: "HUMAN",
      actorRole: "RIGHTS_OPERATOR",
      // ledger-event-payloads.schema.json#/$defs/RIGHTS_CASE_CLOSED exige también caseRef (P1:
      // faltaba).
      payload: { caseRef, outcome },
      // ":closed": con la key plana `caseRef` (la misma de RIGHTS_CASE_CONTACTING, mismo aggregateId) el ledger
      // dedupea y RIGHTS_CASE_CLOSED no se escribia tras RC2u (FINDING P1, CA-124 PR-D).
      idempotencyKey: `${caseRef}:closed`,
    });
    return closed;
  });
}
