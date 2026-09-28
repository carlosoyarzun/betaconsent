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

import { DomainError } from "../common/errors.ts";
import { resolveHandleOrReject } from "../common/guards.ts";
import { UNVERIFIED_BEARER_ACTOR } from "../common/types.ts";
import type { TenantHandlePort } from "../../ports/tenant-handle.port.ts";
import type { RightsCaseRecord, RightsCaseRepositoryPort } from "../../ports/rights-case-repository.port.ts";
import type { RevocationRecord, RevocationRepositoryPort } from "../../ports/revocation-repository.port.ts";
import type { LedgerPort } from "../../ports/ledger.port.ts";

export interface RightsCasePorts {
  readonly tenantHandle: TenantHandlePort;
  readonly rightsCaseRepo: RightsCaseRepositoryPort;
  readonly revocationRepo: RevocationRepositoryPort;
  readonly ledger: LedgerPort;
}

/**
 * GRD-RC-14 (case_bound_to_handle_chain) + GRD-CM-01: el caso se resuelve SIEMPRE en
 * servidor desde el (tenant_id, chainRef) del handle de la request; un caseRef enviado por
 * el cliente se ignora (no se usa ni para desambiguar). Handle inválido/rotado -> ERR-CM-01
 * (404 uniforme, sin evento; TEST-CNS-458). Un caseRef de otro tenant nunca se resuelve
 * porque este método nunca lo consulta (TEST-CNS-459).
 */
export function resolveCaseForHandle(
  ports: Pick<RightsCasePorts, "tenantHandle" | "rightsCaseRepo">,
  handle: string,
  _clientSuppliedCaseRef?: string,
): RightsCaseRecord {
  const resolved = resolveHandleOrReject(ports.tenantHandle, handle);
  const found = ports.rightsCaseRepo.findOpenByChain(
    resolved.tenantId,
    resolved.chainRef,
    resolved.revokedDecisionRef,
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

/**
 * RC3 (rights-case + revocation) / R12: intención expresa del DecisionMaker en la página del
 * caso, resuelto siempre desde el handle (GRD-RC-14; TEST-CNS-459). El actor registrado en el
 * ledger es SIEMPRE {actorType: HUMAN, actorRole: UNVERIFIED_BEARER} (P-v7-3, R14-A): esta
 * función no acepta ni deriva el actor de ningún parámetro del llamador, así que no puede
 * registrar SYSTEM_GUARD ni ningún otro actorRole (TEST-CNS-460).
 */
export function expressRevocationIntentInCase(
  ports: RightsCasePorts,
  handle: string,
  clientSuppliedCaseRef?: string,
): RevocationIntentResult {
  const rightsCase = resolveCaseForHandle(ports, handle, clientSuppliedCaseRef);

  if (!rightsCase.revocationRef) {
    // RC3: no hay Revocation abierta -> crea REQUESTED en el mismo lote.
    const revocationRef = `rv-${rightsCase.caseRef}`;
    const revocation: RevocationRecord = {
      revocationRef,
      tenantId: rightsCase.tenantId,
      chainRef: rightsCase.chainRef,
      caseRef: rightsCase.caseRef,
      status: "REQUESTED",
    };
    ports.revocationRepo.save(revocation);
    const updatedCase: RightsCaseRecord = {
      ...rightsCase,
      revocationRef,
      status: "IN_VERIFICATION",
    };
    ports.rightsCaseRepo.save(updatedCase);
    ports.ledger.append({
      eventType: "REVOCATION_REQUESTED",
      tenantId: rightsCase.tenantId,
      aggregateType: "Revocation",
      aggregateId: revocationRef,
      actorType: UNVERIFIED_BEARER_ACTOR.actorType,
      actorRole: UNVERIFIED_BEARER_ACTOR.actorRole,
      payload: { caseRef: rightsCase.caseRef },
      idempotencyKey: revocationRef,
    });
    return { rightsCase: updatedCase, revocation };
  }

  // R12: ya hay Revocation abierta de la decisión vigente -> se adjunta, no crea otra.
  const existing = ports.revocationRepo.findByRef(rightsCase.tenantId, rightsCase.revocationRef);
  if (!existing) {
    throw new DomainError("ERR-CM-01");
  }
  ports.ledger.append({
    eventType: "REVOCATION_REQUESTED",
    tenantId: rightsCase.tenantId,
    aggregateType: "Revocation",
    aggregateId: existing.revocationRef,
    actorType: UNVERIFIED_BEARER_ACTOR.actorType,
    actorRole: UNVERIFIED_BEARER_ACTOR.actorRole,
    payload: { caseRef: rightsCase.caseRef, attached: true },
    idempotencyKey: `${existing.revocationRef}:r12:${rightsCase.caseRef}`,
  });
  return { rightsCase, revocation: existing };
}

/**
 * RC2u (rights-case.spec.yaml): ConfirmCaseReturnViaHandle — POST explícito del solicitante
 * desde la página del caso servida por /m/, tras GRD-CM-10 (CSRF/Origin, aplicado por el
 * entrypoint HTTP antes de llamar esta función). El caso se resuelve SIEMPRE del handle
 * (GRD-RC-14, vía resolveCaseForHandle); nunca de un caseRef del cliente. GRD-RC-07: solo
 * transiciona si origin = CHANNEL_UNREACHABLE; si no, respuesta uniforme ERR-RC-01 sin evento
 * (TEST-CNS-399). Idempotente por caseRef (idempotencyKey: caseRef): con el caso ya en
 * CONTACTING, un reintento devuelve el mismo resultado sin reemitir RIGHTS_CASE_CONTACTING ni
 * consumir el handle (TEST-CNS-470); el handle de /m/ nunca se rota ni invalida aquí.
 */
export function confirmCaseReturnViaHandle(
  ports: Pick<RightsCasePorts, "tenantHandle" | "rightsCaseRepo" | "ledger">,
  handle: string,
): RightsCaseRecord {
  const rightsCase = resolveCaseForHandle(ports, handle);

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
  ports.rightsCaseRepo.save(updated);
  ports.ledger.append({
    eventType: "RIGHTS_CASE_CONTACTING",
    tenantId: rightsCase.tenantId,
    aggregateType: "RightsCase",
    aggregateId: rightsCase.caseRef,
    actorType: UNVERIFIED_BEARER_ACTOR.actorType,
    actorRole: UNVERIFIED_BEARER_ACTOR.actorRole,
    // ledger-event-payloads.schema.json#/$defs/RIGHTS_CASE_CONTACTING exige caseRef (P1:
    // faltaba); recoveryRef se omite porque origin es siempre CHANNEL_UNREACHABLE en RC2u.
    payload: { caseRef: rightsCase.caseRef },
    idempotencyKey: rightsCase.caseRef,
  });
  return updated;
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
 */
export function openRightsCase(
  ports: Pick<RightsCasePorts, "rightsCaseRepo" | "ledger">,
  tenantId: string,
  input: OpenRightsCaseInput,
): RightsCaseRecord {
  const existing = ports.rightsCaseRepo.findOpenByChain(tenantId, input.chainRef, input.revokedDecisionRef);
  if (existing) return existing;

  const record: RightsCaseRecord = {
    caseRef: input.caseRef,
    tenantId,
    chainRef: input.chainRef,
    revokedDecisionRef: input.revokedDecisionRef,
    status: "OPEN",
    origin: input.origin,
  };
  ports.rightsCaseRepo.save(record);
  ports.ledger.append({
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
}

export type CaseCloseOutcome = "RESOLVED" | "WITHDRAWN";

/**
 * RC4/RC5/RC6 (close_case), simplificado a lo que exigen los tests de este slice: cierra un
 * caso ya en CONTACTING o IN_VERIFICATION. GRD-CM-06 (route_class_rights): esta función
 * nunca lee tenant.active, Study.active, SchoolParticipation ni Enrollment (INV-CM-06); de
 * hecho no recibe ningún puerto de esos agregados, así que un tenant SUSPENDED en un
 * registro aparte no puede afectarla (TEST-CNS-461).
 */
export function closeCase(
  ports: Pick<RightsCasePorts, "rightsCaseRepo" | "ledger">,
  tenantId: string,
  caseRef: string,
  outcome: CaseCloseOutcome,
): RightsCaseRecord {
  const found = ports.rightsCaseRepo.findByRef(tenantId, caseRef);
  if (!found) {
    throw new DomainError("ERR-CM-01");
  }
  if (found.status !== "CONTACTING" && found.status !== "IN_VERIFICATION") {
    throw new DomainError("ERR-CM-06");
  }
  const closed: RightsCaseRecord = { ...found, status: outcome };
  ports.rightsCaseRepo.save(closed);
  ports.ledger.append({
    eventType: "RIGHTS_CASE_CLOSED",
    tenantId,
    aggregateType: "RightsCase",
    aggregateId: caseRef,
    actorType: "HUMAN",
    actorRole: "RIGHTS_OPERATOR",
    // ledger-event-payloads.schema.json#/$defs/RIGHTS_CASE_CLOSED exige también caseRef (P1:
    // faltaba).
    payload: { caseRef, outcome },
    idempotencyKey: caseRef,
  });
  return closed;
}
