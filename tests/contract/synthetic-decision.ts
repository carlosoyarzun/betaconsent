// Fixture de tests (SYNTHETIC DATA ONLY), CA-127: R4 lee la decisión revocada para poblar
// contextRef/subjectRef del sobre del outbox (consent.revoked). Estos helpers siembran una
// ConsentDecisionRecord GRANTED sintética con refs válidas contra common.schema.json.

import { fixtureUuid } from "./uuid-fixture.ts";
import type { ConsentDecisionRecord, ConsentDecisionRepositoryPort } from "../../src/server/ports/consent-decision-repository.port.ts";

export const SYNTHETIC_CONTEXT_REF = "BETA_2026_01";

export function syntheticDecision(tenantId: string, consentId: string): ConsentDecisionRecord {
  return {
    consentId,
    tenantId,
    contextRef: SYNTHETIC_CONTEXT_REF,
    productRef: "LECTORPRO_BETA",
    subjectRef: fixtureUuid(`subject:${tenantId}:${consentId}`),
    decisionMakerRef: fixtureUuid(`dm:${tenantId}:${consentId}`),
    invitationRef: fixtureUuid(`inv:${consentId}`),
    verificationRef: fixtureUuid(`ver:${consentId}`),
    chainRef: fixtureUuid(`chain:${tenantId}:${consentId}`),
    state: "GRANTED",
    purposes: [],
    priorStepsComplete: true,
    stepsRecorded: [],
  };
}

/** Decora un repositorio: si la decisión no existe devuelve una sintética (sin persistirla). Para
 * tests de R2/R3/RH3 que no ejercitan la lectura de la decisión. Los tests de "decisión
 * inexistente" (TEST-CNS-691) usan el repositorio sin decorar. */
export function withSyntheticFallback(repo: ConsentDecisionRepositoryPort): ConsentDecisionRepositoryPort {
  return {
    ...repo,
    findByConsentId: async (tenantId, consentId) => await repo.findByConsentId(tenantId, consentId) ?? syntheticDecision(tenantId, consentId),
    findByConsentIdForUpdate: async (tenantId, consentId) => await repo.findByConsentIdForUpdate(tenantId, consentId) ?? syntheticDecision(tenantId, consentId),
  };
}
