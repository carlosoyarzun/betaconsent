// Gobierna: revocation.spec.yaml RH2 (propose_case_verification + approve_case_verification, GRD-RV-09). Helper de tests:
// ejecuta RH2 con doble control (RIGHTS_OPERATOR propone, APPROVER distinto aprueba) sobre un roster sintético de 4 personas
// para los tests de RH3/R4/INV-6 que solo necesitan una Revocation VERIFIED HUMAN_ASSISTED. SYNTHETIC ONLY.

import { createInMemoryStaffIdentityAdapter } from "../../src/infra/adapters/in-memory-staff-identity.adapter.ts";
import {
  approveCaseVerification,
  proposeCaseVerification,
  type RevocationPorts,
} from "../../src/server/modules/revocation/revocation.ts";
import type { RevocationRecord } from "../../src/server/ports/revocation-repository.port.ts";
import { fixtureUuid } from "./uuid-fixture.ts";

export const RH2_OPERATOR = fixtureUuid("rh2-operator");
export const RH2_APPROVER = fixtureUuid("rh2-approver");
export const RH2_ROSTER = createInMemoryStaffIdentityAdapter([
  { principalRef: RH2_OPERATOR, role: "RIGHTS_OPERATOR" },
  { principalRef: fixtureUuid("rh2-operator-2"), role: "RIGHTS_OPERATOR" },
  { principalRef: RH2_APPROVER, role: "APPROVER" },
  { principalRef: fixtureUuid("rh2-approver-2"), role: "APPROVER" },
]);

/** Sustituye al antiguo RH2 de un paso: propone (RH2_OPERATOR) y aprueba (RH2_APPROVER) con aserción ATTESTED. */
export async function attestHumanAssistedVerification(
  ports: RevocationPorts,
  tenantId: string,
  revocationRef: string,
  caseRef: string,
): Promise<RevocationRecord> {
  const proposalRef = fixtureUuid(`proposal:${revocationRef}`);
  await proposeCaseVerification(ports, RH2_ROSTER, tenantId, revocationRef, caseRef, { principalRef: RH2_OPERATOR }, { proposalRef, verificationScriptVersion: "test-script-1" });
  return (await approveCaseVerification(ports, RH2_ROSTER, tenantId, revocationRef, caseRef, proposalRef, { principalRef: RH2_APPROVER }, true)).record;
}
