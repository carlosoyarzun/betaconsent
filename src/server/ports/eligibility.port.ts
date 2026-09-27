// Gobierna: specs/state-machines/common.spec.yaml GRD-CM-05 (route_class_issuance_decision).
// Puerto (ADR-001 §11): evalúa la fórmula conjuntiva de DEC-BR-016 §8 (study.active AND
// tenant.active AND schoolParticipation.active AND enrollment.active AND consent.valid AND
// NOT revoked AND NOT suspended) para la ruta ISSUANCE_DECISION. El dominio de Invitation,
// otp-challenge y consent-decision NUNCA evalúa esta fórmula por sí mismo: la delega en este
// puerto. IT0 no tiene todavía el módulo tenant-context (Study/SchoolParticipation/Enrollment
// reales); el adaptador in-memory de este puerto es un stub controlado por fixtures hasta que
// esa historia exista (pendiente, ver reporte de esta tarea).

import type { TenantId } from "../modules/common/types.ts";

export interface EligibilityPort {
  /** Estado desconocido, desactualizado o con error = false (fail-closed, GRD-CM-05). */
  isEligibleForIssuance(tenantId: TenantId, contextRef: string, productRef: string): boolean;
}
