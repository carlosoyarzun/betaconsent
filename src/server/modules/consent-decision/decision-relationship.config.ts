// Gobierna: contracts/schemas/api-payloads.schema.json DecisionStepRequest
// (DECISION_MAKER_AUTHORITY_DECLARED.relationshipRef, pattern `^[A-Z_]{1,40}$`, :448-454) y
// specs/state-machines/consent-decision.spec.yaml GRD-CD-04 (relationship_and_authority_
// declaration, :292-297: "relationshipRef del enum ... EXT-A (DEC-BR-003, LD-01)").
//
// Carlos, 2026-09-27: opción (b) para relationshipRef — validar contra una lista de valores
// permitidos inyectada por configuración, mismo patrón exacto que otp-policy.config.ts
// (P-01/P-02/P-03/P-06). El enum real de relación (hijo/a, pupilo/a, tutor legal, etc.) sigue
// PENDING DEC-BR-003 / EXT-A / LD-01: nadie en este archivo decide cuáles son las relaciones
// legalmente suficientes para declarar autoridad, solo la forma de configurar la lista.
//
// Sin default de producción (mismo fail-closed que loadOtpPolicyConfig): si no hay override
// explícito ni `CNS_DECISION_RELATIONSHIP_REFS`, esta función lanza. Los únicos valores
// sintéticos permitidos viven en dev.ts y en tests, marcados LOCAL_ONLY_* (p.ej.
// `SYNTHETIC_GUARDIAN`), y deben cumplir el mismo patrón `^[A-Z_]{1,40}$` que el contrato.

const RELATIONSHIP_REF_PATTERN = /^[A-Z_]{1,40}$/;

export interface DecisionRelationshipConfig {
  /** Lista cerrada de relationshipRef aceptados por GRD-CD-04. PENDING DEC-BR-003 / EXT-A / LD-01
   * fija el enum legal real; esta lista es solo el mecanismo de configuración (opción b). */
  readonly allowedRelationshipRefs: readonly string[];
}

export interface DecisionRelationshipConfigOverrides {
  readonly allowedRelationshipRefs?: readonly string[];
}

function readListEnv(name: string): readonly string[] | undefined {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return undefined;
  return raw
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
}

/**
 * Construye la config de relationshipRef (GRD-CD-04, PENDING DEC-BR-003/EXT-A/LD-01). Sin
 * default de producción: si ninguna fuente (override explícito o `CNS_DECISION_RELATIONSHIP_
 * REFS`) provee una lista no vacía, lanza (fail-closed). Cada valor debe cumplir el patrón del
 * contrato (`^[A-Z_]{1,40}$`); un valor que no cumpla también hace fallar la carga (fail-closed,
 * nunca se filtra en silencio).
 */
export function loadDecisionRelationshipConfig(
  overrides: DecisionRelationshipConfigOverrides = {},
): DecisionRelationshipConfig {
  const allowedRelationshipRefs = overrides.allowedRelationshipRefs ?? readListEnv("CNS_DECISION_RELATIONSHIP_REFS");

  if (!allowedRelationshipRefs || allowedRelationshipRefs.length === 0) {
    throw new Error(
      "Configuración de relationshipRef incompleta: GRD-CD-04 / DEC-BR-003 / EXT-A / LD-01 no " +
        "tienen un enum aprobado por Carlos. No hay default de producción: fija " +
        "CNS_DECISION_RELATIONSHIP_REFS (lista separada por comas) o pasa un override explícito " +
        "LOCAL-only (dev.ts / tests).",
    );
  }
  for (const ref of allowedRelationshipRefs) {
    if (!RELATIONSHIP_REF_PATTERN.test(ref)) {
      throw new Error(
        `relationshipRef inválido en la configuración: "${ref}" no cumple ^[A-Z_]{1,40}$ ` +
          "(contracts/schemas/api-payloads.schema.json DecisionStepRequest).",
      );
    }
  }
  return { allowedRelationshipRefs };
}
