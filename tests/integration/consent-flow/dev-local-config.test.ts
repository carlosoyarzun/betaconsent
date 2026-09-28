// Gobierna: src/server/entrypoints/dev.ts (LOCAL_ONLY_DEV_OTP_POLICY /
// LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG, extraídas a dev-local-config.ts sin efectos secundarios).
// Bug (reporte de Carlos vía CI): dev.ts se caía al arrancar
// (`CNS_ENVIRONMENT=LOCAL node src/server/entrypoints/dev.ts`) con
// "relationshipRef inválido... IT0_SYNTHETIC_GUARDIAN no cumple ^[A-Z_]{1,40}$" (el dígito "0"
// no es ni A-Z ni "_"), y ningún test lo detectaba porque nada más importaba esos valores ni
// llamaba a los loaders reales con ellos. Este test cierra ese hueco: valida, con los loaders
// reales (loadOtpPolicyConfig / loadDecisionRelationshipConfig), los MISMOS valores que dev.ts
// usa para arrancar, sin tener que ejecutar dev.ts como proceso (que además tiene
// process.exit/server.listen al importarse). TEST-CNS-566.

import test from "node:test";
import assert from "node:assert/strict";

import { LOCAL_ONLY_DEV_OTP_POLICY, LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG } from "../../../src/server/entrypoints/dev-local-config.ts";
import { loadOtpPolicyConfig } from "../../../src/server/modules/otp-challenge/otp-policy.config.ts";
import { loadDecisionRelationshipConfig } from "../../../src/server/modules/consent-decision/decision-relationship.config.ts";

test("TEST-CNS-566: dev.ts arranca con una config LOCAL válida — loadOtpPolicyConfig y loadDecisionRelationshipConfig aceptan LOCAL_ONLY_DEV_OTP_POLICY / LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG sin lanzar", () => {
  assert.doesNotThrow(() => loadOtpPolicyConfig(LOCAL_ONLY_DEV_OTP_POLICY));
  assert.doesNotThrow(() => loadDecisionRelationshipConfig(LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG));

  // Cada relationshipRef debe cumplir el mismo patrón que exige el contrato (GRD-CD-04,
  // contracts/schemas/api-payloads.schema.json DecisionStepRequest): solo A-Z y "_", nunca
  // dígitos (regresión exacta del bug: "IT0_SYNTHETIC_GUARDIAN" contenía "0").
  for (const ref of LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG.allowedRelationshipRefs) {
    assert.match(ref, /^[A-Z_]{1,40}$/);
  }
});
