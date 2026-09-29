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

import {
  LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY,
  LOCAL_ONLY_DEV_OTHER_TENANT_ID,
  LOCAL_ONLY_DEV_OTP_POLICY,
  LOCAL_ONLY_DEV_RELATIONSHIP_CONFIG,
  LOCAL_ONLY_DEV_STAFF_ROSTER,
  LOCAL_ONLY_DEV_TENANT_ID,
} from "../../../src/server/entrypoints/dev-local-config.ts";
import { loadInvitationIssuancePolicyConfig } from "../../../src/server/modules/invitation/invitation-issuance-policy.config.ts";
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

test("TEST-CNS-726: el roster sintético de dev no reutiliza personas entre roles (GRD-RC-15), los TENANT_ADMIN (CA-125) llevan tenant propio y distinto, y la política de emisión LOCAL cumple el loader real", () => {
  const refs = LOCAL_ONLY_DEV_STAFF_ROSTER.map((p) => p.principalRef);
  assert.equal(new Set(refs).size, refs.length, "principalRef repetido entre roles");
  const admins = LOCAL_ONLY_DEV_STAFF_ROSTER.filter((p) => p.role === "TENANT_ADMIN");
  assert.equal(admins.length, 2);
  assert.deepEqual(new Set(admins.map((p) => (p as { tenantId?: string }).tenantId)), new Set([LOCAL_ONLY_DEV_TENANT_ID, LOCAL_ONLY_DEV_OTHER_TENANT_ID]));
  for (const p of LOCAL_ONLY_DEV_STAFF_ROSTER.filter((p) => p.role !== "TENANT_ADMIN")) {
    assert.equal((p as { tenantId?: string }).tenantId, undefined, "los roles CASE no llevan tenant");
  }
  assert.doesNotThrow(() => loadInvitationIssuancePolicyConfig(LOCAL_ONLY_DEV_INVITATION_ISSUANCE_POLICY));
  // Sin valores explícitos no hay default de producción (fail-closed).
  assert.throws(() => loadInvitationIssuancePolicyConfig({}));
  assert.throws(() => loadInvitationIssuancePolicyConfig({ expiresInMs: 1000 }));
});
