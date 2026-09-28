// Gobierna: contracts/schemas/api-payloads.schema.json ServedConsentVersion (:489-516) y
// specs/state-machines/consent-decision.spec.yaml GRD-CD-03 (served_version_in_force_and_hash,
// :286-291: "Versión servida = versión en vigor; consentTextHash calculado por el servidor
// sobre lo servido; en el submit, hash devuelto = servido = en vigor").
//
// Extraído de consent-flow.handler.ts a un módulo propio (sin efectos secundarios) para que
// GET /decision (decision-page.ts, vía consent-flow-server.ts) pueda renderizar el MISMO texto
// servido sin llamar recordDecisionStep ni emitir CONSENT_VERSION_VIEWED (common.spec.yaml
// INV-CM-08: un GET nunca transiciona). El evento de ledger CONSENT_VERSION_VIEWED sigue
// emitiéndose solo por POST /decision/steps (C2), como exige la máquina de estados; esto solo
// evita que el usuario vea "cargando…" antes de interactuar (Carlos, revisión en navegador).
//
// LD-06 (consentTextHash como prueba de lo mostrado) y el texto legal real siguen PENDING
// (marcador [LEGAL DECISION] literal); este placeholder solo satisface la FORMA del contrato.

import { createHash } from "node:crypto";

const SERVED_CONSENT_VERSION_TEXT = "[LEGAL DECISION — texto de consentimiento pendiente de aprobación de Carlos]";

export interface ServedConsentVersion {
  readonly consentVersion: string;
  readonly privacyNoticeVersion: string;
  readonly consentTextHash: string;
  readonly text: string;
}

export function getServedConsentVersion(): ServedConsentVersion {
  return {
    consentVersion: "v1",
    privacyNoticeVersion: "v1",
    consentTextHash: createHash("sha256").update(SERVED_CONSENT_VERSION_TEXT).digest("hex"),
    text: SERVED_CONSENT_VERSION_TEXT,
  };
}
