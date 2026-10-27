// origen: src/server/modules/consent-decision/served-consent-version.ts@9345b78 (texto placeholder y forma ServedConsentVersion; sin cambios de lógica).
// Gobierna: plan v2 H1-05. BORRADOR / LEGAL DECISION: el texto de consentimiento real, su versión y el aviso de privacidad los aprueba Carlos (LD-06);
// este placeholder solo satisface la FORMA del contrato. La versión y el hash servidos son los que recibe record_decision.

import { createHash } from "node:crypto";

export const SERVED_CONSENT_VERSION_TEXT = "[BORRADOR / LEGAL DECISION — texto de consentimiento pendiente de aprobación de Carlos]";

export interface ServedConsentVersion {
  readonly consentVersion: string;
  readonly privacyNoticeVersion: string;
  /** SHA-256 hex del texto servido (bytes UTF-8). */
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

/** Relaciones de apoderado aceptadas en la declaración de autoridad. BORRADOR / LEGAL DECISION (qué relación basta es decisión de Carlos; DEC-BR-003). */
export const ALLOWED_RELATIONSHIP_REFS: readonly string[] = ["LEGAL_GUARDIAN"];

/** Finalidades requeridas (lista cerrada de record_decision). allowPartialGrant = false: todas GRANT => GRANTED; alguna DECLINE => DECLINED. */
export const REQUIRED_PURPOSES: readonly string[] = ["STUDY_PARTICIPATION", "AUDIO_RECORDING", "AUTOMATED_ANALYSIS", "HUMAN_REVIEW"];
