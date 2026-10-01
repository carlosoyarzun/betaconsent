// Re-export: la implementación vive en el módulo de dominio (consent-decision.ts emite CONSENT_VERSION_VIEWED /
// CONSENT_GRANTED / CONSENT_DECLINED con la misma versión y hash servidos; X6 P1-A). Ver
// src/server/modules/consent-decision/served-consent-version.ts.
export { getServedConsentVersion, type ServedConsentVersion } from "../../modules/consent-decision/served-consent-version.ts";
