// Gobierna: INV-CM-09 rev. 4g / OPEN-CM-10, revision lampone-security P2-6.
// Claves SINTETICAS y explicitas para tests: createDefaultConsentFlowPorts / createConsentFlowHttpServer
// ya no generan chainRef/decisionMakerRef con clave aleatoria por defecto (fail-open).
import { deriveChainRefKey } from "../../src/server/modules/consent-decision/chain-ref.ts";
import { deriveDecisionMakerRefKey } from "../../src/server/modules/consent-decision/decision-maker-ref.ts";

export const TEST_CHAIN_REF_KEY = deriveChainRefKey(Buffer.alloc(32, 9));
export const TEST_DECISION_MAKER_REF_KEY = deriveDecisionMakerRefKey(Buffer.alloc(32, 8));

// P2-6 (continuacion): claves SINTETICAS y explicitas de sesion / OTP / cursor del roster. Distintas entre si
// (una por proposito); createConsentFlowHttpServer rechaza que coincidan.
export const TEST_SESSION_SECRET = Buffer.alloc(32, 7);
export const TEST_OTP_SECRET = Buffer.alloc(32, 6);
export const TEST_STAFF_ROSTER_CURSOR_KEY = Buffer.alloc(32, 5);
