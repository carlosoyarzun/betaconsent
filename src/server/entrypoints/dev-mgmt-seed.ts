// Gobierna: F-E2E-01 (hallazgo P1 LOCAL de la línea base E2E), common.schema.json Ref (UUIDv4 opaco, INV-CM-09) y
// ledger-event-payloads.schema.json (LedgerPayloadViolationError, ERR-RV-13). SYNTHETIC DATA ONLY.
// Refs de la decisión GRANTED sembrada por dev.ts para el enlace de gestión /m/<token> (CA-116). Antes eran literales
// como "chain-dev-mgmt": no validan el contrato `Ref`, así que POST /otp/submit sobre ese enlace respondía 500 al
// escribir el evento del ledger. Ahora son UUIDv4 sintéticos fijos (LOCAL only, cero PII). El token del enlace no es
// una ref (es el secreto de canje) y se queda en dev.ts.
export const DEV_MGMT_SEED_REFS = {
  chainRef: "c1f4a7d2-3b58-4e69-8a10-5d7e9b2c4f61",
  consentId: "d2a5b8e3-4c69-4f7a-9b21-6e8fa03d5a72",
  decisionMakerRef: "e3b6c9f4-5d7a-4a8b-8c32-7f90b14e6b83",
  invitationRef: "f4c7dafa-6e8b-4b9c-9d43-80a1c25f7c94",
  verificationRef: "a5d8eb0b-7f9c-4cad-8e54-91b2d36a8da5",
  receiptRef: "b6e9fc1c-80ad-4dbe-9f65-a2c3e47b9eb6",
} as const;
