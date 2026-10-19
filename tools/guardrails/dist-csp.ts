// Gobierna: ADR-001 rev. 8 F1 y §3. La lógica vive en src/server/entrypoints/http/dist-validation.ts (la usa también el
// arranque del web en CNS_UI_MODE=spa, fail-closed); este módulo la reexporta para el CLI y los tests del guardrail.
export * from "../../src/server/entrypoints/http/dist-validation.ts";
