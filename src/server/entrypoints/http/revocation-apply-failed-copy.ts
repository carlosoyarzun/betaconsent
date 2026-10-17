// Gobierna: F-PR6-25 (hallazgos F-PR6-51 y F-PR6-52), UX-CNS-015, DEC-BR-006 / REQ-CNS-033 (el
// acuse y el recibo son gate de Carlos: este archivo NO los implementa), RULE-CNS-026.
//
// Copy INTERINO y NO LEGAL de los avisos de "retiro no completado" (HTTP 503
// GUARD_EVALUATOR_UNAVAILABLE de R3/R3r + R4), literal de ravena-ux
// (UX-revocation-apply-failed-copy.md, 2026-10-17, opción 1B de F-PR6-25). No es copy legal de
// producción: lo reemplaza el copy aprobado por Carlos (REQ-CNS-033, F-PR6-25). Ninguno puede decir
// que la solicitud quedó registrada, recibida o en proceso (no hay acuse; DEC-BR-006).
// Los códigos ERR-RV-21/22 son solo de presentación (no cambian el cuerpo de la API: 503 uniforme).

export const HELP_MAILTO = "mailto:ayuda@example.invalid";

/** Pantalla A (vía OTP): revocation-page.ts, bloque #error-apply-failed. */
export const REVOCATION_APPLY_FAILED_COPY = {
  title: "No pudimos completar tu retiro",
  body: "Ocurrió un problema interno y tu retiro no se completó. Tu autorización sigue vigente. El código que usaste puede haber expirado: pide uno nuevo e inténtalo otra vez. Si el problema continúa, escríbenos a ayuda@example.invalid (correo provisorio de pruebas).",
  code: "ERR-RV-21",
  codeLabel: "Código",
  primaryLabel: "Empezar de nuevo",
  helpLabel: "Escribir al equipo del estudio",
} as const;

/** Pantalla B (vía enlace de recuperación): recovery-page.ts, bloque #error-apply-failed. */
export const RECOVERY_APPLY_FAILED_COPY = {
  title: "No pudimos completar tu retiro ahora",
  body: "Tu enlace sigue siendo válido, pero ocurrió un problema interno y el retiro no se completó. Tu autorización sigue vigente. Vuelve a intentarlo desde este mismo enlace en unos minutos. Si continúa, escríbenos a ayuda@example.invalid (correo provisorio de pruebas).",
  code: "ERR-RV-22",
  codeLabel: "Código",
  primaryLabel: "Volver a intentar",
  helpLabel: "Escribir al equipo del estudio",
} as const;
