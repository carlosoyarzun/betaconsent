// Copy INTERINO y NO LEGAL de los avisos de "retiro no completado" (503 GUARD_EVALUATOR_UNAVAILABLE de R3/R3r + R4):
// F-PR6-25 (F-PR6-51/52), opción 1B, ravena-ux 2026-10-17. Réplica literal de
// src/server/entrypoints/http/revocation-apply-failed-copy.ts (un test de backend compara ambos archivos: TEST-CNS-1933).
// NO es copy legal de producción; lo reemplazará DEC-BR-022 / copy aprobado por Carlos (REQ-CNS-033). Ninguno puede
// decir que la solicitud quedó registrada, recibida o en proceso (no hay acuse; DEC-BR-006).
export const HELP_MAILTO = "mailto:ayuda@example.invalid";

/** Pantalla A (vía OTP): /manage/revocation/confirm. */
export const REVOCATION_APPLY_FAILED_COPY = {
  title: "No pudimos completar tu retiro",
  body: "Ocurrió un problema interno y tu retiro no se completó. Tu autorización sigue vigente. El código que usaste puede haber expirado: pide uno nuevo e inténtalo otra vez. Si el problema continúa, escríbenos a ayuda@example.invalid (correo provisorio de pruebas).",
  code: "ERR-RV-21",
  codeLabel: "Código",
  primaryLabel: "Empezar de nuevo",
  helpLabel: "Escribir al equipo del estudio",
} as const;

/** Pantalla B (vía enlace de recuperación): /recovery/confirm. */
export const RECOVERY_APPLY_FAILED_COPY = {
  title: "No pudimos completar tu retiro ahora",
  body: "Tu enlace sigue siendo válido, pero ocurrió un problema interno y el retiro no se completó. Tu autorización sigue vigente. Vuelve a intentarlo desde este mismo enlace en unos minutos. Si continúa, escríbenos a ayuda@example.invalid (correo provisorio de pruebas).",
  code: "ERR-RV-22",
  codeLabel: "Código",
  primaryLabel: "Volver a intentar",
  helpLabel: "Escribir al equipo del estudio",
} as const;
