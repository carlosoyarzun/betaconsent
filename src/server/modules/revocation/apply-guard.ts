// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §4.2.a puntos 4 y 5 (G-3: "revocacion atomica, reintentos acotados y recuperacion por el proceso de respaldo (worker); el agotamiento
// de reintentos genera alerta y mantiene el caso pendiente, sin emitir acuse de aplicacion exitosa"; lectura (A) confirmada por Carlos el 2026-10-15), §10 fila 6d, §15.3 punto 4; F-PR6-14, F-PR6-25;
// specs/state-machines/revocation.spec.yaml (R3, R3r, R4, RH3; comportamiento ante agotamiento); db/migrations/0066 (R4 atomica en la base) y 0067 (alerta).
//
// Guardia del llamador (web para R3/R3r, platform para RH3) alrededor de la tx COMPLETA "R3/R3r/RH3 + R4 + C6 + ledger":
//  1. Atomica: la base revierte todo si R4 falla; aqui nunca se reintenta "solo R4".
//  2. Reintentos acotados: ante un error TRANSITORIO (40001, 40P01, 55P03, conflicto de secuencia, conexion perdida) se reintenta la tx completa, hasta `maxAttempts` (tope tecnico configurable, no regulatorio), con
//     backoff. Un error de dominio (guard de la base, 404 uniforme, etc.) NO se reintenta: se propaga igual que antes.
//  3. Commit ambiguo: ANTES de cada reintento se lee el estado. Si la Revocation ya esta APPLIED por esta misma solicitud (misma revocationRef; las claves de idempotencia del ledger son las de la ref), se devuelve el
//     resultado REAL (con su recibo); si sigue sin aplicar, se reintenta. Nunca se informa fallo de algo que se aplico ni exito de algo que no.
//  4. Agotamiento: (a) alerta a operacion (evento sin PII, motivo R4_RETRIES_EXHAUSTED) en una tx SEPARADA, posterior al rollback; (b) si esa tx tambien falla, la alerta va al LOG del proceso sin PII (codigo de
//     motivo, ref opaca, hora) y el llamador igual recibe el error uniforme (fail-closed); (c) el caso queda pendiente (la Revocation sigue VERIFIED / en su estado previo, sin APPLIED; el seguimiento es el worker de respaldo
//     para CONFIRMED sin APPLIED y, si nadie actua, la escalada humana R9 por TTL P-19); (d) se lanza RevocationApplyUnavailableError: NUNCA un acuse de aplicacion exitosa.
//  5. Fallo NO transitorio y NO guard de dominio (G-3 alcance, Carlos 2026-10-16, opcion A; p. ej. XX000): alerta R4_APPLY_FAILED con las mismas garantias (tx separada, sin PII, log si falla) y el error original se
//     propaga sin acuse de exito. Los guards de dominio (rechazos esperados) no alertan.
//
// LEGAL DECISION (F-PR6-25, no la decide este codigo ni ningun modelo): que se comunica al titular cuando se agotan los reintentos; si basta la alerta como registro de la voluntad expresada en R1r-R3r (donde no queda
// ninguna fila); y si el plazo P-19 hasta R9 es aceptable tras una confirmacion fallida. Este modulo solo lanza el error uniforme; el handler HTTP no inventa texto para el titular.
//
// 2B (F-PR6-25, DEC-BR-017, diseño F-PR6-25-2B-R9 rev. 2 §2/C6): ademas de la alerta, y en OTRA tx posterior a ella (independiente: ninguna depende de la otra), el proceso WEB registra de forma durable y sin PII que
// "informo un intento de revocacion confirmado y no aplicado" (ApplyAttemptSink). No cambia la Revocation, la Decision (sigue GRANTED), el ledger ni el outbox; nunca lanza ni cambia el error propagado; no se llama ante un
// guard de dominio. Si falla, linea de log sin PII con attempt_id, attempt_ref y recovery_ref (nunca el token ni su hash). Valor probatorio del registro: LEGAL DECISION (c), no se decide aqui.
//
// Sin PII: el log y la alerta llevan solo codigo de motivo, ref opaca y hora.

import { randomUUID } from "node:crypto";

export const APPLY_ALERT_REASONS = ["R4_RETRIES_EXHAUSTED", "R4_BACKUP_APPLIED", "R4_BACKUP_FAILED", "R4_APPLY_FAILED"] as const;
export type ApplyAlertReason = (typeof APPLY_ALERT_REASONS)[number];

/** Error uniforme de agotamiento (o de Revocation CONFIRMED sin APPLIED): el llamador NO emite acuse de exito. Sin detalle. */
export class RevocationApplyUnavailableError extends Error {
  readonly code = "REVOCATION_APPLY_UNAVAILABLE";
  constructor() {
    super("REVOCATION_APPLY_UNAVAILABLE");
    this.name = "RevocationApplyUnavailableError";
  }
}

/** Motivos del registro 2B: subconjunto de los de la alerta (los de respaldo del worker no se registran aqui). */
export const APPLY_ATTEMPT_REASONS = ["R4_RETRIES_EXHAUSTED", "R4_APPLY_FAILED"] as const;
export type ApplyAttemptReason = (typeof APPLY_ATTEMPT_REASONS)[number];

export interface ApplyAttemptInput {
  readonly tenantId: string;
  /** UUIDv4 generado UNA vez por llamada a runBoundedApply (un POST): clave de idempotencia del registro (C3). */
  readonly attemptId: string;
  /** Ref opaca (UUIDv4) de la Revocation usada por el intento (en R1r-R3r puede ser la generada para el intento). */
  readonly attemptRef: string;
  /** Ref opaca del registro del token de recuperacion (app.recovery_token.recovery_ref); NUNCA el token ni su hash. Presente solo en la via RECOVERY. */
  readonly recoveryRef?: string;
  readonly reason: ApplyAttemptReason;
  /** Intentos de la tx completa realizados en este POST (1..10). */
  readonly tries: number;
}

export type ApplyAttemptOutcome = "RECORDED" | "DUPLICATE" | "NOOP_APPLIED" | "NOOP_CAPPED";

/** Escribe el registro 2B en una tx propia de tenant. Puede lanzar: el guardia cae al log. Obligatorio en web (C6); no existe en platform. */
export type ApplyAttemptSink = (input: ApplyAttemptInput) => Promise<ApplyAttemptOutcome>;

export interface ApplyAlertInput {
  readonly tenantId: string;
  /** Ref opaca (UUIDv4) de la Revocation; en R1r-R3r tras el rollback es la ref generada para el intento. */
  readonly revocationRef: string;
  readonly reason: ApplyAlertReason;
}

/** Escribe la alerta en una tx propia (el adaptador decide como: web/worker por `ops.record_revocation_apply_alert`, platform por `platform.alert_case_apply_exhausted`). Puede lanzar: el guardia cae al log. */
export type ApplyAlertSink = (input: ApplyAlertInput) => Promise<void>;

export interface ApplyGuardConfig {
  /** Tope tecnico de intentos de la tx completa (>= 1). Valor inicial 3, configurable; NO es un parametro regulatorio. */
  readonly maxAttempts: number;
  /** Espera antes del reintento `attempt` (1-based); jitter y tope los decide el llamador. */
  readonly backoffMs: (attempt: number) => number;
  readonly sleep: (ms: number) => Promise<void>;
  /** Clasifica un error como transitorio o de commit ambiguo (infraestructura: SQLSTATE 40001/40P01/55P03, conflicto de secuencia, conexion perdida). */
  readonly isTransient: (error: unknown) => boolean;
  /** G-3 alcance (Carlos 2026-10-16, opcion A): true = guard de dominio (rechazo esperado: no es una falla de aplicar, no alerta). Todo otro error no transitorio dispara R4_APPLY_FAILED. */
  readonly isDomainGuard: (error: unknown) => boolean;
  readonly alert: ApplyAlertSink;
  /** 2B: registro durable del intento no aplicado. Obligatorio en el proceso web (se comprueba al arrancar); ausente en platform. */
  readonly attemptSink?: ApplyAttemptSink;
  /** Respaldo de la alerta (fail-closed): linea de log del proceso SIN PII. */
  readonly log: (line: string) => void;
  readonly now: () => Date;
}

export const DEFAULT_APPLY_MAX_ATTEMPTS = 3;

export function validateApplyGuardConfig(config: ApplyGuardConfig): ApplyGuardConfig {
  if (!Number.isInteger(config.maxAttempts) || config.maxAttempts < 1 || config.maxAttempts > 10) {
    throw new TypeError("ApplyGuardConfig.maxAttempts debe ser un entero entre 1 y 10 (fail-closed).");
  }
  return config;
}

const OPAQUE_REF = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Alerta de agotamiento: tx separada; si falla, log sin PII. Nunca lanza. */
export async function raiseApplyAlert(config: ApplyGuardConfig, input: ApplyAlertInput): Promise<"PERSISTED" | "LOGGED"> {
  try {
    await config.alert(input);
    return "PERSISTED";
  } catch {
    // Solo codigo de motivo, ref opaca (si tiene forma de ref) y hora; nunca el mensaje del error (podria llevar datos).
    const ref = OPAQUE_REF.test(input.revocationRef) ? input.revocationRef : "invalid-ref";
    config.log(`revocation_apply_alert reason=${input.reason} ref=${ref} at=${config.now().toISOString()} persisted=false`);
    return "LOGGED";
  }
}

/** Registro 2B: tx separada, DESPUES de la alerta y sin depender de ella. Nunca lanza; si falla, log sin PII. */
export async function recordApplyAttempt(config: ApplyGuardConfig, input: ApplyAttemptInput): Promise<ApplyAttemptOutcome | "LOGGED" | "SKIPPED"> {
  if (config.attemptSink === undefined) return "SKIPPED";
  try {
    const outcome = await config.attemptSink(input);
    if (outcome === "NOOP_CAPPED") config.log(`revocation_apply_attempt_capped reason=${input.reason} at=${config.now().toISOString()}`);
    return outcome;
  } catch {
    // Solo codigos y refs opacas con forma de UUID (el hash del token es hex de 64 y nunca pasa el filtro); jamas el mensaje del error.
    const safe = (v: string | undefined): string => (v !== undefined && OPAQUE_REF.test(v) ? v : "invalid-ref");
    const recovery = input.recoveryRef === undefined ? "" : ` recovery_ref=${safe(input.recoveryRef)}`;
    config.log(`revocation_apply_attempt_unrecorded reason=${input.reason} attempt_id=${safe(input.attemptId)} attempt_ref=${safe(input.attemptRef)}${recovery} at=${config.now().toISOString()} persisted=false`);
    return "LOGGED";
  }
}

export interface BoundedApplyContext {
  readonly tenantId: string;
  /** Ref de la Revocation de ESTA solicitud, si ya se conoce (R3: la de la sesion; R1r-R3r: la existente o la generada para el intento). Puede completarse durante el intento. */
  readonly revocationRef: () => string | undefined;
  /** 2B: UUIDv4 del POST (uno por llamada a runBoundedApply). Si falta se genera aqui; solo los tests lo fijan. */
  readonly attemptId?: string;
  /** 2B: ref opaca del token de recuperacion de esta solicitud (via RECOVERY), si la hay. */
  readonly recoveryRef?: () => string | undefined;
}

/**
 * Ejecuta `attempt` (la tx COMPLETA) con reintentos acotados. `readApplied` lee, en una tx NUEVA de solo lectura, el resultado real si la Revocation de esta solicitud ya esta APPLIED (o null). Devuelve el
 * resultado del intento o el resultado real leido; lanza RevocationApplyUnavailableError al agotar (tras la alerta). Los errores no transitorios se propagan tal cual.
 */
export async function runBoundedApply<T>(
  config: ApplyGuardConfig,
  ctx: BoundedApplyContext,
  attempt: () => Promise<T>,
  readApplied: (revocationRef: string) => Promise<T | null>,
): Promise<T> {
  validateApplyGuardConfig(config);
  const attemptId = ctx.attemptId ?? randomUUID();
  const register = (reason: ApplyAttemptReason, tries: number): Promise<unknown> => {
    const recoveryRef = ctx.recoveryRef?.();
    return recordApplyAttempt(config, { tenantId: ctx.tenantId, attemptId, attemptRef: ctx.revocationRef() ?? "", ...(recoveryRef === undefined ? {} : { recoveryRef }), reason, tries });
  };
  for (let n = 1; n <= config.maxAttempts; n += 1) {
    try {
      return await attempt();
    } catch (error) {
      if (!config.isTransient(error)) {
        // G-3 alcance (Carlos 2026-10-16, opcion A): un fallo que NO es guard de dominio ni transitorio (p. ej. XX000) alerta (tx separada, sin PII; si falla, log) y se propaga SIN acuse de exito.
        // RevocationApplyUnavailableError ya es el error uniforme de "aplicacion no disponible": no se alerta dos veces.
        if (!(error instanceof RevocationApplyUnavailableError) && !config.isDomainGuard(error)) {
          await raiseApplyAlert(config, { tenantId: ctx.tenantId, revocationRef: ctx.revocationRef() ?? "", reason: "R4_APPLY_FAILED" });
          await register("R4_APPLY_FAILED", n);
        }
        throw error;
      }
      if (n < config.maxAttempts) await config.sleep(config.backoffMs(n));
    }
    // Antes de reintentar (y tambien antes de rendirse) se lee el estado: un commit ambiguo pudo haber aplicado la solicitud.
    const ref = ctx.revocationRef();
    if (ref !== undefined) {
      let applied: T | null = null;
      try {
        applied = await readApplied(ref);
      } catch {
        applied = null; // la lectura tambien fallo: se sigue con el reintento / el agotamiento (nunca se supone exito)
      }
      if (applied !== null) return applied; // resultado REAL de lo aplicado, con su recibo
    }
  }
  const ref = ctx.revocationRef();
  await raiseApplyAlert(config, { tenantId: ctx.tenantId, revocationRef: ref ?? "", reason: "R4_RETRIES_EXHAUSTED" });
  await register("R4_RETRIES_EXHAUSTED", config.maxAttempts);
  throw new RevocationApplyUnavailableError();
}
