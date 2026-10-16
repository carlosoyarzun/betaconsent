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
//
// LEGAL DECISION (F-PR6-25, no la decide este codigo ni ningun modelo): que se comunica al titular cuando se agotan los reintentos; si basta la alerta como registro de la voluntad expresada en R1r-R3r (donde no queda
// ninguna fila); y si el plazo P-19 hasta R9 es aceptable tras una confirmacion fallida. Este modulo solo lanza el error uniforme; el handler HTTP no inventa texto para el titular.
//
// Sin PII: el log y la alerta llevan solo codigo de motivo, ref opaca y hora.

export const APPLY_ALERT_REASONS = ["R4_RETRIES_EXHAUSTED", "R4_BACKUP_APPLIED", "R4_BACKUP_FAILED"] as const;
export type ApplyAlertReason = (typeof APPLY_ALERT_REASONS)[number];

/** Error uniforme de agotamiento (o de Revocation CONFIRMED sin APPLIED): el llamador NO emite acuse de exito. Sin detalle. */
export class RevocationApplyUnavailableError extends Error {
  readonly code = "REVOCATION_APPLY_UNAVAILABLE";
  constructor() {
    super("REVOCATION_APPLY_UNAVAILABLE");
    this.name = "RevocationApplyUnavailableError";
  }
}

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
  readonly alert: ApplyAlertSink;
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

export interface BoundedApplyContext {
  readonly tenantId: string;
  /** Ref de la Revocation de ESTA solicitud, si ya se conoce (R3: la de la sesion; R1r-R3r: la existente o la generada para el intento). Puede completarse durante el intento. */
  readonly revocationRef: () => string | undefined;
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
  for (let n = 1; n <= config.maxAttempts; n += 1) {
    try {
      return await attempt();
    } catch (error) {
      if (!config.isTransient(error)) throw error;
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
  throw new RevocationApplyUnavailableError();
}
