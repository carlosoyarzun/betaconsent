// Gobierna: ADR-010 rev. 5 (enmienda rev. c, aceptada por Carlos el 2026-10-15) §5.2 pasos 5-7, §6, §10 fila PR-6c; specs/db-roles.spec.yaml (platform_rw: open_platform_session,
// open_case_session, validate_session, revoke_session); db/migrations/0052-0054; ADR-001 §11 (puerto: el dominio no conoce Postgres).
//
// Sesiones PLATFORM y CASE de operador (equipo de LectorPro), proceso `platform`. La BASE genera el sid (256 bits aprox.), solo persiste su sha256 y toma el principal de la asercion LOGIN
// consumida en la MISMA transaccion que crea la sesion (nunca de la request). El sid viaja solo en una cookie `__Host-` HttpOnly Secure SameSite=Strict. Cero PII: refs opacas y hashes.
// Un DENY de la base devuelve null/false (la evidencia y la asercion consumida ya estan confirmadas); un error de base lanza PlatformDeniedError uniforme.

export type SessionKind = "PLATFORM" | "CASE";

/** Vida de la sesion por configuracion del proceso (sin default fuera de LOCAL); la base solo acota rangos (techos de 8 h y 30 min). */
export interface SessionLifetime {
  readonly absoluteSeconds: number;
  readonly idleSeconds: number;
}

export interface ValidatedSession {
  readonly sessionRef: string;
  readonly kind: SessionKind;
  /** Principal de la FILA de la sesion (UUIDv4); es la clave de P-50. */
  readonly principalRef: string;
  /** Solo CASE. */
  readonly caseRef: string | null;
}

export interface PlatformSessionPort {
  /** Consume la asercion LOGIN_PLATFORM (exchangeRef de la cookie + state) y abre la sesion; `previousSid` rota (revoca) la sesion previa del navegador. null = DENY. */
  openPlatformSession(input: { exchangeRef: string; state: string; lifetime: SessionLifetime; previousSid?: string | null }): Promise<string | null>;
  /** Consume la asercion LOGIN_CASE ligada a `caseRef` y abre la sesion CASE colgada de la sesion PLATFORM `platformSid`. null = DENY. */
  openCaseSession(input: { exchangeRef: string; state: string; caseRef: string; platformSid: string; lifetime: SessionLifetime; previousCaseSid?: string | null }): Promise<string | null>;
  /** Valida y avanza la actividad; revalida rol, grant y sesion PLATFORM en cada llamada. null ante cualquier fallo. */
  validate(input: { sid: string; kind: SessionKind }): Promise<ValidatedSession | null>;
  /** Logout en servidor (idempotente). true si revoco. */
  revoke(input: { sid: string; kind: SessionKind }): Promise<boolean>;
}
