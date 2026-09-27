// Gobierna: specs/state-machines/common.spec.yaml (actorModel, tenancy, ledgerEnvelope).
// Tipos compartidos del dominio IT0. Cero PII, solo refs opacas (UUIDv4 en producción real;
// strings sintéticos en IT0). Sin imports de SDK de proveedor (ADR-001 §11).

/** tenant_id es la única clave de aislamiento (DEC-BR-015 §1; INV-CM-02). Nunca organization_*. */
export type TenantId = string;

/** Referencia opaca a una cadena de decisión (chainRef), resuelta siempre en servidor. */
export type ChainRef = string;

export type ActorType = "HUMAN" | "SYSTEM_GUARD" | "FIXTURE";

export type ActorRole =
  | "DECISION_MAKER"
  | "INVITER"
  | "CONTEXT_OWNER"
  | "PLATFORM_ADMIN"
  | "RIGHTS_OPERATOR"
  | "UNVERIFIED_BEARER";

/** ADR-002 §2: PRODUCTION NOT PROVISIONED en IT0; CI corre como LOCAL (OPEN-CM-07). */
export type Environment = "LOCAL" | "DEV" | "STAGING" | "PRODUCTION";

/**
 * GRD-CM-15 (source_from_execution_identity): la fuente de una transición se deriva de la
 * identidad de ejecución (rol de DB de la conexión + entrypoint del proceso), nunca de un
 * campo de la request. BEARER/STAFF = entrypoint web con app_rw; PLATFORM = consola PLATFORM
 * con platform_rw; SYSTEM = rol worker; FIXTURE = rol de seed del bootstrap LOCAL (GRD-CM-14).
 */
export type ExecutionSource = "BEARER" | "STAFF" | "PLATFORM" | "SYSTEM" | "FIXTURE";

/**
 * Identidad de ejecución que el entrypoint construye del lado servidor (conexión de DB +
 * proceso), nunca de datos enviados por el cliente. Es lo único de lo que un guard puede
 * derivar `source`; ninguna función de dominio acepta `source` como parámetro del llamador.
 */
export interface ExecutionContext {
  readonly source: ExecutionSource;
  readonly environment: Environment;
  /** Ref opaca del principal autenticado en la sesión del servidor (nunca PII). */
  readonly sessionPrincipalRef?: string;
}

export const UNVERIFIED_BEARER_ACTOR = {
  actorType: "HUMAN" as const,
  actorRole: "UNVERIFIED_BEARER" as const,
};
