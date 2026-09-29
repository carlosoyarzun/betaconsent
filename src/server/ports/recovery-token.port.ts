// Gobierna: specs/state-machines/revocation.spec.yaml RV0 effects ("Crea
// tenant_resolve.recovery_token(token_hash, tenant_id, chain_ref, revoked_decision_ref,
// recovery_ref, expires_at, consumed_at)"), GRD-RV-06 (recovery_token_valid). Puerto (ADR-001
// §11): proyección del token de recuperación de /r/{token}. IT0: adaptador in-memory; el
// adaptador de Postgres llega con la historia de infraestructura. Mismo patrón que
// invitation-repository.port.ts (GRD-IV-05: solo el hash persiste, nunca el token en claro).

import type { ChainRef, TenantId } from "../modules/common/types.ts";

export interface RecoveryTokenRecord {
  /** SHA-256 del token opaco (mismo patrón que InvitationRecord.tokenHash); el token en claro
   * nunca persiste. */
  readonly tokenHash: string;
  /** Ref opaca del token, distinta del token en claro: es la que sí puede viajar en payloads
   * de ledger (recoveryRef, DEC-BR-017 §6) sin revelar el secreto. */
  readonly recoveryRef: string;
  readonly tenantId: TenantId;
  readonly chainRef: ChainRef;
  /** SEC N2-04 / R14-C: decisión GRANTED vigente de la cadena al emitir (GRD-RV-02); un token
   * ligado a la decisión de un ciclo anterior no es vigente para el ciclo nuevo (GRD-RV-06). */
  readonly revokedDecisionRef: string;
  /** P-15 (SEC-CNS-006, sin valor aprobado: ver recovery-token-policy.config.ts). */
  readonly expiresAt: Date;
  /** Un solo uso (GRD-RV-06, GRD-RV-23): una vez consumido, cualquier otro uso es ERR-RV-05. */
  readonly consumedAt?: Date;
}

export interface RecoveryTokenRepositoryPort {
  /** GRD-RV-06: resuelve por tokenHash (igualdad exacta), nunca por el token en claro. */
  findByTokenHash(tokenHash: string): Promise<RecoveryTokenRecord | null>;
  save(record: RecoveryTokenRecord): Promise<void>;
  /** Marca el token como consumido (un solo uso); no-op si el tokenHash no existe. */
  consume(tokenHash: string): Promise<void>;
}
