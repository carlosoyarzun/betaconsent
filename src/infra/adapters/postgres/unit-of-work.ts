// Gobierna: CA-124 (H09), ADR-002, ADR-006 §1/§4-§6, common.spec.yaml (INV-CM-01, INV-CM-02),
// TEST-CNS-741/742 (propuestos TEST-CNS-711/712 en el diseño de CA-124).
//
// Unidad de trabajo por tenant sobre PostgreSQL: BEGIN + `set_config('app.tenant_id', $1,
// true)` como PRIMER statement (solo local a la transacción; nunca sesión), trabajo, COMMIT.
// Error: ROLLBACK. Si el ROLLBACK falla, la conexión se destruye (release(true)). Reintenta
// 40001/40P01 hasta 3 intentos: `work` debe ser reejecutable (sin efectos fuera de la tx).
//
// El dominio nunca importa este archivo (ADR-001 §11): solo conoce UnitOfWorkPort. PgUnitOfWork lo
// implementa (CA-124 PR-C): `inTenant` entrega TenantTxPorts completos (revocationRepo,
// consentDecisionRepo, recoveryTokenRepo, ledger, outbox) sobre la MISMA transacción;
// `withTenantTx` entrega la tx cruda para adaptadores y tests de infraestructura.
//
// Este es el ÚNICO archivo de src/** autorizado a invocar set_config('app.tenant_id', ...);
// tests/unit/postgres/tenant-context-scan.test.ts lo hace cumplir.

import type { QueryResult } from "pg";
import type { TenantTxPorts, UnitOfWorkPort } from "../../../server/ports/unit-of-work.port.ts";
import { createPgConsentDecisionRepository } from "./consent-decision.adapter.ts";
import { createPgEnrollmentRepository, ENROLLMENT_SINGLE_ACTIVE_UNIQUE } from "./enrollment.adapter.ts";
import { createPgInvitationRepository, INVITATION_SINGLE_NON_TERMINAL_UNIQUE } from "./invitation.adapter.ts";
import { createPgLedgerAdapter } from "./ledger.adapter.ts";
import { createPgOtpVerificationRepository, OTP_SINGLE_ACTIVE_UNIQUE } from "./otp-verification.adapter.ts";
import { createPgOutboxAdapter } from "./outbox.adapter.ts";
import { acquireCleanClient } from "./pool.ts";
import type { PoolLike } from "./pool.ts";
import { createPgRecoveryTokenRepository } from "./recovery-token.adapter.ts";
import { createPgRevocationRepository, OPEN_REVOCATION_UNIQUE } from "./revocation.adapter.ts";
import { createPgRightsCaseRepository, RIGHTS_CASE_SINGLE_OPEN_UNIQUE } from "./rights-case.adapter.ts";
import { DomainError } from "../../../server/modules/common/errors.ts";
import type { DomainErrorCode } from "../../../server/modules/common/errors.ts";
import { LedgerSequenceConflictError } from "../../../server/ports/ledger.port.ts";

export interface TenantTx {
  query<R = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<QueryResult<R>>;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RETRYABLE_SQLSTATES = new Set(["40001", "40P01"]);

export interface UnitOfWorkOptions {
  maxAttempts?: number;
}

/**
 * Carreras de "una sola crea, las demas se adjuntan" que la base resuelve con un UNIQUE parcial
 * (GRD-RV-04, GRD-IV-01, GRD-OT-08, GRD-RC-02, GRD-TC-03). El perdedor reejecuta `work` en una tx
 * nueva: ahora ve a la ganadora (la adjunta, devuelve el challenge/caso activo, o falla con el
 * error de dominio del guard). Es un reintento de dominio, no un error. Si los reintentos se
 * agotan, el valor es el DomainError con que se rinde (null = se relanza el 23505 crudo).
 */
const RACE_CONSTRAINTS: ReadonlyMap<string, DomainErrorCode | null> = new Map([
  [OPEN_REVOCATION_UNIQUE, "ERR-CM-06"],
  [INVITATION_SINGLE_NON_TERMINAL_UNIQUE, "ERR-IV-02"],
  [ENROLLMENT_SINGLE_ACTIVE_UNIQUE, "ERR-TC-03"],
  [OTP_SINGLE_ACTIVE_UNIQUE, null],
  [RIGHTS_CASE_SINGLE_OPEN_UNIQUE, null],
]);

function raceConstraint(error: unknown): string | undefined {
  const e = error as { code?: unknown; constraint?: unknown };
  return e?.code === "23505" && typeof e.constraint === "string" && RACE_CONSTRAINTS.has(e.constraint) ? e.constraint : undefined;
}

/** SEC-CNS-015 P2-E: la secuencia base se captura ANTES del lock; si otra unidad avanzo el agregado
 * entre la captura y el append, el ledger lanza LedgerSequenceConflictError con la tx entera sin
 * confirmar. Reejecutar la unidad (relee base y estado) es seguro y es lo que evita perder el
 * intento (p.ej. un intento OTP erroneo concurrente). */
function isSequenceConflict(error: unknown): boolean {
  return error instanceof LedgerSequenceConflictError;
}

function sqlState(error: unknown): string | undefined {
  if (typeof error === "object" && error !== null && "code" in error) {
    const code = (error as { code: unknown }).code;
    return typeof code === "string" ? code : undefined;
  }
  return undefined;
}

/** Puertos del tenant ligados a UNA transacción abierta (todos escriben en la misma tx). */
export function createPgTenantTxPorts(tx: TenantTx): TenantTxPorts {
  return {
    revocationRepo: createPgRevocationRepository(tx),
    consentDecisionRepo: createPgConsentDecisionRepository(tx),
    recoveryTokenRepo: createPgRecoveryTokenRepository(tx),
    invitationRepo: createPgInvitationRepository(tx),
    otpRepo: createPgOtpVerificationRepository(tx),
    rightsCaseRepo: createPgRightsCaseRepository(tx),
    enrollmentRepo: createPgEnrollmentRepository(tx),
    ledger: createPgLedgerAdapter(tx),
    outbox: createPgOutboxAdapter(tx),
  };
}

export class PgUnitOfWork implements UnitOfWorkPort {
  private readonly pool: PoolLike;
  private readonly maxAttempts: number;

  constructor(pool: PoolLike, options: UnitOfWorkOptions = {}) {
    this.pool = pool;
    this.maxAttempts = options.maxAttempts ?? 3;
  }

  inTenant<T>(tenantId: string, work: (tx: TenantTxPorts) => Promise<T>): Promise<T> {
    return this.withTenantTx(tenantId, (tx) => work(createPgTenantTxPorts(tx))).catch((error: unknown) => {
      // Reintentos agotados sobre una carrera de UNIQUE parcial: el error de dominio del guard
      // (revocacion abierta -> transicion invalida, invitacion activa, enrollment activo), sin
      // codigos nuevos. withTenantTx (infraestructura) propaga el 23505 crudo.
      const constraint = raceConstraint(error);
      const code = constraint === undefined ? null : (RACE_CONSTRAINTS.get(constraint) ?? null);
      if (code !== null) throw new DomainError(code);
      throw error;
    });
  }

  /** Igual que `inTenant` pero con la transacción cruda (infraestructura y tests; el dominio no la ve). */
  async withTenantTx<T>(tenantId: string, work: (tx: TenantTx) => Promise<T>): Promise<T> {
    if (!UUID_RE.test(tenantId)) {
      throw new TypeError("tenantId debe ser un UUID.");
    }
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.runOnce(tenantId, work);
      } catch (error) {
        const state = sqlState(error);
        const retryable =
          (state !== undefined && RETRYABLE_SQLSTATES.has(state)) || raceConstraint(error) !== undefined || isSequenceConflict(error);
        if (retryable && attempt < this.maxAttempts) continue;
        throw error;
      }
    }
  }

  private async runOnce<T>(tenantId: string, work: (tx: TenantTx) => Promise<T>): Promise<T> {
    const client = await acquireCleanClient(this.pool);
    let destroy = false;
    let open = true;
    const tx: TenantTx = {
      query: (text, values) => {
        if (!open) return Promise.reject(new Error("La transacción de tenant ya terminó."));
        return client.query(text, values);
      },
    };
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      const result = await work(tx);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {
        destroy = true; // ROLLBACK o conexión rota: no se devuelve al pool (P1-1)
      }
      throw error;
    } finally {
      open = false;
      client.release(destroy);
    }
  }
}
