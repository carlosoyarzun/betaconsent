// Gobierna: ADR-010 rev. 4 §4.2 (PR-5a), specs/state-machines/revocation.spec.yaml `dbEnforcement` (FN-RV-01..15, INV-RV-12),
// db/migrations/0037_adr010_case_state_revocation.sql; src/server/ports/revocation-transitions.port.ts. ADR-001 §11: solo este adaptador
// conoce el SQL de las funciones `case_state.*` de transition_owner.
//
// Cada metodo llama UNA funcion SECURITY DEFINER dentro de la tx de PgUnitOfWork.inTenant (el tenant sale de app.current_tenant_id(),
// nunca de un parametro). La llamada va en un SAVEPOINT: un rechazo de guard de la base (SQLSTATE RVxxx) deja la tx utilizable, igual que
// los rechazos previos a escribir del dominio. Sin SQL dinamico: un texto SQL literal por funcion.

import { DomainError } from "../../../server/modules/common/errors.ts";
import type { DomainErrorCode } from "../../../server/modules/common/errors.ts";
import { LedgerSequenceConflictError } from "../../../server/ports/ledger.port.ts";
import type { RevocationTransitionsPort, TransitionResult } from "../../../server/ports/revocation-transitions.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

/** SQLSTATE de las funciones case_state -> error de dominio del onFail del spec (0037). RV409 = conflicto de secuencia del ledger. */
const GUARD_SQLSTATES: ReadonlyMap<string, DomainErrorCode> = new Map([
  ["RV001", "ERR-CM-01"],
  ["RV002", "ERR-CM-06"],
  ["RV003", "ERR-RV-02"],
  ["RV004", "ERR-RV-07"],
  ["RV005", "ERR-RV-18"],
  ["RV006", "ERR-RV-20"],
  ["RV007", "ERR-RV-05"],
]);

export function mapTransitionError(error: unknown): unknown {
  const e = error as { code?: unknown; detail?: unknown };
  if (typeof e?.code !== "string") return error;
  const domain = GUARD_SQLSTATES.get(e.code);
  if (domain) return new DomainError(domain);
  if (e.code === "RV409") {
    const m = /expected=(-?\d+) actual=(\d+)/.exec(typeof e.detail === "string" ? e.detail : "");
    return new LedgerSequenceConflictError(m ? Number(m[1]) : -1, m ? Number(m[2]) : -1);
  }
  return error;
}

export function createPgRevocationTransitions(tx: TenantTx): RevocationTransitionsPort {
  async function run<R>(text: string, values: readonly unknown[]): Promise<R> {
    await tx.query("SAVEPOINT revocation_transition");
    try {
      const r = await tx.query<{ r: R }>(text, values);
      await tx.query("RELEASE SAVEPOINT revocation_transition");
      return r.rows[0]?.r as R;
    } catch (error) {
      await tx.query("ROLLBACK TO SAVEPOINT revocation_transition");
      throw mapTransitionError(error);
    }
  }
  const seq = (r: { sequence: number }): TransitionResult => ({ sequence: Number(r.sequence) });

  return {
    async request(i) {
      return seq(await run<{ sequence: number }>("SELECT case_state.request_revocation($1::text, $2::text, $3::text) AS r", [i.revocationRef, i.chainRef, i.revokedDecisionRef]));
    },
    async verifyOtp(i) {
      return seq(await run<{ sequence: number }>("SELECT case_state.verify_revocation_otp($1::text, $2::text, $3::integer) AS r", [i.revocationRef, i.verificationRef, i.expectedSequence]));
    },
    async confirm(i) {
      return seq(await run<{ sequence: number }>("SELECT case_state.confirm_revocation($1::text, $2::integer) AS r", [i.revocationRef, i.expectedSequence]));
    },
    async revokeWithRecoveryLink(i) {
      const r = await run<{ sequence: number; revocationRef: string }>(
        "SELECT case_state.revoke_with_recovery_link($1::text, $2::text, $3::integer) AS r",
        [i.recoveryRef, i.newRevocationRef, i.expectedSequence],
      );
      return { ...seq(r), revocationRef: r.revocationRef };
    },
    async withdraw(i) {
      return seq(await run<{ sequence: number }>("SELECT case_state.withdraw_revocation($1::text, $2::integer) AS r", [i.revocationRef, i.expectedSequence]));
    },
    async expressRevocationIntentInCase(i) {
      return seq(
        await run<{ sequence: number }>(
          "SELECT case_state.express_revocation_intent_in_case($1::text, $2::text, $3::text, $4::text, $5::text, $6::boolean, $7::integer) AS r",
          [i.caseRef, i.chainRef, i.revokedDecisionRef, i.initiatedVia, i.revocationRef, i.attach, i.expectedSequence],
        ),
      );
    },
    async proposeCaseVerification(i) {
      await run<unknown>("SELECT case_state.propose_case_verification($1::text, $2::text, $3::text, $4::text, $5::text) AS r", [
        i.revocationRef,
        i.caseRef,
        i.proposalRef,
        i.proposedByRef,
        i.verificationScriptVersion,
      ]);
    },
    async approveCaseVerification(i) {
      return seq(
        await run<{ sequence: number }>("SELECT case_state.approve_case_verification($1::text, $2::text, $3::text, $4::text, $5::integer) AS r", [
          i.revocationRef,
          i.caseRef,
          i.proposalRef,
          i.approverRef,
          i.expectedSequence,
        ]),
      );
    },
    async withdrawCaseVerificationProposal(i) {
      return seq(
        await run<{ sequence: number }>("SELECT case_state.withdraw_case_verification_proposal($1::text, $2::text, $3::text, $4::text, $5::integer) AS r", [
          i.revocationRef,
          i.caseRef,
          i.proposalRef,
          i.actorRef,
          i.expectedSequence,
        ]),
      );
    },
    async recordCaseConfirmation(i) {
      await run<unknown>("SELECT case_state.record_case_confirmation($1::text, $2::text, $3::text) AS r", [i.revocationRef, i.caseRef, i.recordedByRef]);
    },
    async cosignCaseConfirmation(i) {
      return seq(
        await run<{ sequence: number }>("SELECT case_state.cosign_case_confirmation($1::text, $2::text, $3::text, $4::integer) AS r", [
          i.revocationRef,
          i.caseRef,
          i.cosignedByRef,
          i.expectedSequence,
        ]),
      );
    },
    async apply(i) {
      return seq(await run<{ sequence: number }>("SELECT case_state.apply_revocation($1::text, $2::integer) AS r", [i.revocationRef, i.expectedSequence]));
    },
    async markDownstreamEmitted(i) {
      return seq(
        await run<{ sequence: number }>("SELECT case_state.mark_downstream_emitted($1::text, $2::text[], $3::integer) AS r", [
          i.revocationRef,
          [...i.subscriptionRefs],
          i.expectedSequence,
        ]),
      );
    },
    async recordDownstreamAck(i) {
      return seq(await run<{ sequence: number }>("SELECT case_state.record_downstream_ack($1::text, $2::text, $3::integer) AS r", [i.revocationRef, i.ackRef, i.expectedSequence]));
    },
    async recordErasureAttestation(i) {
      return seq(
        await run<{ sequence: number }>("SELECT case_state.record_erasure_attestation($1::text, $2::text, $3::integer) AS r", [i.revocationRef, i.attestationRef, i.expectedSequence]),
      );
    },
  };
}
