// Gobierna: ADR-010 rev. 4 §4.2 (PR-5b), specs/state-machines/rights-case.spec.yaml `dbEnforcement` (FN-RC-01, FN-RC-02, FN-RC-06, TRG-RC-01,
// INV-RC-07), specs/db-roles.spec.yaml (transition_owner, Q-18). ADR-001 §11: el dominio solo conoce este puerto.
//
// Puerto de escritura de las transiciones del RightsCase. Con un adaptador que lo implementa (Postgres: funciones SECURITY DEFINER de
// `case_state`, dueno transition_owner), la fila de `app.rights_case` y su evento de ledger los escribe LA FUNCION en la misma tx; el dominio
// solo decide (lee, valida, pasa `expectedSequence`) y llama. RC3 (lado rights_case) vive en `RevocationTransitionsPort.expressRevocationIntentInCase`
// (FN-RC-03 = FN-RV-06: una sola funcion para ambos lados del mismo lote). Sin este puerto (adaptador in-memory), el dominio escribe con
// `rightsCaseRepo.save` + `ledger.append` como antes (rutas legacy documentadas en rights-case.ts). Ambos caminos producen los mismos eventos y estados.
//
// `sequence` = ultima sequence del agregado RightsCase tras la llamada. Los errores de guard de la base llegan como DomainError (ERR-CM-01/06,
// ERR-RC-01/02/03/09) y el conflicto de secuencia como LedgerSequenceConflictError, igual que el ledger.

import type { TransitionResult } from "./revocation-transitions.port.ts";

export interface RightsCaseTransitionsPort {
  /** FN-RC-01 RC1 (fuente BEARER). Idempotente por (cadena, decision) (GRD-RC-02): si ya hay un caso no terminal lo devuelve con `created: false`. */
  open(input: {
    readonly caseRef: string;
    readonly chainRef: string;
    readonly revokedDecisionRef: string;
    readonly origin: "LIMIT_REACHED" | "CHANNEL_UNREACHABLE" | "REQUESTER_ASKED";
  }): Promise<TransitionResult & { readonly caseRef: string; readonly created: boolean }>;
  /** FN-RC-02 RC2u (OPEN -> CONTACTING). Con el caso ya en CONTACTING no cambia nada (`changed: false`). */
  confirmReturn(input: { readonly caseRef: string; readonly expectedSequence: number }): Promise<TransitionResult & { readonly changed: boolean }>;
  /** FN-RC-06 RC4.RESOLVED / RC4.WITHDRAWN / RC5 / RC6. */
  close(input: { readonly caseRef: string; readonly outcome: "RESOLVED" | "WITHDRAWN"; readonly operatorRef: string; readonly expectedSequence: number }): Promise<TransitionResult>;
}
