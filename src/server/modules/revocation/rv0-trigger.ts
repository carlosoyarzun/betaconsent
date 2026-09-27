// Gobierna: specs/state-machines/revocation.spec.yaml RV0 (guardsBySource BEARER/SYSTEM),
// specs/state-machines/common.spec.yaml GRD-CM-15 (source_from_execution_identity),
// SEC-CNS-013 N-4c-01. Alcance IT0 de este archivo: solo el guard de fuente de RV0 con
// trigger CASE_CONTACT (TEST-CNS-471); el resto de RV0 (envío real al canal ligado) es una
// historia posterior que depende del adaptador de email-sink.

import { assertExecutionSourceIn } from "../common/guards.ts";
import type { ExecutionContext } from "../common/types.ts";

export type Rv0Trigger = "CASE_CONTACT" | "SCHOOL_REPORTED";

export interface Rv0Result {
  readonly sent: boolean;
}

/**
 * RV0 con trigger=CASE_CONTACT o SCHOOL_REPORTED (rights-case RC2) solo puede dispararse
 * desde la fuente de ejecución SYSTEM (rol worker dentro de la tx de RC2), nunca desde un
 * POST web del portador (BEARER) que declare ese trigger (GRD-CM-15, N-4c-01). La fuente se
 * deriva EXCLUSIVAMENTE de `ctx.source`: esta función no lee ningún campo "source" del
 * cuerpo de la request, así que un POST BEARER no puede simular SYSTEM (TEST-CNS-471).
 */
export function triggerCaseContactNotice(ctx: ExecutionContext, trigger: Rv0Trigger): Rv0Result {
  assertExecutionSourceIn(ctx, ["SYSTEM"]);
  return { sent: true };
}
