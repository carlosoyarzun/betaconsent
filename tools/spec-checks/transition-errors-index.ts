// Gobierna: OPEN-RV-12, SEC-CNS-013; specs/state-machines/*.spec.yaml (campo `errors` de cada
// transición). TEST-CNS-474: cierra en runtime lo que h01-sm-checker.ts (`errors ⊇
// onFail(guards)`) solo verifica de forma estática sobre la spec. Este módulo expone un índice
// transitionId -> errors[] leído en vivo con yaml-lite (sin parser YAML externo, ADR-001 §5),
// reutilizando el mismo loadSpecs() que usa el checker de gobierno H01 (misma fuente, mismo
// parser, cero duplicación de lectura de YAML).

import { loadSpecs, type SpecFile } from "./h01-sm-checker.ts";
import type { YamlValue } from "./yaml-lite.ts";

function asRec(v: YamlValue | undefined): Record<string, YamlValue> {
  return v !== null && v !== undefined && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, YamlValue>)
    : {};
}
function asArr(v: YamlValue | undefined): YamlValue[] {
  return Array.isArray(v) ? v : [];
}
function asStr(v: YamlValue | undefined): string | null {
  return typeof v === "string" ? v : null;
}

export interface TransitionErrorsIndex {
  /** true si `errorCode` está declarado en errors[] de la transición `transitionId`. Una
   * transición ausente de la spec (fail-closed) nunca permite ningún código. */
  allows(transitionId: string, errorCode: string): boolean;
  errorsOf(transitionId: string): readonly string[];
  /** IDs de transición vistos al cargar (para detectar typos del test contra la spec real). */
  knownTransitionIds(): ReadonlySet<string>;
}

/**
 * Carga todas las specs de `specDir` (rights-case, revocation, common, etc.) y construye el
 * índice transitionId -> errors[] declarado por cada una. IDs de transición son únicos entre
 * specs de máquinas de estado distintas en este repo (RC*, RV*, R*, EN*, ...).
 */
export function loadTransitionErrorsIndex(specDir: string): TransitionErrorsIndex {
  const specs: SpecFile[] = loadSpecs(specDir);
  const byId = new Map<string, string[]>();
  for (const spec of specs) {
    const transitions = asArr(spec.data.transitions).map(asRec);
    for (const t of transitions) {
      const id = asStr(t.id);
      if (!id) continue;
      const errors = asArr(t.errors).filter((e): e is string => typeof e === "string");
      byId.set(id, errors);
    }
  }
  return {
    allows(transitionId, errorCode) {
      const errors = byId.get(transitionId);
      if (errors === undefined) return false;
      return errors.includes(errorCode);
    },
    errorsOf(transitionId) {
      return byId.get(transitionId) ?? [];
    },
    knownTransitionIds() {
      return new Set(byId.keys());
    },
  };
}
