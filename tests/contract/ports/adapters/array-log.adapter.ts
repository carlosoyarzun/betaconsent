// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), ADR-001 §11 regla (4).
// Adaptador de ejemplo #2 de ExampleCounterPort: implementación deliberadamente
// distinta (guarda un log de incrementos en vez de un contador) para demostrar que la
// suite de contrato es agnóstica a la implementación mientras cumpla el puerto.

import type { ExampleCounterPort } from "../example-port.ts";

export function createArrayLogCounterAdapter(): ExampleCounterPort {
  const log: number[] = [];
  return {
    async increment() {
      log.push(1);
      return log.length;
    },
    async get() {
      return log.length;
    },
    async reset() {
      log.length = 0;
    },
  };
}
