// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), ADR-001 §11 regla (4).
// Adaptador de ejemplo #1 de ExampleCounterPort: variable cerrada en closure.

import type { ExampleCounterPort } from "../example-port.ts";

export function createInMemoryCounterAdapter(): ExampleCounterPort {
  let value = 0;
  return {
    async increment() {
      value += 1;
      return value;
    },
    async get() {
      return value;
    },
    async reset() {
      value = 0;
    },
  };
}
