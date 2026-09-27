// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), ADR-001 §11 regla (4).
//
// Suite de contrato reutilizable para ExampleCounterPort (TEST-CNS-902):
// una única definición de casos que se registra, con node:test, contra cada adaptador
// que implemente el puerto. Convención para puertos reales futuros en
// src/server/ports/**: la suite vive junto al puerto (o en tests/contract/ports/) y
// expone una función `run<Puerto>Contract(adapterName, factory)`.

import test from "node:test";
import assert from "node:assert/strict";
import type { ExampleCounterPort } from "./example-port.ts";

export function runExampleCounterPortContract(
  adapterName: string,
  makeAdapter: () => ExampleCounterPort,
): void {
  test(`TEST-CNS-902 ExampleCounterPort contract (${adapterName}): empieza en 0`, async () => {
    const adapter = makeAdapter();
    assert.equal(await adapter.get(), 0);
  });

  test(`TEST-CNS-902 ExampleCounterPort contract (${adapterName}): increment devuelve el nuevo valor`, async () => {
    const adapter = makeAdapter();
    assert.equal(await adapter.increment(), 1);
    assert.equal(await adapter.increment(), 2);
    assert.equal(await adapter.get(), 2);
  });

  test(`TEST-CNS-902 ExampleCounterPort contract (${adapterName}): reset vuelve a 0`, async () => {
    const adapter = makeAdapter();
    await adapter.increment();
    await adapter.reset();
    assert.equal(await adapter.get(), 0);
  });

  test(`TEST-CNS-902 ExampleCounterPort contract (${adapterName}): instancias nuevas no comparten estado`, async () => {
    const a = makeAdapter();
    const b = makeAdapter();
    await a.increment();
    assert.equal(await a.get(), 1);
    assert.equal(await b.get(), 0);
  });
}
