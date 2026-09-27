// Gobierna: JIRA CA-116 (H01/F-015), specs/test-framework.spec.yaml (capa unit). Prueba
// tools/spec-checks/yaml-lite.ts sobre fragmentos representativos de la sintaxis usada en
// specs/state-machines/*.spec.yaml: mapeos/secuencias por indentación, flow [..]/{..} anidado,
// comillas simples/dobles (incluida una cadena entre comillas dobles multi-línea) y comentarios.
import test from "node:test";
import assert from "node:assert/strict";
import { parseYaml } from "../../../tools/spec-checks/yaml-lite.ts";

test("TEST-CNS-906 yaml-lite: mapeo y secuencia por indentación", () => {
  const data = parseYaml(`
specId: SPEC-X
status: PROPOSED
states:
  - id: A
    initial: true
  - id: B
    terminal: true
`) as Record<string, unknown>;
  assert.equal(data.specId, "SPEC-X");
  assert.deepEqual(data.states, [
    { id: "A", initial: true },
    { id: "B", terminal: true },
  ]);
});

test("TEST-CNS-906 yaml-lite: flow list y flow map anidados, con comas dentro de comillas", () => {
  const data = parseYaml(`
guards: [GRD-A, GRD-B, GRD-C] # comentario de cola
item: {id: LD-01, topic: "Uno, dos (tres)", owner: Carlos, blocksDataReal: true}
`) as Record<string, unknown>;
  assert.deepEqual(data.guards, ["GRD-A", "GRD-B", "GRD-C"]);
  assert.deepEqual(data.item, { id: "LD-01", topic: "Uno, dos (tres)", owner: "Carlos", blocksDataReal: true });
});

test("TEST-CNS-906 yaml-lite: guardsBySource anidado bajo actor con bySource", () => {
  const data = parseYaml(`
actor:
  bySource:
    BEARER: {ref: UNVERIFIED_BEARER}
    SYSTEM: {actorType: SYSTEM_GUARD}
guardsBySource:
  BEARER: [GRD-CM-01, GRD-CM-10]
  SYSTEM: [GRD-CM-15]
`) as Record<string, unknown>;
  assert.deepEqual(data.actor, {
    bySource: { BEARER: { ref: "UNVERIFIED_BEARER" }, SYSTEM: { actorType: "SYSTEM_GUARD" } },
  });
  assert.deepEqual(data.guardsBySource, { BEARER: ["GRD-CM-01", "GRD-CM-10"], SYSTEM: ["GRD-CM-15"] });
});

test("TEST-CNS-906 yaml-lite: escalar entre comillas dobles que cruza varias líneas (fold)", () => {
  const data = parseYaml(`
changeNote: "Primera parte de la nota
  segunda parte, con coma, y (paréntesis)
  tercera parte."
next: true
`) as Record<string, unknown>;
  assert.equal(data.changeNote, "Primera parte de la nota segunda parte, con coma, y (paréntesis) tercera parte.");
  assert.equal(data.next, true);
});

test("TEST-CNS-906 yaml-lite: null/true/false/número y bloque folded '>'", () => {
  const data = parseYaml(`
a: null
b: true
c: false
d: 42
e: >
  línea uno
  línea dos
`) as Record<string, unknown>;
  assert.equal(data.a, null);
  assert.equal(data.b, true);
  assert.equal(data.c, false);
  assert.equal(data.d, 42);
  assert.equal(data.e, "línea uno línea dos");
});

test("TEST-CNS-906 yaml-lite: ítem de secuencia como mapeo flow inline ('- {id: X, ...}', legalDecisions/openItems reales)", () => {
  const data = parseYaml(`
legalDecisions:
  - {id: LD-05, topic: "Validez de una revocación (excepción P16)", owner: Carlos, blocksDataReal: true}
  - {id: LD-04, topic: "'suspended' no existe en IT0", owner: Carlos, blocksDataReal: true}
`) as Record<string, unknown>;
  assert.deepEqual(data.legalDecisions, [
    { id: "LD-05", topic: "Validez de una revocación (excepción P16)", owner: "Carlos", blocksDataReal: true },
    { id: "LD-04", topic: "'suspended' no existe en IT0", owner: "Carlos", blocksDataReal: true },
  ]);
});

test("TEST-CNS-906 yaml-lite: ítem de secuencia como lista flow inline ('- [a, b]')", () => {
  const data = parseYaml(`
groups:
  - [GRD-A, GRD-B]
  - [GRD-C]
`) as Record<string, unknown>;
  assert.deepEqual(data.groups, [["GRD-A", "GRD-B"], ["GRD-C"]]);
});

test("TEST-CNS-906 yaml-lite (SEC-CNS-014 P2c, fail-closed): lista flow sin ']' de cierre lanza error", () => {
  assert.throws(() => parseYaml("guards: [GRD-A, GRD-B\n"), /sin '\]' de cierre/);
});

test("TEST-CNS-906 yaml-lite (SEC-CNS-014 P2c, fail-closed): mapeo flow sin '}' de cierre lanza error", () => {
  assert.throws(() => parseYaml("item: {id: LD-05, owner: Carlos\n"), /sin '\}' de cierre/);
});

test("TEST-CNS-906 yaml-lite (SEC-CNS-014 P2c, fail-closed): texto sobrante tras el cierre de un flow lanza error", () => {
  assert.throws(() => parseYaml("guards: [GRD-A, GRD-B] basura\n"), /texto sobrante tras el valor flow/);
});

test("TEST-CNS-906 yaml-lite (SEC-CNS-014 P2d, fail-closed): clave duplicada en un mapeo flow lanza error", () => {
  assert.throws(() => parseYaml("item: {id: LD-05, id: LD-06}\n"), /clave duplicada "id"/);
});

test("TEST-CNS-906 yaml-lite (SEC-CNS-014 P2d, fail-closed): clave duplicada en un mapeo por indentación lanza error", () => {
  assert.throws(
    () =>
      parseYaml(`
a: 1
b: 2
a: 3
`),
    /clave duplicada "a"/,
  );
});

test("TEST-CNS-906 yaml-lite (SEC-CNS-014 P2d, fail-closed): clave duplicada en un ítem de secuencia inline lanza error", () => {
  assert.throws(
    () =>
      parseYaml(`
states:
  - id: A
    id: B
`),
    /clave duplicada "id"/,
  );
});

test("TEST-CNS-906 yaml-lite (SEC-CNS-014 P2a, fail-closed): línea top-level sin consumir al terminar el documento lanza error", () => {
  assert.throws(
    () =>
      parseYaml(`
a: 1
  b: 2
`),
    /sin consumir al terminar el documento/,
  );
});
