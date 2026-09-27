// Gobierna: SEC-CNS-013 (propuesta re-evaluada, scratchpad/sec-cns-013/propuesta-4c.md sección
// "tests"), specs/state-machines/{revocation,rights-case,tenant-context}.spec.yaml,
// specs/test-framework.spec.yaml (capa unit).
//
// Estos son los casos de SEC-CNS-013 verificables HOY sobre las specs YAML (sin src/): confirman
// que las correcciones de guards/actor que propuso SEC-CNS-013 están efectivamente en el spec
// vigente. No prueban comportamiento en runtime (eso requiere src/, ver
// traceability/test-matrix.csv filas PLANNED de esta misma tanda).
import test from "node:test";
import assert from "node:assert/strict";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadSpecs, type SpecFile } from "../../../tools/spec-checks/h01-sm-checker.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const SPEC_DIR = resolve(REPO_ROOT, "specs", "state-machines");

function spec(specs: SpecFile[], name: string): Record<string, unknown> {
  const s = specs.find((x) => x.name === name);
  if (!s) throw new Error(`spec no encontrada: ${name}`);
  return s.data as Record<string, unknown>;
}

function transitionsOf(data: Record<string, unknown>): Array<Record<string, unknown>> {
  const submachines = data.submachines as Array<Record<string, unknown>> | undefined;
  if (submachines && submachines.length > 0) {
    return submachines.flatMap((m) => (m.transitions as Array<Record<string, unknown>> | undefined) ?? []);
  }
  return (data.transitions as Array<Record<string, unknown>> | undefined) ?? [];
}

function findTransition(data: Record<string, unknown>, id: string): Record<string, unknown> {
  const t = transitionsOf(data).find((x) => x.id === id);
  if (!t) throw new Error(`transición no encontrada: ${id}`);
  return t;
}

test("TEST-CNS-452 SEC-CNS-013: RH3 (revocation) lleva GRD-CM-06/07 en guards y ERR-RV-20 en errors", () => {
  const specs = loadSpecs(SPEC_DIR);
  const rh3 = findTransition(spec(specs, "revocation"), "RH3");
  const guards = rh3.guards as string[];
  assert.ok(guards.includes("GRD-CM-06"), `RH3.guards no incluye GRD-CM-06: ${guards}`);
  assert.ok(guards.includes("GRD-CM-07"), `RH3.guards no incluye GRD-CM-07: ${guards}`);
  const errors = rh3.errors as string[];
  assert.ok(errors.includes("ERR-RV-20"), `RH3.errors no incluye ERR-RV-20: ${errors}`);
});

test("TEST-CNS-453 SEC-CNS-013: TN1/TN2/SP1-4 (tenant-context) con fuente FIXTURE y guardsBySource ⊇ {GRD-CM-14, GRD-CM-15}", () => {
  const specs = loadSpecs(SPEC_DIR);
  const tc = spec(specs, "tenant-context");
  for (const id of ["TN1", "TN2", "SP1", "SP2", "SP3", "SP4"]) {
    const t = findTransition(tc, id);
    const gbs = t.guardsBySource as Record<string, string[]> | undefined;
    assert.ok(gbs, `${id} sin guardsBySource`);
    const fixture = gbs?.FIXTURE ?? [];
    assert.ok(fixture.includes("GRD-CM-14"), `${id} guardsBySource.FIXTURE no incluye GRD-CM-14: ${fixture}`);
    assert.ok(fixture.includes("GRD-CM-15"), `${id} guardsBySource.FIXTURE no incluye GRD-CM-15: ${fixture}`);
  }
});

test("TEST-CNS-454 SEC-CNS-013 (F-CT-10): RC2u (rights-case) es un POST con CSRF (GRD-CM-10) y actor {ref: UNVERIFIED_BEARER}", () => {
  const specs = loadSpecs(SPEC_DIR);
  const rc2u = findTransition(spec(specs, "rights-case"), "RC2u");
  assert.equal(rc2u.httpPost, true);
  const guards = rc2u.guards as string[];
  assert.ok(guards.includes("GRD-CM-10"), `RC2u.guards no incluye GRD-CM-10: ${guards}`);
  assert.deepEqual(rc2u.actor, {
    ref: "UNVERIFIED_BEARER",
    note: (rc2u.actor as Record<string, unknown>).note,
  });
});

test("TEST-CNS-455 SEC-CNS-013 N-4c-01: RV0 (revocation) declara guardsBySource {BEARER, SYSTEM} y la fuente SYSTEM lleva GRD-CM-15", () => {
  const specs = loadSpecs(SPEC_DIR);
  const rv0 = findTransition(spec(specs, "revocation"), "RV0");
  const gbs = rv0.guardsBySource as Record<string, string[]>;
  assert.ok(gbs.BEARER, "RV0.guardsBySource sin fuente BEARER");
  assert.ok(gbs.SYSTEM, "RV0.guardsBySource sin fuente SYSTEM");
  assert.ok(gbs.SYSTEM.includes("GRD-CM-15"), `RV0.guardsBySource.SYSTEM no incluye GRD-CM-15: ${gbs.SYSTEM}`);
  const hps = rv0.httpPostBySource as Record<string, boolean>;
  assert.equal(hps.BEARER, true);
  assert.equal(hps.SYSTEM, false);
});

test("TEST-CNS-456 SEC-CNS-013 N-4c-02: RC2 (rights-case, fuente SYSTEM) lleva GRD-CM-15 en guards", () => {
  const specs = loadSpecs(SPEC_DIR);
  const rc2 = findTransition(spec(specs, "rights-case"), "RC2");
  assert.equal(rc2.httpPost, false);
  const guards = rc2.guards as string[];
  assert.ok(guards.includes("GRD-CM-15"), `RC2.guards no incluye GRD-CM-15: ${guards}`);
});

test("TEST-CNS-457 SEC-CNS-013 N-4c-03: RC1 (rights-case, fuente BEARER) lleva GRD-CM-07 en guardsBySource.BEARER", () => {
  const specs = loadSpecs(SPEC_DIR);
  const rc1 = findTransition(spec(specs, "rights-case"), "RC1");
  const gbs = rc1.guardsBySource as Record<string, string[]>;
  const bearer = gbs.BEARER ?? [];
  assert.ok(bearer.includes("GRD-CM-07"), `RC1.guardsBySource.BEARER no incluye GRD-CM-07: ${bearer}`);
});
