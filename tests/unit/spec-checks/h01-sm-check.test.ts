// Gobierna: JIRA CA-116 (H01/F-015), specs/test-framework.spec.yaml (capa unit: funciones puras,
// sin I/O externo; leer specs/state-machines/*.spec.yaml del propio repo es fixture local, no I/O de
// red/DB). Prueba tools/spec-checks/h01-sm-checker.ts: (1) PASS sobre el estado real de
// specs/state-machines/ y (2) mutaciones negativas (deep-clone en memoria; nunca se escribe en el
// repo) que confirman que el checker detecta cada clase de violación.
import test from "node:test";
import assert from "node:assert/strict";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { checkSpecs, loadSpecs, type SpecFile } from "../../../tools/spec-checks/h01-sm-checker.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const SPEC_DIR = resolve(REPO_ROOT, "specs", "state-machines");

function clone(specs: SpecFile[]): SpecFile[] {
  return specs.map((s) => ({ ...s, data: JSON.parse(JSON.stringify(s.data)) }));
}

function spec(specs: SpecFile[], name: string): SpecFile {
  const s = specs.find((x) => x.name === name);
  if (!s) throw new Error(`spec no encontrada: ${name}`);
  return s;
}

// Encuentra una transición por (fileName, id), buscando también dentro de submachines
// (tenant-context), igual que el `tr()` del checker original en Python.
function tr(specs: SpecFile[], fileName: string, id: string): Record<string, unknown> {
  const data = spec(specs, fileName).data as Record<string, unknown>;
  const submachines = data.submachines as Array<Record<string, unknown>> | undefined;
  const machines = submachines && submachines.length > 0 ? submachines : [data];
  for (const m of machines) {
    const transitions = (m.transitions as Array<Record<string, unknown>> | undefined) ?? [];
    const found = transitions.find((t) => t.id === id);
    if (found) return found;
  }
  throw new Error(`transición no encontrada: ${fileName}:${id}`);
}

test("TEST-CNS-906 h01-sm-check: PASS sobre specs/state-machines/ (estado real del repo)", () => {
  const specs = loadSpecs(SPEC_DIR);
  const { errors } = checkSpecs(specs);
  assert.deepEqual(errors, []);
});

test("TEST-CNS-906 h01-sm-check: guard inexistente en una transición", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  (tr(specs, "invitation", "I1").guards as string[]).push("GRD-XX-01");
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("guard inexistente GRD-XX-01")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: onFail nuevo sin error en la transición (hueco NUEVO, no en known-onfail-exceptions)", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  // GRD-IV-02 (onFail ERR-CM-01) no es un guard GRD-CM-*, así que sí lo exige el checker; I1 no
  // tiene ERR-CM-01 en su lista de errors y esta combinación no está en known-onfail-exceptions.ts.
  const i1 = tr(specs, "invitation", "I1");
  i1.errors = (i1.errors as string[]).filter((e) => e !== "ERR-CM-01");
  const { errors } = checkSpecs(specs);
  assert.ok(
    errors.some((e) => e.includes("errors no incluye onFail(GRD-IV-02)=ERR-CM-01")),
    errors.join("\n"),
  );
});

test("TEST-CNS-906 h01-sm-check: GET que transiciona (httpPost:false con GRD-CM-10 en guards)", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  const r5 = tr(specs, "revocation", "R5");
  assert.equal(r5.httpPost, false);
  (r5.guards as string[]).push("GRD-CM-10");
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("R5 httpPost:false con GRD-CM-10 en guards")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: POST sin CSRF (httpPost:true sin GRD-CM-10)", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  const r8 = tr(specs, "revocation", "R8");
  assert.equal(r8.httpPost, true);
  r8.guards = (r8.guards as string[]).filter((g) => g !== "GRD-CM-10");
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("R8 httpPost sin GRD-CM-10")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: guard definido y no usado", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  (spec(specs, "common").data.guards as Array<Record<string, unknown>>).push({
    id: "GRD-CM-99",
    onFail: null,
    governedBy: ["x"],
    testIds: ["TEST-CNS-100"],
  });
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("guard definido y no usado: GRD-CM-99")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: error definido y no usado", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  (spec(specs, "common").data.errors as Array<Record<string, unknown>>).push({
    id: "ERR-CM-99",
    governedBy: ["x"],
    testIds: ["TEST-CNS-100"],
  });
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("error definido y no usado: ERR-CM-99")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: evento definido y no emitido", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  (spec(specs, "invitation").data.events as Array<Record<string, unknown>>).push({
    id: "ORPHAN_EVENT",
    emittedBy: [],
    governedBy: ["x"],
    testIds: ["TEST-CNS-120"],
  });
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("evento definido y no emitido: ORPHAN_EVENT")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: estado inexistente en 'to'", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  tr(specs, "consent-decision", "C3").to = "NOWHERE";
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("to estado inexistente NOWHERE")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: actor.ref inexistente", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  tr(specs, "invitation", "I4").actor = { ref: "GHOST" };
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("actor.ref inexistente GHOST")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: RC1 fuente SYSTEM sin GRD-CM-15 (SEC N3-01)", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  const rc1 = tr(specs, "rights-case", "RC1");
  const gbs = rc1.guardsBySource as Record<string, string[]>;
  gbs.SYSTEM = (gbs.SYSTEM ?? []).filter((g) => g !== "GRD-CM-15");
  const { errors } = checkSpecs(specs);
  assert.ok(
    errors.some((e) => e.includes("fuente SYSTEM sin POST no deriva la fuente de la identidad de ejecución")),
    errors.join("\n"),
  );
});

test("TEST-CNS-906 h01-sm-check: fuente sin POST con guard de handle/CSRF (SEC N2-01)", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  const rc1 = tr(specs, "rights-case", "RC1");
  const gbs = rc1.guardsBySource as Record<string, string[]>;
  (gbs.SYSTEM ?? (gbs.SYSTEM = [])).push("GRD-CM-10");
  const { errors } = checkSpecs(specs);
  assert.ok(
    errors.some((e) => e.includes("fuente SYSTEM sin POST ni credencial con guards de handle/CSRF")),
    errors.join("\n"),
  );
});

test("TEST-CNS-906 h01-sm-check: RC2u deja de ser actor UNVERIFIED_BEARER (F-CT-10)", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  tr(specs, "rights-case", "RC2u").actor = { actorType: "SYSTEM_GUARD" };
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("rights-case:RC2u actor debe ser {ref: UNVERIFIED_BEARER}")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: FIXTURE sin GRD-CM-14 (R14-F)", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  const tn1 = tr(specs, "tenant-context", "TN1");
  const gbs = tn1.guardsBySource as Record<string, string[]>;
  gbs.FIXTURE = (gbs.FIXTURE ?? []).filter((g) => g !== "GRD-CM-14");
  const { errors } = checkSpecs(specs);
  assert.ok(
    errors.some((e) => e.includes("fuente FIXTURE sin guardsBySource")),
    errors.join("\n"),
  );
});

test("TEST-CNS-906 h01-sm-check: clave prohibida de tenancy (organization_id) fuera de common", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  const invitation = spec(specs, "invitation");
  invitation.rawText += "\n# organization_id filtrado por error\n";
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("menciona clave prohibida de tenancy")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: PII (email) en el texto crudo de una spec", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  const common = spec(specs, "common");
  common.rawText += "\n# prueba: persona@correo-real.cl\n";
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("posible PII (email)")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: testId fuera de rango 100-499", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  (tr(specs, "invitation", "I2").testIds as string[]).push("TEST-CNS-905");
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("fuera de rango 100-499")), errors.join("\n"));
});

test("TEST-CNS-906 h01-sm-check: dos estados iniciales", () => {
  const specs = clone(loadSpecs(SPEC_DIR));
  const states = spec(specs, "revocation").data.states as Array<Record<string, unknown>>;
  const target = states[1];
  if (!target) throw new Error("fixture inválido: revocation.states[1] no existe");
  target.initial = true;
  const { errors } = checkSpecs(specs);
  assert.ok(errors.some((e) => e.includes("debe haber exactamente 1 estado inicial")), errors.join("\n"));
});
