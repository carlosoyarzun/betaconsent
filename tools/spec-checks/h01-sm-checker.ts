// Gobierna: JIRA CA-116 (H01), specs/state-machines/*.spec.yaml, specs/test-framework.spec.yaml.
// Checker de consistencia de las máquinas de estado IT0. Puerto a TypeScript (sin dependencias
// nuevas, ADR-001 §5) del checker original h01_sm_check.py (scratchpad, Python + PyYAML), adaptado al
// estado actual (rev. 4c/4d/4e) de las specs y a specs/test-framework.spec.yaml (sin parser YAML en
// la allowlist: usa tools/spec-checks/yaml-lite.ts).
//
// Alcance implementado (ver README.md de este directorio para el detalle regla por regla y lo NO
// portado del original):
//   - existencia de guards/errors/eventos referenciados (guards, guardsBySource, guardsByScope,
//     errors, emits, onFail)
//   - httpPost declarado en toda transición; POST exige GRD-CM-10 (CSRF); una fuente sin POST
//     (guardsBySource) nunca lo exige
//   - coherencia guardsBySource / httpPostBySource / fuentes del actor (bySource, byReasonCode.source)
//   - fuente sin POST (SYSTEM/FIXTURE/MIGRATION deshabilitada) nunca lleva guards de handle/credencial
//     (HANDLE_OR_POST_GUARDS) y siempre deriva la fuente por identidad de ejecución (GRD-CM-15)
//   - FIXTURE siempre con guardsBySource ⊇ {GRD-CM-14, GRD-CM-15} (R14-F)
//   - actor.ref solo puede ser UNVERIFIED_BEARER (la única referencia declarada en common.spec.yaml)
//   - from/to de toda transición referencian estados existentes de la unidad (máquina/submáquina)
//   - exactamente un estado inicial y al menos un estado terminal por unidad (salvo
//     noTerminalStates/partial)
//   - guard/error definidos y nunca referenciados (drift)
//   - errors ⊇ onFail(guards) para guards no-GRD-CM-*, con lista de excepciones conocidas
//     (known-onfail-exceptions.ts, OPEN-RV-12): fail-closed para huecos NUEVOS
//   - forbiddenKeys de tenancy.forbiddenKeys (organization_*, etc.) ausentes del texto crudo
//   - RC2u (rights-case) con actor {ref: UNVERIFIED_BEARER} (F-CT-10)
//   - formato y rango (100-499) de TEST-CNS-### en testIds
//   - escaneo de PII (email, RUT) en el texto crudo de las specs
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parseYaml, type YamlValue } from "./yaml-lite.ts";
import { isKnownOnFailGap } from "./known-onfail-exceptions.ts";

export const SPEC_ORDER = [
  "common",
  "invitation",
  "otp-challenge",
  "consent-decision",
  "revocation",
  "rights-case",
  "tenant-context",
] as const;

type Rec = Record<string, YamlValue>;

function asRec(v: YamlValue | undefined): Rec {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : {};
}
function asArr(v: YamlValue | undefined): YamlValue[] {
  return Array.isArray(v) ? v : [];
}
function asStr(v: YamlValue | undefined): string | null {
  return typeof v === "string" ? v : null;
}

const HANDLE_OR_POST_GUARDS = new Set(["GRD-CM-01", "GRD-CM-10", "GRD-RC-14", "GRD-RV-06", "GRD-RV-18", "GRD-RV-20"]);
const SOURCE_IDENTITY_GUARD = "GRD-CM-15";
const FIXTURE_SEED_GUARD = "GRD-CM-14";
const TEST_ID_RE = /^TEST-CNS-(\d{3})$/;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const RUT_RE = /\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b/;

export interface SpecFile {
  name: string;
  data: Rec;
  rawText: string;
}

export function loadSpecs(specDir: string): SpecFile[] {
  const files = readdirSync(specDir).filter((f) => f.endsWith(".spec.yaml"));
  const known = new Set(SPEC_ORDER.map((n) => `${n}.spec.yaml`));
  const extra = files.filter((f) => !known.has(f));
  if (extra.length > 0) {
    throw new Error(`h01-sm-checker: specs no esperadas en ${specDir}: ${extra.join(", ")}`);
  }
  return SPEC_ORDER.map((name) => {
    const rawText = readFileSync(join(specDir, `${name}.spec.yaml`), "utf-8");
    const data = asRec(parseYaml(rawText));
    return { name, data, rawText };
  });
}

interface Unit {
  unitName: string;
  fileName: string;
  data: Rec;
}

function units(fileName: string, data: Rec): Unit[] {
  const sub = data.submachines;
  if (Array.isArray(sub) && sub.length > 0) {
    return sub.map((m) => {
      const mm = asRec(m);
      return { unitName: `${fileName}.${asStr(mm.machine) ?? "?"}`, fileName, data: mm };
    });
  }
  return [{ unitName: fileName, fileName, data }];
}

interface Transition {
  unit: string;
  id: string;
  data: Rec;
}

function guardSetsOf(t: Rec): { scope: string; guards: string[] }[] {
  const out: { scope: string; guards: string[] }[] = [{ scope: "guards", guards: asArr(t.guards).map(String) }];
  const byScope = asRec(t.guardsByScope);
  for (const [k, v] of Object.entries(byScope)) out.push({ scope: `byScope:${k}`, guards: asArr(v).map(String) });
  const bySource = asRec(t.guardsBySource);
  for (const [k, v] of Object.entries(bySource)) out.push({ scope: `bySource:${k}`, guards: asArr(v).map(String) });
  return out;
}

// Fuentes declaradas por actor.bySource o actor.byReasonCode[*].source; null si no aplica;
// "MISSING" si hay tipos mixtos sin fuente declarada explícitamente.
function actorSources(actor: YamlValue | undefined): Set<string> | "MISSING" | null {
  const a = asRec(actor);
  if (Object.keys(a).length === 0) return null;
  const bySource = a.bySource;
  if (bySource && typeof bySource === "object" && !Array.isArray(bySource)) {
    // Una fuente deshabilitada (enabled: false, p. ej. MIGRATION en tenant-context: "migración
    // revisada" sin decidir, DECISION CARLOS pendiente) no tiene guards que evaluar todavía; no
    // se exige guardsBySource para ella (mismo tratamiento que "enabled: false" en transiciones).
    const keys = Object.keys(bySource as Rec).filter((k) => asRec((bySource as Rec)[k]).enabled !== false);
    return new Set(keys);
  }
  const byReasonCode = a.byReasonCode;
  if (byReasonCode && typeof byReasonCode === "object" && !Array.isArray(byReasonCode)) {
    const vals = Object.values(byReasonCode as Rec).map((v) => asRec(v));
    const srcs = new Set(vals.map((v) => asStr(v.source)).filter((x): x is string => x !== null));
    const hasMissing = vals.some((v) => asStr(v.source) === null);
    if (hasMissing) {
      const actorTypes = new Set(vals.map((v) => asStr(v.actorType)));
      return actorTypes.size > 1 ? "MISSING" : null;
    }
    return srcs;
  }
  return null;
}

// Igualdad "por valor" de escalares o listas de escalares (para from/to, que pueden ser un id
// suelto o una lista de ids: SM-CNS-001 permite "self-loop de conjunto", p. ej. M3 [GRANTED,
// DECLINED] -> [GRANTED, DECLINED]).
function sameValue(a: YamlValue | undefined, b: YamlValue | undefined): boolean {
  const al = Array.isArray(a) ? a : [a];
  const bl = Array.isArray(b) ? b : [b];
  if (al.length !== bl.length) return false;
  return al.every((v, i) => String(v) === String(bl[i]));
}

function refsIn(actor: YamlValue | undefined, out: string[] = []): string[] {
  const a = asRec(actor);
  for (const [k, v] of Object.entries(a)) {
    if (k === "ref" && typeof v === "string") out.push(v);
    else if (v && typeof v === "object" && !Array.isArray(v)) refsIn(v as Rec, out);
  }
  return out;
}

export interface CheckResult {
  errors: string[];
  stats: Record<string, Record<string, number>>;
}

export function checkSpecs(specs: SpecFile[]): CheckResult {
  const errors: string[] = [];
  const err = (m: string): void => {
    errors.push(m);
  };
  const stats: Record<string, Record<string, number>> = {};

  const guardDefs = new Map<string, { file: string; onFail: string | null }>();
  const errorIds = new Map<string, string>();
  const eventIds = new Map<string, string>();
  const allTransitions: Transition[] = [];
  const usedGuards = new Set<string>();
  const usedErrors = new Set<string>();
  // globalErrors (common.spec.yaml:156-158: ERR-CM-06, ERR-CM-12) aplican a TODA transición de TODA
  // spec ("el checker los cuenta como usados"); una transición no necesita listarlos en su propio
  // `errors` para que un onFail(guard) = ERR-CM-06/ERR-CM-12 cuente como cubierto (SEC-CNS-014 C1).
  const globalErrorIds = new Set<string>();

  for (const { name, data } of specs) {
    if (asStr(data.status) !== "PROPOSED") err(`${name}: status != PROPOSED`);
    for (const k of ["specId", "smId", "version", "governedBy", "owner"]) {
      if (!data[k]) err(`${name}: metadata sin ${k}`);
    }
    for (const g of asArr(data.guards)) {
      const gg = asRec(g);
      const id = asStr(gg.id);
      if (!id) continue;
      if (guardDefs.has(id)) err(`ID global duplicado guard ${id} (${guardDefs.get(id)!.file} y ${name})`);
      guardDefs.set(id, { file: name, onFail: asStr(gg.onFail) });
    }
    for (const e of asArr(data.errors)) {
      const ee = asRec(e);
      const id = asStr(ee.id);
      if (!id) continue;
      if (errorIds.has(id)) err(`ID global duplicado error ${id} (${errorIds.get(id)} y ${name})`);
      errorIds.set(id, name);
    }
    for (const ev of asArr(data.events)) {
      const ee = asRec(ev);
      const id = asStr(ee.id);
      if (!id) continue;
      if (eventIds.has(id)) err(`ID global duplicado event ${id} (${eventIds.get(id)} y ${name})`);
      eventIds.set(id, name);
    }
    for (const g of asArr(data.startupChecks)) usedGuards.add(String(g));
    for (const e of asArr(data.globalErrors)) {
      usedErrors.add(String(e));
      globalErrorIds.add(String(e));
    }
  }

  for (const { name, data } of specs) {
    const c: Record<string, number> = {};
    for (const u of units(name, data)) {
      const states = asArr(u.data.states).map(asRec);
      const stateIds = new Set(states.map((s) => asStr(s.id)).filter((x): x is string => x !== null));
      const partial = Boolean(u.data.partial);
      if (states.length > 0 && !partial) {
        const initialCount = states.filter((s) => s.initial === true).length;
        if (initialCount !== 1) err(`${u.unitName}: debe haber exactamente 1 estado inicial (hay ${initialCount})`);
        const hasTerminal = states.some((s) => s.terminal === true);
        if (!hasTerminal && !u.data.noTerminalStates) err(`${u.unitName}: sin estados terminales`);
      }
      c.state = (c.state ?? 0) + states.length;
      const terminalIds = new Set(states.filter((s) => s.terminal === true).map((s) => asStr(s.id)));

      // flags: (rights-case, revocation) referencian guards por fuera de transitions (p. ej.
      // FLAG-overdue -> GRD-RC-11); cuentan como "usados" igual que en h01_sm_check.py.
      const flags = asArr(u.data.flags).map(asRec);
      c.flag = (c.flag ?? 0) + flags.length;
      for (const fl of flags) {
        if (fl.guard) usedGuards.add(String(fl.guard));
      }

      const transitions = asArr(u.data.transitions).map(asRec);
      c.transition = (c.transition ?? 0) + transitions.length;
      for (const t of transitions) {
        const tid = asStr(t.id) ?? "?";
        allTransitions.push({ unit: u.unitName, id: tid, data: t });

        const gb = t.governedBy;
        if (!gb || asArr(gb).length === 0) err(`${u.unitName}: transition ${tid} sin governedBy`);
        const testIds = asArr(t.testIds).map(String);
        if (testIds.length === 0) err(`${u.unitName}: transition ${tid} sin testIds`);
        for (const tst of testIds) {
          const m = TEST_ID_RE.exec(tst);
          if (!m) err(`${u.unitName}: transition ${tid} testId mal formado ${tst}`);
          else if (Number(m[1]) < 100 || Number(m[1]) > 499) err(`${u.unitName}: transition ${tid} testId fuera de rango 100-499: ${tst}`);
        }

        // from/to referencian estados existentes; nunca sale de un terminal salvo self-loop
        for (const side of ["from", "to"] as const) {
          const v = t[side];
          const vals = Array.isArray(v) ? v : [v];
          for (const x of vals) {
            if (x !== null && x !== undefined && !stateIds.has(String(x))) {
              err(`${u.unitName}:${tid} ${side} estado inexistente ${String(x)}`);
            }
          }
        }
        {
          const fr = t.from;
          const frl = (Array.isArray(fr) ? fr : [fr]).map((x) => (x === null || x === undefined ? null : String(x)));
          const fromTerminal = frl.filter((x) => x !== null && terminalIds.has(x));
          if (fromTerminal.length > 0 && !sameValue(t.to, t.from)) {
            err(`${u.unitName}:${tid} sale de un estado terminal ${JSON.stringify(fromTerminal)}`);
          }
        }

        if (!("httpPost" in t)) err(`${u.unitName}:${tid} sin httpPost declarado`);
        if (t.enabled === false && !t.disabledReason) err(`${u.unitName}:${tid} enabled:false sin disabledReason`);

        const flat = new Set(asArr(t.guards).map(String));
        const gbs = t.guardsBySource && typeof t.guardsBySource === "object" ? asRec(t.guardsBySource) : null;

        if (t.httpPost === true && !gbs && !flat.has("GRD-CM-10")) err(`${u.unitName}:${tid} httpPost sin GRD-CM-10 (CSRF)`);
        if (t.httpPost === false && flat.has("GRD-CM-10")) err(`${u.unitName}:${tid} httpPost:false con GRD-CM-10 en guards`);

        const srcs = actorSources(t.actor);
        if (srcs === "MISSING") err(`${u.unitName}:${tid} actor con tipos mixtos sin fuente declarada`);
        else if (srcs) {
          const gbsKeys = new Set(Object.keys(gbs ?? {}));
          const eq = gbsKeys.size === srcs.size && [...srcs].every((s) => gbsKeys.has(s));
          if (!eq) err(`${u.unitName}:${tid} fuentes del actor [${[...srcs].sort()}] != guardsBySource [${[...gbsKeys].sort()}]`);
        }

        if (gbs) {
          const hps = asRec(t.httpPostBySource);
          const gbsKeys = new Set(Object.keys(gbs));
          const hpsKeys = new Set(Object.keys(hps));
          const sameKeys = gbsKeys.size === hpsKeys.size && [...gbsKeys].every((k) => hpsKeys.has(k));
          if (!sameKeys) err(`${u.unitName}:${tid} guardsBySource y httpPostBySource con fuentes distintas`);
          const anyTrue = Object.values(hps).some((v) => v === true);
          if (t.httpPost !== anyTrue) err(`${u.unitName}:${tid} httpPost no coincide con httpPostBySource`);
          for (const [src, gl] of Object.entries(gbs)) {
            const eff = new Set([...flat, ...asArr(gl).map(String)]);
            if (hps[src] === true && !eff.has("GRD-CM-10")) err(`${u.unitName}:${tid} fuente ${src} httpPost sin GRD-CM-10 (CSRF)`);
            if (hps[src] === false) {
              const bad = [...eff].filter((g) => HANDLE_OR_POST_GUARDS.has(g)).sort();
              if (bad.length > 0) err(`${u.unitName}:${tid} fuente ${src} sin POST ni credencial con guards de handle/CSRF [${bad}]`);
              if (!eff.has(SOURCE_IDENTITY_GUARD)) {
                err(`${u.unitName}:${tid} fuente ${src} sin POST no deriva la fuente de la identidad de ejecución (${SOURCE_IDENTITY_GUARD}, SEC N3-01)`);
              }
            }
            if (src === "FIXTURE" && (!eff.has(FIXTURE_SEED_GUARD) || !eff.has(SOURCE_IDENTITY_GUARD))) {
              err(`${u.unitName}:${tid} fuente FIXTURE sin guardsBySource ⊇ {${FIXTURE_SEED_GUARD}, ${SOURCE_IDENTITY_GUARD}} (R14-F)`);
            }
          }
        }

        const gsets = guardSetsOf(t);
        const errorsSet = new Set(asArr(t.errors).map(String));
        for (const { scope, guards } of gsets) {
          for (const g of guards) {
            usedGuards.add(g);
            const def = guardDefs.get(g);
            if (!def) {
              err(`${u.unitName}:${tid} guard inexistente ${g} (${scope})`);
              continue;
            }
            if (def.onFail && !errorsSet.has(def.onFail) && !globalErrorIds.has(def.onFail)) {
              if (!isKnownOnFailGap(u.unitName, tid, g)) {
                err(`${u.unitName}:${tid} errors no incluye onFail(${g})=${def.onFail} (${scope}); si es un hueco nuevo, corregir la spec; si es preexistente, no está en known-onfail-exceptions.ts (OPEN-RV-12)`);
              }
            }
          }
        }
        for (const e of asArr(t.errors)) {
          const eid = String(e);
          usedErrors.add(eid);
          if (!errorIds.has(eid)) err(`${u.unitName}:${tid} error inexistente ${eid}`);
        }
        for (const ev of asArr(t.emits)) {
          const evid = String(ev);
          if (!eventIds.has(evid)) err(`${u.unitName}:${tid} evento inexistente ${evid}`);
        }

        for (const r of refsIn(t.actor)) {
          const commonUb = asRec(asRec(asRec(specs.find((s) => s.name === "common")?.data).actorModel).unverifiedBearer);
          const ubId = asStr(commonUb.id);
          if (r && r !== ubId) err(`${u.unitName}:${tid} actor.ref inexistente ${r}`);
        }
      }
    }
    for (const g of asArr(data.guards)) {
      const gg = asRec(g);
      for (const of_ of [gg.onFail, ...Object.values(asRec(gg.onFailByScope))]) {
        if (of_ === null || of_ === undefined) continue;
        usedErrors.add(String(of_));
        if (!errorIds.has(String(of_))) err(`${name}:${asStr(gg.id)} onFail inexistente ${String(of_)}`);
      }
    }
    stats[name] = c;
  }

  for (const [g, def] of guardDefs) {
    if (!usedGuards.has(g)) err(`guard definido y no usado: ${g} (${def.file})`);
  }
  for (const [e, file] of errorIds) {
    if (!usedErrors.has(e)) err(`error definido y no usado: ${e} (${file})`);
  }
  const emitted = new Set<string>();
  for (const t of allTransitions) for (const ev of asArr(t.data.emits)) emitted.add(String(ev));
  for (const [ev, file] of eventIds) {
    if (!emitted.has(ev)) err(`evento definido y no emitido: ${ev} (${file})`);
  }

  // tenancy.forbiddenKeys (organization_*, organizationRef, billing_subscription*, rbd) ausentes del
  // texto de toda spec que NO sea la propia declaración en common.spec.yaml (DEC-BR-015 §1: tenant_id
  // es la única clave de aislamiento).
  const common = specs.find((s) => s.name === "common");
  const forbidden = asArr(asRec(common?.data.tenancy).forbiddenKeys).map(String);
  for (const { name, rawText } of specs) {
    if (name === "common") continue; // ahí es donde se declara la prohibición; mención legítima
    for (const pattern of forbidden) {
      const literal = pattern.replace(/\*/g, "");
      if (literal && rawText.includes(literal)) {
        err(`${name}: menciona clave prohibida de tenancy '${literal}' (common.spec.yaml tenancy.forbiddenKeys, DEC-BR-015 §1)`);
      }
    }
  }

  // RC2u: actor debe ser {ref: UNVERIFIED_BEARER} (F-CT-10)
  const rightsCase = specs.find((s) => s.name === "rights-case");
  if (rightsCase) {
    const rc2u = asArr(rightsCase.data.transitions).map(asRec).find((t) => asStr(t.id) === "RC2u");
    if (!rc2u) err(`rights-case: transición RC2u no encontrada`);
    else if (asStr(asRec(rc2u.actor).ref) !== "UNVERIFIED_BEARER") {
      err(`rights-case:RC2u actor debe ser {ref: UNVERIFIED_BEARER} (F-CT-10), es ${JSON.stringify(rc2u.actor)}`);
    }
  }

  // PII scan
  for (const { name, rawText } of specs) {
    const email = EMAIL_RE.exec(rawText);
    if (email) err(`${name}: posible PII (email): ${email[0]}`);
    const rut = RUT_RE.exec(rawText);
    if (rut) err(`${name}: posible PII (RUT): ${rut[0]}`);
  }

  return { errors, stats };
}

export { units as internalUnitsForTest, guardSetsOf as internalGuardSetsOfForTest, actorSources as internalActorSourcesForTest };
