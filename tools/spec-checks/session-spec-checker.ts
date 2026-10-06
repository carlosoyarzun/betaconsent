// Gobierna: JIRA CA-140, specs/session.spec.yaml (SPEC-CNS-SESSION). Checker de la spec de sesiones STAFF/CASE:
// parsea con yaml-lite (sin dependencias) y valida estructura, unicidad de IDs, que todo testId exista en
// traceability/test-matrix.csv (y que su archivo exista), y que todo guard/invariante tenga tests o una nota explicita.
// Funcion pura: recibe los textos; el llamador lee los archivos.
import { parseYaml, type YamlValue } from "./yaml-lite.ts";

type Rec = Record<string, YamlValue>;
const asRec = (v: YamlValue | undefined): Rec => (v && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : {});
const asArr = (v: YamlValue | undefined): YamlValue[] => (Array.isArray(v) ? v : []);
const asStr = (v: YamlValue | undefined): string | null => (typeof v === "string" ? v : null);

const TEST_ID_RE = /^TEST-CNS-\d{3,4}$/;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

export interface MatrixRow { readonly testId: string; readonly file: string }

/** Lee test_id y file de test-matrix.csv (la columna file nunca lleva comas ni comillas). */
export function parseMatrix(csvText: string): MatrixRow[] {
  const rows: MatrixRow[] = [];
  for (const line of csvText.split("\n")) {
    const m = /^(TEST-CNS-\d+),[^,]*,([^,]*),/.exec(line);
    if (m) rows.push({ testId: m[1]!, file: m[2]! });
  }
  return rows;
}

export function checkSessionSpec(specText: string, matrix: readonly MatrixRow[], fileExists: (path: string) => boolean = () => true): string[] {
  const errors: string[] = [];
  const err = (m: string): void => void errors.push(`session.spec: ${m}`);
  let data: Rec;
  try {
    data = asRec(parseYaml(specText));
  } catch (e) {
    return [`session.spec: no parsea: ${(e as Error).message}`];
  }
  if (data.specId !== "SPEC-CNS-SESSION") err("specId debe ser SPEC-CNS-SESSION");
  if (asStr(data.status) === null) err("falta status");
  if (EMAIL_RE.test(specText)) err("contiene algo con forma de correo (cero PII)");
  const byId = new Map(matrix.map((r) => [r.testId, r]));
  const seen = new Set<string>();
  const checkTests = (owner: string, node: Rec, mustHaveTestsOrNote: boolean): void => {
    const ids = asArr(node.testIds);
    if (!Array.isArray(node.testIds)) err(`${owner}: falta testIds (lista, puede ser vacia con testNotes)`);
    for (const t of ids) {
      const id = asStr(t);
      if (id === null || !TEST_ID_RE.test(id)) { err(`${owner}: testId invalido`); continue; }
      const row = byId.get(id);
      if (!row) err(`${owner}: ${id} no existe en traceability/test-matrix.csv`);
      else if (row.file.startsWith("/") || row.file.split("/").includes("..")) err(`${owner}: ${id} ruta no permitida en la matriz (${row.file}); debe ser relativa a la raiz sin '..'`);
      else if (!fileExists(row.file)) err(`${owner}: ${id} apunta a un archivo inexistente (${row.file})`);
    }
    if (mustHaveTestsOrNote && ids.length === 0 && asStr(node.testNotes) === null) err(`${owner}: sin tests ni testNotes (FINDING no declarado)`);
  };
  const guards = asArr(data.guards).map(asRec);
  if (guards.length === 0) err("sin guards");
  for (const g of guards) {
    const id = asStr(g.id) ?? "?";
    if (!/^GRD-SE-\d{2}$/.test(id)) err(`guard ${id}: id debe ser GRD-SE-NN`);
    if (seen.has(id)) err(`guard ${id}: duplicado`);
    seen.add(id);
    for (const k of ["name", "rule", "governedBy"]) if (g[k] === undefined) err(`guard ${id}: falta ${k}`);
    checkTests(`guard ${id}`, g, true);
  }
  for (const i of asArr(data.invariants).map(asRec)) {
    const id = asStr(i.id) ?? "?";
    if (!/^INV-SE-\d{2}$/.test(id)) err(`invariante ${id}: id debe ser INV-SE-NN`);
    if (seen.has(id)) err(`invariante ${id}: duplicado`);
    seen.add(id);
    checkTests(`invariante ${id}`, i, true);
  }
  for (const e of asArr(data.errors).map(asRec)) checkTests(`error ${asStr(e.id) ?? "?"}`, e, false);
  // Toda transicion referencia guards que existen.
  for (const t of asArr(asRec(data.lifecycle).transitions).map(asRec)) {
    for (const g of asArr(t.guards)) if (!seen.has(asStr(g) ?? "")) err(`transicion ${asStr(t.id) ?? "?"}: guard inexistente ${String(g)}`);
  }
  for (const r of asArr(data.residuals).map(asRec)) if (asStr(r.acceptedFor) === null) err(`residual ${asStr(r.id) ?? "?"}: falta acceptedFor`);
  return errors;
}
