// Gobierna: DEC-BR-014 rev. 8 §3 X8 (decision 4 de Carlos, 2026-10-06), specs/test-framework.spec.yaml (matriz de tests).
// Checker minimo de trazabilidad: valida que todo TEST-CNS citado en las matrices de maquinas de estado y en
// traceability/requirements-trace-matrix.csv exista en traceability/test-matrix.csv con archivo real dentro del
// repo (sin rutas absolutas ni '..'), que no haya IDs duplicados inconsistentes, que toda fila UNCOVERED tenga motivo
// y que todo hueco GRD/INV/ERR/API/REQ/RULE sin test este en traceability/x8-exceptions.csv.
// Funcion pura: recibe los textos; el llamador lee los archivos. No usa tools/guardrails.

/** Parser CSV minimo (RFC 4180: comillas dobles, "" escapa). Devuelve filas con cabecera como claves. */
export function parseCsv(text: string): Array<Record<string, string>> {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inQ) {
      if (c === '"') {
        if (text[i + 1] === '"') { cell += '"'; i++; } else inQ = false;
      } else cell += c;
    } else if (c === '"') inQ = true;
    else if (c === ",") { row.push(cell); cell = ""; }
    else if (c === "\n") { row.push(cell); rows.push(row); row = []; cell = ""; }
    else if (c !== "\r") cell += c;
  }
  if (cell !== "" || row.length > 0) { row.push(cell); rows.push(row); }
  const header = rows.shift() ?? [];
  return rows.filter((r) => r.some((x) => x !== "")).map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] ?? ""])));
}

export interface TraceabilityInputs {
  readonly testMatrix: string;
  readonly smMatrix: string;
  readonly smGuards: string;
  readonly reqMatrix: string;
  readonly exceptions: string;
  /** Texto de las specs (specs/state-machines/*.yaml y specs/session.spec.yaml), para el universo de GRD/INV/ERR. */
  readonly specTexts: readonly string[];
  readonly fileExists: (path: string) => boolean;
}

const TEST_ID_RE = /^TEST-CNS-\d{3,4}$/;
const NORM_ID_RE = /^(GRD|INV|ERR)-[A-Z]{2}-\d+$|^INV-\d+$/;
const escRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const cites = (text: string, id: string): boolean => new RegExp(`(?<![A-Za-z0-9_-])${escRe(id)}(?![A-Za-z0-9_])`).test(text);

function badPath(p: string): boolean {
  return p.startsWith("/") || /^[A-Za-z]:/.test(p) || p.split("/").includes("..") || p.includes("\\");
}

export function checkTraceability(inp: TraceabilityInputs): string[] {
  const errors: string[] = [];
  const err = (m: string): void => void errors.push(m);

  // 1. test-matrix.csv: rutas, duplicados inconsistentes.
  const tm = parseCsv(inp.testMatrix);
  const real = new Map<string, { file: string; status: string }>();
  const layerOf = new Map<string, string>();
  const statusOf = new Map<string, string>();
  const seenRow = new Set<string>();
  for (const r of tm) {
    const id = r.test_id ?? "";
    if (!TEST_ID_RE.test(id)) { err(`test-matrix: test_id invalido (${id})`); continue; }
    const rowKey = `${id}|${r.file}|${r.test_name}`;
    if (seenRow.has(rowKey)) err(`test-matrix: fila duplicada ${id} (${r.file})`);
    seenRow.add(rowKey);
    const lk = `${id}|${r.file}`;
    if (layerOf.has(lk) && layerOf.get(lk) !== r.layer) err(`test-matrix: ${id} en ${r.file} con capas distintas`);
    layerOf.set(lk, r.layer ?? "");
    if (statusOf.has(id) && statusOf.get(id) !== r.status) err(`test-matrix: ${id} con estados inconsistentes (${statusOf.get(id)} vs ${r.status})`);
    statusOf.set(id, r.status ?? "");
    if (r.status === "PLANNED") { real.set(id, { file: r.file ?? "", status: "PLANNED" }); continue; }
    if (badPath(r.file ?? "")) err(`test-matrix: ${id} ruta no permitida (${r.file}); debe ser relativa a la raiz sin '..'`);
    else if (!inp.fileExists(r.file ?? "")) err(`test-matrix: ${id} apunta a un archivo inexistente (${r.file})`);
    real.set(id, { file: r.file ?? "", status: r.status ?? "" });
  }
  const checkIds = (owner: string, cell: string): boolean => {
    let ok = true;
    for (const id of cell.split(";").map((x) => x.trim()).filter((x) => x !== "")) {
      const t = real.get(id);
      if (!TEST_ID_RE.test(id)) { err(`${owner}: id de test invalido (${id})`); ok = false; }
      else if (!t) { err(`${owner}: ${id} no existe en traceability/test-matrix.csv`); ok = false; }
      else if (t.status === "PLANNED") { err(`${owner}: ${id} esta PLANNED (sin archivo); no puede cubrir`); ok = false; }
    }
    return ok;
  };

  // 2. Matrices de maquinas de estado.
  const sm = parseCsv(inp.smMatrix);
  const gd = parseCsv(inp.smGuards);
  const mappedIds = new Set<string>();
  const checkSm = (name: string, rows: Array<Record<string, string>>, idOf: (r: Record<string, string>) => string, idsOf: (r: Record<string, string>) => string[]): void => {
    for (const r of rows) {
      const owner = `${name} ${r.machine}/${idOf(r)}`;
      const cell = r.test_id ?? "";
      if (cell.trim() === "") { err(`${owner}: test_id vacio (use UNCOVERED con motivo)`); continue; }
      if (cell.trim() === "UNCOVERED") {
        if ((r.uncovered_reason ?? "").trim() === "") err(`${owner}: UNCOVERED sin uncovered_reason`);
        continue;
      }
      if (cell.includes("UNCOVERED")) err(`${owner}: UNCOVERED mezclado con IDs`);
      else if (checkIds(owner, cell)) for (const i of idsOf(r)) mappedIds.add(i);
    }
  };
  checkSm("state-machine-matrix", sm, (r) => r.element_id ?? "?", (r) => [r.element_id ?? ""]);
  checkSm("transition-guards", gd, (r) => `${r.transition_id}/${r.guard_id}`, (r) => [r.guard_id ?? ""]);

  // 3. Matriz REQ/RULE/UX/SEC/API.
  const rq = parseCsv(inp.reqMatrix);
  const seenNorm = new Set<string>();
  const reqUncovered: Array<{ id: string; type: string }> = [];
  for (const r of rq) {
    const id = r.norm_id ?? "";
    if (seenNorm.has(id)) err(`requirements-trace-matrix: ${id} duplicado`);
    seenNorm.add(id);
    checkIds(`requirements-trace-matrix ${id}`, r.test_ids ?? "");
    for (const col of ["spec", "contract", "evidence"] as const) {
      for (const ref of (r[col] ?? "").split(";").filter((x) => x !== "")) {
        const path = ref.split("#")[0]!;
        if (badPath(path)) err(`requirements-trace-matrix ${id}: ruta no permitida en ${col} (${path})`);
        else if (!inp.fileExists(path)) err(`requirements-trace-matrix ${id}: ${col} apunta a archivo inexistente (${path})`);
      }
    }
    for (const m of (r.code_module ?? "").split(";").filter((x) => x !== "")) {
      if (badPath(m)) err(`requirements-trace-matrix ${id}: ruta no permitida en code_module (${m})`);
      else if (!inp.fileExists(m)) err(`requirements-trace-matrix ${id}: code_module inexistente (${m})`);
    }
    if (["API", "REQ", "RULE"].includes(r.norm_type ?? "") && (r.test_ids ?? "").trim() === "") reqUncovered.push({ id, type: r.norm_type ?? "" });
  }

  // 4. Huecos vs archivo de excepciones.
  const tmText = tm.map((r) => `${r.test_name} ${r.governed_by}`).join(" ");
  const universe = new Set<string>();
  for (const t of inp.specTexts) for (const line of t.split("\n")) {
    const m = /^\s*(?:-\s*)?(?:id|code|name|guardId):\s*"?((?:GRD|INV|ERR)-[A-Z]{2}-\d+)/.exec(line);
    if (m) universe.add(m[1]!);
  }
  for (const r of sm) if (NORM_ID_RE.test(r.element_id ?? "")) universe.add(r.element_id!);
  for (const r of gd) if (NORM_ID_RE.test(r.guard_id ?? "")) universe.add(r.guard_id!);
  const holes = new Set<string>();
  for (const id of universe) if (!mappedIds.has(id) && !cites(tmText, id)) holes.add(id);
  for (const h of reqUncovered) holes.add(h.id);
  const exc = parseCsv(inp.exceptions);
  const excIds = new Set<string>();
  for (const r of exc) {
    const id = r.id ?? "";
    if (excIds.has(id)) err(`x8-exceptions: ${id} duplicado`);
    excIds.add(id);
    if ((r.reason ?? "").trim() === "") err(`x8-exceptions: ${id} sin reason`);
    if (!holes.has(id)) err(`x8-exceptions: ${id} figura como excepcion pero ya tiene test (o no existe); retirar la fila`);
  }
  for (const h of [...holes].sort()) if (!excIds.has(h)) err(`hueco sin test y sin excepcion: ${h} (agregar a traceability/x8-exceptions.csv)`);
  return errors;
}
