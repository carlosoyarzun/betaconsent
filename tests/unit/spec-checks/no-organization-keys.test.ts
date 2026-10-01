// Gobierna: DEC-BR-015 §1 (tenant = colegio), INV-CM-02 (tenant_id es la unica clave de aislamiento,
// nunca organization_*), contracts/schemas/common.schema.json x-forbidden-keys, DEC-BR-014 X5
// ("guardrail de organization_*"). Escanea src/, db/ y contracts/ (contenido y nombres de archivo):
// ningun identificador organization_* / organizationId / organizationRef usado como codigo o como
// clave estructural (TS/SQL fuera de comentarios; claves/elementos JSON y YAML). La prosa (comentarios,
// "description") que NIEGA la clave ("sin organizationRef") se admite, igual que la lista
// x-forbidden-keys del schema comun. Vive en tests/unit (no en tests/guardrails, CODEOWNERS).
// TEST-CNS-951.

import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SCAN_DIRS = ["src", "db", "contracts"];
const FORBIDDEN = /organization_(?!\*)|organization(Id|Ref)\b/i;
const FORBIDDEN_NAME = /organization/i;
const ALLOWED_LINES: ReadonlyArray<{ file: string; line: RegExp }> = [
  { file: "contracts/schemas/common.schema.json", line: /^\s*"(organization_\*|organizationRef)",?\s*$/ },
];

/** Parte de la linea que cuenta como codigo/clave (la prosa de comentarios y descriptions no). */
function codeOrKeyPart(rel: string, line: string): string {
  if (rel.endsWith(".ts")) return line.replace(/\/\/.*$/, "").replace(/^\s*\*.*$/, "");
  if (rel.endsWith(".sql")) return line.replace(/--.*$/, "");
  if (rel.endsWith(".json") || rel.endsWith(".yaml") || rel.endsWith(".yml")) {
    const m = /^\s*(?:-\s*)?["']?(organization[\w*]*)["']?\s*(?::|,?\s*$)/i.exec(line);
    return m ? (m[1] ?? "") : "";
  }
  return "";
}

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules") continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

test("TEST-CNS-951 guardrail organization_*: ningun identificador organization_/organizationId/organizationRef en src/, db/, contracts/ (salvo la prohibicion literal)", () => {
  const offenders: string[] = [];
  let scanned = 0;
  for (const dir of SCAN_DIRS) {
    for (const file of walk(join(ROOT, dir))) {
      const rel = relative(ROOT, file);
      scanned++;
      if (FORBIDDEN_NAME.test(rel)) offenders.push(`${rel} (nombre de archivo)`);
      const lines = readFileSync(file, "utf8").split("\n");
      lines.forEach((raw, i) => {
        const text = codeOrKeyPart(rel, raw);
        if (!FORBIDDEN.test(text)) return;
        if (ALLOWED_LINES.some((a) => a.file === rel && a.line.test(raw))) return;
        offenders.push(`${rel}:${i + 1}`);
      });
    }
  }
  assert.ok(scanned > 50, `el escaneo debe cubrir archivos reales (cubrio ${scanned})`);
  assert.deepEqual(offenders, []);
});

test("TEST-CNS-951 el patron del guardrail no es vacuo: atrapa organization_id y organizationRef, no la prohibicion literal organization_*", () => {
  for (const bad of ["organization_id uuid", "const organizationId = 1", "x.organizationRef", "ORGANIZATION_ID"]) assert.match(bad, FORBIDDEN);
  assert.doesNotMatch("Nunca organization_*.", FORBIDDEN);
});
