// Gobierna: ADR-001 rev. 8 F1 (fase A). frontend/ no importa de src/, db/ ni tools/.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { checkFrontendBoundary } from "../../../tools/guardrails/frontend-boundary.ts";

const f = (path: string, content: string) => ({ path, content });

describe("frontend-boundary", () => {
  it("TEST-CNS-1880: acepta imports dentro de frontend/ y paquetes npm", () => {
    const v = checkFrontendBoundary([
      f("frontend/src/pages/welcome.tsx", `import { useState } from "react";\nimport { postJson } from "../api/client.ts";\nexport { x } from "./y.ts";`),
      f("frontend/tests/pages/w.test.tsx", `import { WelcomePage } from "../../src/pages/welcome.tsx";`),
    ]);
    assert.deepEqual(v, []);
  });

  it("TEST-CNS-1881: rechaza import estático, dinámico, require, export-from y side-effect hacia src/ o db/", () => {
    const v = checkFrontendBoundary([
      f("frontend/src/a.ts", `import { x } from "../../src/domain/x.ts";`),
      f("frontend/src/b.ts", `const m = await import("../../db/migrations/0001.sql");`),
      f("frontend/src/c.ts", `const m = require("../../src/y.ts");`),
      f("frontend/src/d.ts", `export * from "../../src/z.ts";`),
      f("frontend/src/e.ts", `import "../../tools/guardrails/x.ts";`),
      f("frontend/src/f.ts", `import type { T } from "../../src/types.ts";`),
    ]);
    assert.equal(v.length, 6);
  });

  it("TEST-CNS-1882: rechaza imports absolutos y @import de CSS fuera de frontend/", () => {
    const v = checkFrontendBoundary([
      f("frontend/src/a.ts", `import x from "/etc/passwd";`),
      f("frontend/src/styles/other.css", `@import "../../../src/server/entrypoints/http/assets/app.css";`),
    ]);
    assert.equal(v.length, 2);
  });

  it("TEST-CNS-1883: permite solo `import type` desde contracts/**", () => {
    assert.deepEqual(checkFrontendBoundary([f("frontend/src/a.ts", `import type { Api } from "../../contracts/types/api.ts";`)]), []);
    assert.equal(checkFrontendBoundary([f("frontend/src/a.ts", `import { Api } from "../../contracts/types/api.ts";`)]).length, 1);
  });

  it("TEST-CNS-1884: las excepciones de CSS son exactas por archivo y destino", () => {
    const css = `@import "../../../design-system/index.css";\n@import "../../../src/server/entrypoints/http/assets/app.css";`;
    assert.deepEqual(checkFrontendBoundary([f("frontend/src/styles/index.css", css)]), []);
    assert.equal(checkFrontendBoundary([f("frontend/src/styles/index.css", `@import "../../../src/server/entrypoints/http/assets/verify.js";`)]).length, 1);
    assert.equal(checkFrontendBoundary([f("frontend/src/styles/otro.css", css)]).length, 2);
  });
});
