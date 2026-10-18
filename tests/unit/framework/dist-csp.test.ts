// Gobierna: ADR-001 rev. 8 F1 y §3 (build de la SPA sin inline).
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { checkDist } from "../../../tools/guardrails/dist-csp.ts";

const GOOD = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="cns-page-state" content="ready"><title>x</title>
<script type="module" crossorigin src="/assets/index-AAA.js"></script><link rel="stylesheet" crossorigin href="/assets/style-BBB.css"></head><body class="lp-guest-body"><div id="root"></div></body></html>`;
const ASSETS = new Set(["/assets/index-AAA.js", "/assets/style-BBB.css"]);
const ok = (html: string, assets = ASSETS, css: string[] = []) => checkDist({ indexHtml: html, assetPaths: assets, cssContents: css });

describe("dist-csp", () => {
  it("TEST-CNS-1885: acepta un index.html con script y hoja locales con hash", () => assert.deepEqual(ok(GOOD), []));
  it("TEST-CNS-1886: rechaza <style>, style=, on*=, <script> inline y javascript:", () => {
    assert.equal(ok(GOOD.replace("</head>", "<style>a{}</style></head>")).length, 1);
    assert.equal(ok(GOOD.replace('<div id="root">', '<div style="color:red" id="root">')).length, 1);
    assert.equal(ok(GOOD.replace('<div id="root">', '<div onclick="x()" id="root">')).length, 1);
    assert.ok(ok(GOOD.replace("</body>", "<script>alert(1)</script></body>")).some((x) => x.includes("inline")));
    assert.ok(ok(GOOD.replace("</body>", '<a href="javascript:x">a</a></body>')).some((x) => x.includes("javascript:")));
  });
  it("TEST-CNS-1887: rechaza scripts remotos/data: y assets inexistentes", () => {
    assert.ok(ok(GOOD.replace("/assets/index-AAA.js", "https://cdn.example/x.js")).length >= 1);
    assert.ok(ok(GOOD.replace("/assets/index-AAA.js", "data:text/javascript,1")).length >= 1);
    assert.ok(ok(GOOD, new Set(["/assets/style-BBB.css"])).some((x) => x.includes("no existe")));
  });
  it("TEST-CNS-1888: exige el marcador cns-page-state y rechaza @import remoto en CSS", () => {
    assert.ok(ok(GOOD.replace('<meta name="cns-page-state" content="ready">', "")).some((x) => x.includes("cns-page-state")));
    assert.equal(ok(GOOD, ASSETS, ['@import url("https://fonts.example/x.css");']).length, 1);
  });
});
