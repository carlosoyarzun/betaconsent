// Gobierna: F-PR6-25 (hallazgos F-PR6-51 y F-PR6-52), UX-CNS-015, DEC-BR-006 / REQ-CNS-033 (sin
// acuse ni recibo), RULE-CNS-026. TEST-CNS-1767..1765.
// Ejecuta revocation.js / recovery.js reales contra un DOM mínimo construido con los ids del HTML
// que renderizan revocation-page.ts / recovery-page.ts (sin jsdom: dependencia no permitida).

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

import { renderRevocationConfirmPage } from "../../../src/server/entrypoints/http/revocation-page.ts";
import { renderRecoveryConfirmPage } from "../../../src/server/entrypoints/http/recovery-page.ts";
import { REVOCATION_APPLY_FAILED_COPY as COPY_A, RECOVERY_APPLY_FAILED_COPY as COPY_B } from "../../../src/server/entrypoints/http/revocation-apply-failed-copy.ts";

const ASSETS = new URL("../../../src/server/entrypoints/http/assets/", import.meta.url);

class FakeEl {
  hidden: boolean;
  textContent = "";
  dataset: Record<string, string> = {};
  readonly listeners: Record<string, Array<() => void>> = {};
  readonly id: string;
  readonly doc: FakeDoc;
  constructor(id: string, hidden: boolean, doc: FakeDoc) { this.id = id; this.hidden = hidden; this.doc = doc; }
  readonly attrs: Record<string, string> = {};
  setAttribute(k: string, v: string): void { this.attrs[k] = v; }
  addEventListener(type: string, fn: () => void): void { (this.listeners[type] ??= []).push(fn); }
  focus(): void { this.doc.focused = this.id; }
  click(): void { for (const fn of this.listeners.click ?? []) fn(); }
}
class FakeDoc {
  focused: string | null = null;
  cookie = "";
  readonly els = new Map<string, FakeEl>();
  private ready: Array<() => void> = [];
  constructor(html: string) {
    for (const m of html.matchAll(/<(\w+)([^>]*?)\sid="([^"]+)"([^>]*)>/g)) {
      const attrs = `${m[2]} ${m[4]}`;
      this.els.set(m[3]!, new FakeEl(m[3]!, /\shidden(\s|$)/.test(attrs), this));
    }
  }
  getElementById(id: string): FakeEl | null { return this.els.get(id) ?? null; }
  addEventListener(_t: string, fn: () => void): void { this.ready.push(fn); }
  fire(): void { for (const fn of this.ready) fn(); }
}

async function settle(): Promise<void> { for (let i = 0; i < 20; i += 1) await new Promise((r) => setImmediate(r)); }

function boot(asset: string, html: string, respond: (url: string) => { status: number; body?: unknown }): FakeDoc {
  const doc = new FakeDoc(html);
  const fetchStub = (url: string): Promise<unknown> => {
    const r = respond(url);
    return Promise.resolve({ status: r.status, json: () => Promise.resolve(r.body ?? {}) });
  };
  vm.runInNewContext(readFileSync(new URL(asset, ASSETS), "utf8"), { document: doc, fetch: fetchStub, decodeURIComponent, JSON });
  doc.fire();
  return doc;
}

const UNAVAILABLE = { code: "GUARD_EVALUATOR_UNAVAILABLE", status: 503, correlationId: "00000000-0000-4000-8000-000000000000" };
const NO_ACK = /registrad|recibid|en proceso|en curso|te avisaremos|revocad|cancelad|denegad/i;

test("TEST-CNS-1767: revocation-page.ts renderiza el aviso A con el copy literal (UX-CNS-015), role=alert, oculto, foco programático, ícono + código ERR-RV-21 en texto y sin afirmar registro ni proceso", () => {
  const html = renderRevocationConfirmPage();
  assert.match(html, /<div role="alert" aria-live="assertive" class="lp-alert-error" id="error-apply-failed" tabindex="-1" hidden>/);
  assert.ok(html.includes("No pudimos completar tu retiro</span>"));
  assert.ok(html.includes(COPY_A.body));
  assert.match(html, /<p id="apply-failed-code">Código: ERR-RV-21<\/p>/);
  assert.match(html, /<a href="\/manage" [^>]*id="new-code-link">Empezar de nuevo<\/a>/);
  assert.match(html, /<a href="mailto:ayuda@example\.invalid" class="lp-link" id="apply-failed-help">Escribir al equipo del estudio<\/a>/);
  assert.match(html, /class="lp-alert-icon" aria-hidden="true"/); // no depende del color
  for (const text of [COPY_A.title, COPY_A.body, COPY_B.title, COPY_B.body]) assert.doesNotMatch(text, NO_ACK);
  const src = readFileSync(new URL("../../../src/server/entrypoints/http/revocation-apply-failed-copy.ts", import.meta.url), "utf8");
  assert.match(src, /INTERINO y NO LEGAL/);
  assert.match(src, /F-PR6-25/);
  assert.match(src, /REQ-CNS-033/);
});

test("TEST-CNS-1768: revocation.js ante 503 de /confirm muestra el aviso A (no el uniforme ni el comprobante), con foco, sin ocultar el formulario", async () => {
  const doc = boot("revocation.js", renderRevocationConfirmPage(), (url) => (url.endsWith("/confirm") ? { status: 503, body: UNAVAILABLE } : { status: 200 }));
  doc.getElementById("confirm-revocation-btn")!.click();
  await settle();
  assert.equal(doc.getElementById("error-apply-failed")!.hidden, false);
  assert.equal(doc.focused, "error-apply-failed");
  assert.equal(doc.getElementById("error-uniform")!.hidden, true);
  assert.equal(doc.getElementById("state-applied")!.hidden, true);
  assert.equal(doc.getElementById("revocation-form")!.hidden, false);
});

test("TEST-CNS-1769: revocation.js con 503 sin cuerpo JSON también muestra el aviso A; con 200 + revocationRef sigue mostrando el comprobante y oculta el aviso", async () => {
  let calls = 0;
  const doc = boot("revocation.js", renderRevocationConfirmPage(), (url) => {
    if (!url.endsWith("/confirm")) return { status: 200 };
    calls += 1;
    return calls === 1 ? { status: 503, body: "no-es-objeto" } : { status: 200, body: { revocationRef: "ref-opaca", status: "APPLIED" } };
  });
  doc.getElementById("confirm-revocation-btn")!.click();
  await settle();
  assert.equal(doc.getElementById("error-apply-failed")!.hidden, false);
  doc.getElementById("confirm-revocation-btn")!.click();
  await settle();
  assert.equal(calls, 2);
  assert.equal(doc.getElementById("error-apply-failed")!.hidden, true);
  assert.equal(doc.getElementById("state-applied")!.hidden, false);
});

test("TEST-CNS-1770: revocation.js con 404 sigue mostrando el texto uniforme actual (sin aviso A)", async () => {
  const html = renderRevocationConfirmPage();
  assert.match(html, /El enlace puede no ser válido o haber expirado\./);
  const doc = boot("revocation.js", html, (url) => (url.endsWith("/confirm") ? { status: 404 } : { status: 200 }));
  doc.getElementById("confirm-revocation-btn")!.click();
  await settle();
  assert.equal(doc.getElementById("error-uniform")!.hidden, false);
  assert.equal(doc.getElementById("error-apply-failed")!.hidden, true);
});

test("TEST-CNS-1771: recovery.js distingue el 503 (aviso B: enlace aún válido, ERR-RV-22, foco) del 404/202 (texto uniforme actual: token inválido o expirado)", async () => {
  const html = renderRecoveryConfirmPage();
  assert.match(html, /id="error-uniform" hidden>\s*<p>No pudimos continuar con este retiro\.<\/p>\s*<p>El enlace puede no ser válido o haber expirado\./);
  assert.match(html, /<div role="alert" aria-live="assertive" class="lp-alert-error" id="error-apply-failed" tabindex="-1" hidden>/);
  assert.match(html, /class="lp-alert-icon" aria-hidden="true"/);
  assert.ok(html.includes(COPY_B.title));
  assert.ok(html.includes(COPY_B.body));
  assert.match(html, /<p id="apply-failed-code">Código: ERR-RV-22<\/p>/);
  assert.match(html, /id="retry-apply-btn">Volver a intentar<\/button>/);
  assert.match(COPY_B.body, /Tu enlace sigue siendo válido/);
  assert.doesNotMatch(COPY_B.body, /haber expirado|no sea válido/);

  const internal = boot("recovery.js", html, () => ({ status: 503, body: UNAVAILABLE }));
  internal.getElementById("confirm-recovery-btn")!.click();
  await settle();
  assert.equal(internal.getElementById("error-apply-failed")!.hidden, false);
  assert.equal(internal.focused, "error-apply-failed");
  assert.equal(internal.getElementById("error-uniform")!.hidden, true);

  for (const status of [404, 202]) {
    const uniform = boot("recovery.js", html, () => ({ status, body: { result: "RECEIVED" } }));
    uniform.getElementById("confirm-recovery-btn")!.click();
    await settle();
    assert.equal(uniform.getElementById("error-uniform")!.hidden, false, `status ${status}`);
    assert.equal(uniform.getElementById("error-apply-failed")!.hidden, true, `status ${status}`);
  }
});

test("TEST-CNS-1772: recovery.js 'Volver a intentar' tras el 503 reenvía /recovery/revoke y un CONFIRMED posterior muestra el comprobante", async () => {
  let calls = 0;
  const doc = boot("recovery.js", renderRecoveryConfirmPage(), () => {
    calls += 1;
    return calls === 1 ? { status: 503, body: UNAVAILABLE } : { status: 200, body: { state: "CONFIRMED", revocationRef: "ref-opaca" } };
  });
  doc.getElementById("confirm-recovery-btn")!.click();
  await settle();
  const retry = doc.getElementById("retry-apply-btn")!;
  retry.click();
  assert.equal(retry.attrs["aria-busy"], "true"); // mientras se envía el reintento
  assert.equal(retry.attrs["aria-disabled"], "true");
  await settle();
  assert.equal(retry.attrs["aria-busy"], "false");
  assert.equal(calls, 2);
  assert.equal(doc.getElementById("error-apply-failed")!.hidden, true);
  assert.equal(doc.getElementById("state-applied")!.hidden, false);
});
