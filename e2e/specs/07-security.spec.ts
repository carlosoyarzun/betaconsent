// Transversales de seguridad HTTP de la UI de titulares: cabeceras, cookies __Host-*, CSRF/Origin, 404 JSON, higiene de URL.
// Gobierna: UX-CNS-001 (cabeceras), SEC-CNS-014 (cookies, frame-ancestors en /recovery/confirm), GRD-CM-10 (csrf_and_origin),
// PRIV-CNS: cero PII/credenciales en URL.
import type { Page, Response } from "@playwright/test";
import { test, expect } from "../fixtures/index.ts";
import { reachRevocationConfirm } from "../fixtures/flows.ts";

const HTML_ROUTES = ["/welcome", "/verify", "/decision", "/manage", "/manage/verify", "/manage/revocation/verify", "/manage/revocation/confirm", "/recovery/confirm"] as const;

function collectDocuments(page: Page): Response[] {
  const docs: Response[] = [];
  page.on("response", (r) => {
    if (r.request().resourceType() === "document") docs.push(r);
  });
  return docs;
}

test.describe("seguridad HTTP", () => {
  test("E2E-CNS-072 las 8 páginas HTML (variante sin sesión) llevan CSP, no-store y no-referrer (UX-CNS-001)", async ({ request }) => {
    for (const route of HTML_ROUTES) {
      const res = await request.get(route);
      const h = res.headers();
      expect(h["content-type"], route).toContain("text/html");
      expect(h["content-security-policy"], `CSP en ${route}`).toBeTruthy();
      expect(h["content-security-policy"], route).toContain("default-src 'self'");
      expect(h["content-security-policy"], `sin unsafe-inline/eval en ${route}`).not.toMatch(/unsafe-inline|unsafe-eval/);
      expect(h["cache-control"], route).toContain("no-store");
      expect(h["referrer-policy"], route).toBe("no-referrer");
    }
  });

  test("E2E-CNS-073 las páginas HTML en 200 (flujo real hasta la confirmación de retiro) llevan las mismas cabeceras (UX-CNS-001)", async ({ page, app }) => {
    const docs = collectDocuments(page);
    await reachRevocationConfirm(page, app);
    const ok = docs.filter((d) => d.status() === 200 && new URL(d.url()).pathname.match(/^\/(welcome|verify|decision|manage|manage\/verify|manage\/revocation\/verify|manage\/revocation\/confirm)$/));
    const paths = new Set(ok.map((d) => new URL(d.url()).pathname));
    for (const p of ["/welcome", "/verify", "/decision", "/manage", "/manage/verify", "/manage/revocation/verify", "/manage/revocation/confirm"]) {
      expect(paths.has(p), `se visitó ${p} con 200`).toBe(true);
    }
    for (const d of ok) {
      const h = d.headers();
      expect(h["content-security-policy"], d.url()).toContain("default-src 'self'");
      expect(h["cache-control"], d.url()).toContain("no-store");
      expect(h["referrer-policy"], d.url()).toBe("no-referrer");
    }
  });

  test("E2E-CNS-074 /recovery/confirm (200 y 404) lleva frame-ancestors 'none' y COOP same-origin (SEC-CNS-014)", async ({ page, app }) => {
    const res404 = await page.goto("/recovery/confirm");
    expect(res404!.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(res404!.headers()["cross-origin-opener-policy"]).toBe("same-origin");
    const link = await app.createRecoveryLink(page);
    const res200 = await page.goto(link);
    expect(res200!.status()).toBe(200);
    expect(res200!.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(res200!.headers()["cross-origin-opener-policy"]).toBe("same-origin");
  });

  test("E2E-CNS-075 hallazgo F-E2E-03: las páginas HTML del invitado (incluida la confirmación de retiro) no deberían poder enmarcarse (frame-ancestors 'none' o X-Frame-Options)", async ({ request }) => {
    test.fail(true, "F-E2E-03 (P2): solo /recovery/confirm declara frame-ancestors; las otras 7 páginas (incl. /manage/revocation/confirm) sin frame-ancestors ni X-Frame-Options => clickjacking posible");
    for (const route of HTML_ROUTES.filter((r) => r !== "/recovery/confirm")) {
      const h = (await request.get(route)).headers();
      const csp = h["content-security-policy"] ?? "";
      expect(/frame-ancestors\s+'none'/.test(csp) || /^(deny|sameorigin)$/i.test(h["x-frame-options"] ?? ""), route).toBe(true);
    }
  });

  test("E2E-CNS-076 hallazgo F-E2E-02: las páginas HTML deberían llevar X-Content-Type-Options: nosniff (como /staff y el roster)", async ({ request }) => {
    test.fail(true, "F-E2E-02 (P2): writeHtmlSecurityHeaders no fija X-Content-Type-Options; staff-ui.handler.ts:109 y staff-roster.handler.ts:80 sí");
    for (const route of HTML_ROUTES) {
      expect((await request.get(route)).headers()["x-content-type-options"], route).toBe("nosniff");
    }
  });

  test("E2E-CNS-077 cookies __Host-*: Secure, Path=/, sin Domain; sesión HttpOnly + SameSite=Lax; CSRF legible por JS con SameSite=Lax (SEC-CNS-014)", async ({ page, app }) => {
    await page.goto(await app.invitationPath());
    await page.getByRole("button", { name: "Continuar" }).click();
    await expect(page).toHaveURL(/\/verify$/);
    const cookies = await page.context().cookies();
    expect(cookies.length).toBeGreaterThan(0);
    for (const c of cookies) {
      expect(c.name, "toda cookie del flujo usa prefijo __Host-").toMatch(/^__Host-/);
      expect(c.secure, c.name).toBe(true);
      expect(c.path, c.name).toBe("/");
      expect(c.sameSite, c.name).toBe("Lax");
    }
    const session = cookies.find((c) => c.name === "__Host-cns-session");
    expect(session, "cookie de sesión").toBeDefined();
    expect(session!.httpOnly).toBe(true);
    const csrf = cookies.find((c) => c.name === "__Host-cns-csrf");
    expect(csrf, "cookie CSRF double-submit").toBeDefined();
    expect(csrf!.httpOnly, "el JS debe poder leer el token CSRF").toBe(false);
    // ninguna cookie de sesión legible desde JS
    const visibleToJs = await page.evaluate(() => document.cookie);
    expect(visibleToJs).not.toContain("__Host-cns-session");
  });

  test("E2E-CNS-078 POST sin x-csrf-token o con Origin ajeno se rechaza con 403 (GRD-CM-10 csrf_and_origin)", async ({ page, app }) => {
    await page.goto(await app.invitationPath());
    const results = await page.evaluate(async () => {
      const csrf = decodeURIComponent((document.cookie.split(";").map((c) => c.trim()).find((c) => c.startsWith("__Host-cns-csrf=")) ?? "=").split("=")[1]!);
      const sinToken = await fetch("/invitation/open", { method: "POST", headers: { "content-type": "application/json" }, body: "{}", credentials: "same-origin" });
      const tokenErroneo = await fetch("/invitation/open", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrf + "x" }, body: "{}", credentials: "same-origin" });
      return [sinToken.status, tokenErroneo.status];
    });
    expect(results).toEqual([403, 403]);
    // Origin ajeno (cabecera fijada fuera del navegador, que no deja falsearla)
    const res = await fetch(`${app.baseURL}/otp/request`, { method: "POST", headers: { origin: "https://evil.invalid", "content-type": "application/json", "x-csrf-token": "x" }, body: "{}" });
    expect(res.status).toBe(403);
  });

  test("E2E-CNS-079 rutas fuera del catálogo responden 404 JSON uniforme (sin HTML ni stack) en GET y POST", async ({ request }) => {
    for (const [method, path] of [["GET", "/no-existe"], ["GET", "/assets/no-listado.js"], ["GET", "/platform/anything"], ["GET", "/../etc/passwd"], ["POST", "/no-existe"]] as const) {
      const res = method === "GET" ? await request.get(path) : await request.post(path, { data: {} });
      expect(res.status(), `${method} ${path}`).toBe(404);
      expect(res.headers()["content-type"], `${method} ${path}`).toContain("application/json");
      expect(await res.json()).toEqual({ status: 404 });
    }
  });

  test("E2E-CNS-080 higiene de URL: ninguna navegación del flujo completo expone tokens, OTP ni query string (PRIV: cero credenciales en URL)", async ({ page, app }) => {
    const urls: string[] = [];
    page.on("framenavigated", (f) => { if (f === page.mainFrame()) urls.push(f.url()); });
    await reachRevocationConfirm(page, app);
    const finals = urls.filter((u) => !/\/(i|m|r)\/[^/]+$/.test(new URL(u).pathname));
    expect(finals.length).toBeGreaterThan(5);
    for (const u of finals) {
      const url = new URL(u);
      expect(url.search, u).toBe("");
      expect(url.pathname, u).toMatch(/^\/(welcome|verify|decision|manage|manage\/verify|manage\/revocation\/verify|manage\/revocation\/confirm)$/);
    }
  });

  test("E2E-CNS-081 los activos estáticos del invitado se sirven con no-store y solo desde la lista cerrada /assets/** (static-assets.ts)", async ({ request }) => {
    for (const p of ["/assets/app.css", "/assets/welcome.js", "/assets/design-system/index.css"]) {
      const res = await request.get(p);
      expect(res.status(), p).toBe(200);
      expect(res.headers()["cache-control"], p).toContain("no-store");
    }
    expect((await request.get("/assets/../../package.json")).status()).toBe(404);
  });
});
