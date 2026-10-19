// Ruta /i/{token} -> /welcome (UX-CNS-001, API-CNS-101, INV-CM-05, INV-CM-08).
import { test, expect } from "../fixtures/index.ts";
import { WELCOME_H1, openInvitation } from "../fixtures/flows.ts";

const BADGE = /Prueba · IT0|Entorno de prueba · IT0 · datos sintéticos/;

test.describe("welcome", () => {
  test("E2E-CNS-001 canje GET /i/{token} responde 303 a /welcome sin exponer el token (UX-CNS-001, API-CNS-101)", async ({ app, request }) => {
    const res = await request.get(await app.invitationPath(), { maxRedirects: 0 });
    expect(res.status()).toBe(303);
    expect(res.headers()["location"]).toBe("/welcome");
  });

  test("E2E-CNS-002 /welcome muestra título, detalle de invitación y los 3 pasos de 'Cómo funciona' (UX-CNS-001)", async ({ page, app }) => {
    await openInvitation(page, app);
    await expect(page.getByRole("heading", { level: 1, name: WELCOME_H1 })).toBeVisible();
    await expect(page.getByText("te invita a participar en el Estudio Beta de LectorPro")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Cómo funciona" })).toBeVisible();
    for (const step of ["Verifica tu identidad", "Revisa la información", "Decide si participar"]) {
      await expect(page.getByText(step, { exact: true })).toBeVisible();
    }
    await expect(page).toHaveTitle(/Consent App/);
    await expect(page.locator("html")).toHaveAttribute("lang", "es");
  });

  for (const [label, width] of [["escritorio", 1280], ["móvil", 390]] as const) {
    test(`E2E-CNS-003 insignia de entorno 'Prueba · IT0' visible en ${label} (marca de agua IT0, DEC-BR-014)`, async ({ page, app }) => {
      await page.setViewportSize({ width, height: 800 });
      await openInvitation(page, app);
      await expect(page.getByText(BADGE).filter({ visible: true })).toHaveCount(1);
      await expect(page.getByText("LectorPro · Estudio Beta")).toBeVisible();
    });
  }

  test("E2E-CNS-004 botón principal 'Continuar' único, visible y habilitado; foco inicial en el documento (UX-CNS-001, WCAG 2.4.3)", async ({ page, app }) => {
    await openInvitation(page, app);
    const cta = page.getByRole("button", { name: "Continuar" });
    await expect(cta).toHaveCount(1);
    await expect(cta).toBeVisible();
    await expect(cta).not.toHaveAttribute("aria-disabled", "true");
    // Línea base: sin autofoco; el primer Tab llega a un control interactivo de la página (no a una trampa).
    expect(await page.evaluate(() => document.activeElement === document.body)).toBe(true);
    await page.keyboard.press("Tab");
    expect(await page.evaluate(() => document.activeElement !== document.body)).toBe(true);
  });

  test("E2E-CNS-005 'Continuar' abre la invitación, emite un OTP al sink y navega a /verify (UX-CNS-001, API-CNS-101/103)", async ({ page, app }) => {
    await openInvitation(page, app);
    const before = await app.otpCount();
    await page.getByRole("button", { name: "Continuar" }).click();
    await expect(page).toHaveURL(/\/verify$/);
    expect(await app.otpCount()).toBe(before + 1);
    expect(await app.readLatestOtp()).toMatch(/^\d{6}$/);
  });

  test("E2E-CNS-006 enlace inválido: /welcome muestra el error uniforme con role=alert, sin 'Continuar', y no emite OTP (INV-CM-05)", async ({ page, app }) => {
    const before = await app.otpCount();
    await page.goto(`/i/${"0".repeat(64)}`);
    await expect(page).toHaveURL(/\/welcome$/);
    const alert = page.getByRole("alert").filter({ hasText: "No pudimos abrir esta invitación." });
    await expect(alert).toBeVisible();
    await expect(alert).toContainText("El enlace puede no ser válido o haber expirado");
    await expect(page.getByRole("button", { name: "Continuar" })).toHaveCount(0);
    expect(await app.otpCount()).toBe(before);
  });

  test("E2E-CNS-007 GET /welcome sin sesión entrega la pantalla de error uniforme en HTML (no JSON) (INV-CM-05)", async ({ page }) => {
    const res = await page.goto("/welcome");
    expect(res!.status()).toBe(404);
    expect(res!.headers()["content-type"]).toContain("text/html");
    await expect(page.getByRole("heading", { level: 1, name: WELCOME_H1 })).toBeVisible();
    await expect(page.getByRole("alert")).toContainText("No pudimos abrir esta invitación.");
    await expect(page.getByRole("button", { name: "Continuar" })).toHaveCount(0);
  });

  test("E2E-CNS-008 línea base: una invitación OPENED se puede reabrir desde otro contexto y llega a /verify sin emitir un OTP nuevo (observación O-1, ver PR)", async ({ page, app, browser }) => {
    const path = await app.invitationPath();
    await page.goto(path);
    await page.getByRole("button", { name: "Continuar" }).click();
    await expect(page).toHaveURL(/\/verify$/);
    const before = await app.otpCount();
    const ctx2 = await browser.newContext({ baseURL: app.baseURL });
    const page2 = await ctx2.newPage();
    await page2.goto(path);
    await page2.getByRole("button", { name: "Continuar" }).click();
    await expect(page2).toHaveURL(/\/verify$/);
    expect(await app.otpCount()).toBe(before);
    await ctx2.close();
  });

  test("E2E-CNS-009 error de red: aviso 'No pudimos conectar.' y 'Reintentar' completa el flujo (UX-CNS-001)", async ({ page, app }) => {
    await openInvitation(page, app);
    await page.route("**/invitation/open", (route) => route.abort("failed"), { times: 1 });
    await page.getByRole("button", { name: "Continuar" }).click();
    const net = page.getByRole("alert").filter({ hasText: "No pudimos conectar." });
    await expect(net).toBeVisible();
    await net.getByRole("button", { name: "Reintentar" }).click();
    await expect(page).toHaveURL(/\/verify$/);
  });
});
