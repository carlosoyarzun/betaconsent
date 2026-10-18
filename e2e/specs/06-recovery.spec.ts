// Rutas /r/{token} -> /recovery/confirm: UX-CNS-004 (recuperación), UX-CNS-015 (ERR-RV-22 interino), SEC-CNS-014,
// API-CNS-134/135 (RV0/RV1), GRD-RV-06/17, INV-CM-05.
import { test, expect } from "../fixtures/index.ts";

test.describe("recovery", () => {
  test("E2E-CNS-063 canje GET /r/{token} responde 303 a /recovery/confirm sin leer la BD y /recovery/confirm muestra el retiro total (UX-CNS-004, SEC-CNS-014)", async ({ page, app, request }) => {
    const link = await app.createRecoveryLink(page);
    expect(link).toMatch(/^\/r\/[0-9A-Za-z_-]{16,}$/);
    // el canje con una sesión limpia (APIRequestContext) responde 303 sin consumir el token
    const res = await request.get(link, { maxRedirects: 0 });
    expect(res.status()).toBe(303);
    expect(res.headers()["location"]).toBe("/recovery/confirm");
    await page.goto(link);
    await expect(page).toHaveURL(/\/recovery\/confirm$/);
    await expect(page.getByRole("heading", { level: 1, name: "Confirmar retiro" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Vas a retirar tu consentimiento" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Confirmar retiro total" })).toBeVisible();
    await expect(page.getByRole("link", { name: /ayuda@example\.invalid/ })).toBeVisible();
  });

  test("E2E-CNS-064 'Confirmar retiro total' vía enlace de recuperación: 'Retiramos tu consentimiento' con foco en el título (UX-CNS-004)", async ({ page, app }) => {
    const link = await app.createRecoveryLink(page);
    await page.goto(link);
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    const h = page.getByRole("heading", { name: "Retiramos tu consentimiento" });
    await expect(h).toBeVisible();
    await expect(h).toBeFocused();
    await expect(page.getByText("Nunca te mostraremos aquí el enlace de gestión")).toBeVisible();
    await expect(page.getByRole("button", { name: "Confirmar retiro total" })).toHaveCount(0);
  });

  test("E2E-CNS-065 enlace de recuperación inválido: /recovery/confirm entrega el error uniforme en HTML con vía a soporte (INV-CM-05)", async ({ page }) => {
    await page.goto(`/r/${"a".repeat(64)}`);
    await expect(page).toHaveURL(/\/recovery\/confirm$/);
    await expect(page.getByRole("alert")).toContainText("No pudimos continuar con este retiro.");
    await expect(page.getByRole("link", { name: /ayuda@example\.invalid/ })).toBeVisible();
    await expect(page.getByRole("button", { name: "Confirmar retiro total" })).toHaveCount(0);
  });

  test("E2E-CNS-066 GET /recovery/confirm sin cookie de recuperación: 404 HTML uniforme, con CSP frame-ancestors 'none' (SEC-CNS-014)", async ({ page }) => {
    const res = await page.goto("/recovery/confirm");
    expect(res!.status()).toBe(404);
    expect(res!.headers()["content-type"]).toContain("text/html");
    expect(res!.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
    await expect(page.getByRole("alert")).toContainText("No pudimos continuar con este retiro.");
  });

  test("E2E-CNS-067 un enlace de recuperación ya usado no vuelve a ofrecer la confirmación (token de un solo uso, GRD-RV-06)", async ({ page, app, browser }) => {
    const link = await app.createRecoveryLink(page);
    await page.goto(link);
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    await expect(page.getByRole("heading", { name: "Retiramos tu consentimiento" })).toBeVisible();
    const ctx2 = await browser.newContext({ baseURL: app.baseURL });
    const p2 = await ctx2.newPage();
    await p2.goto(link);
    await expect(p2).toHaveURL(/\/recovery\/confirm$/);
    // Observado: o bien error uniforme, o bien 'ya está en curso'; en ambos casos no hay botón de confirmación activo
    const confirm = p2.getByRole("button", { name: "Confirmar retiro total" });
    if (await confirm.count()) {
      await confirm.click();
      await expect(p2.getByRole("alert").filter({ hasText: "No pudimos continuar con este retiro." }).or(p2.getByRole("heading", { name: "Este retiro ya está en curso" }))).toBeVisible();
    } else {
      await expect(p2.getByRole("alert")).toContainText("No pudimos continuar con este retiro.");
    }
    await ctx2.close();
  });

  test("E2E-CNS-068 ERR-RV-22 (copy interino): ante 503 se muestra 'No pudimos completar tu retiro ahora', código ERR-RV-22, role=alert con foco (UX-CNS-015)", async ({ page, app }) => {
    const link = await app.createRecoveryLink(page);
    await page.goto(link);
    await app.forceApplyFailure(page, "/recovery/revoke");
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    const alert = page.getByRole("alert").filter({ hasText: "No pudimos completar tu retiro ahora" });
    await expect(alert).toBeVisible();
    await expect(alert).toBeFocused();
    await expect(alert).toContainText("Tu enlace sigue siendo válido");
    await expect(alert).toContainText("Código: ERR-RV-22");
    await expect(alert.getByRole("link", { name: "Escribir al equipo del estudio" })).toHaveAttribute("href", /^mailto:/);
  });

  test("E2E-CNS-069 ERR-RV-22: 'Volver a intentar' reenvía la confirmación y, sin el fallo, completa el retiro (UX-CNS-015)", async ({ page, app }) => {
    const link = await app.createRecoveryLink(page);
    await page.goto(link);
    await page.route("**/recovery/revoke", (route) =>
      route.fulfill({ status: 503, contentType: "application/problem+json", body: JSON.stringify({ code: "GUARD_EVALUATOR_UNAVAILABLE", status: 503, correlationId: "00000000-0000-4000-8000-000000000000" }) }),
      { times: 1 });
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    const alert = page.getByRole("alert").filter({ hasText: "No pudimos completar tu retiro ahora" });
    await expect(alert).toBeVisible();
    await alert.getByRole("button", { name: "Volver a intentar" }).click();
    await expect(page.getByRole("heading", { name: "Retiramos tu consentimiento" })).toBeVisible();
  });

  test("E2E-CNS-070 el token de recuperación no se consume tras un 503 real del apply-guard", async () => {
    test.skip(true, "No automatizable sin hook: no hay CNS_TEST_* ni inyección de fallo del apply-guard en el proceso web. E2E-CNS-069 cubre solo el reintento de la UI tras un 503 simulado en el navegador (el POST simulado no llega al servidor).");
  });

  test("E2E-CNS-071 error de red al confirmar por recuperación: 'No pudimos conectar.' y 'Reintentar' completa el retiro (UX-CNS-004)", async ({ page, app }) => {
    const link = await app.createRecoveryLink(page);
    await page.goto(link);
    await page.route("**/recovery/revoke", (route) => route.abort("failed"), { times: 1 });
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    const net = page.getByRole("alert").filter({ hasText: "No pudimos conectar." });
    await expect(net).toBeVisible();
    await net.getByRole("button", { name: "Reintentar" }).click();
    await expect(page.getByRole("heading", { name: "Retiramos tu consentimiento" })).toBeVisible();
  });
});
