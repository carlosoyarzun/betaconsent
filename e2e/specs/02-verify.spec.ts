// Ruta /verify (scope DECISION): UX-CNS-002, API-CNS-103/104/105, INV-OT-06, INV-CM-05.
import { test, expect } from "../fixtures/index.ts";
import { continueToVerify, openInvitation, typeOtp } from "../fixtures/flows.ts";

test.describe("verify", () => {
  test.beforeEach(async ({ page, app }) => {
    await openInvitation(page, app);
    await continueToVerify(page);
  });

  test("E2E-CNS-010 /verify muestra paso 1 de 3, campo de código con etiqueta, 'Verificar' y 'Reenviar código' (UX-CNS-002)", async ({ page }) => {
    await expect(page.getByRole("heading", { level: 1, name: "Verifica el código" })).toBeVisible();
    await expect(page.getByText("Paso 1 de 3 · Verificación")).toBeVisible();
    const input = page.getByLabel("Código de verificación");
    await expect(input).toBeVisible();
    await expect(input).toHaveAttribute("inputmode", "numeric");
    await expect(input).toHaveAttribute("autocomplete", "one-time-code");
    await expect(page.getByRole("button", { name: "Verificar", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Reenviar código" })).toBeVisible();
    await expect(page.getByRole("link", { name: /ayuda@example\.invalid/ })).toBeVisible();
  });

  test("E2E-CNS-011 observación O-2: el texto de ayuda de /verify muestra marcadores de parámetro sin resolver ([N], P-01, P-02, P-06)", async ({ page }) => {
    const body = page.locator("main");
    await expect(body).toContainText("[N] caracteres");
    await expect(body).toContainText("P-01");
    await expect(body).toContainText("P-06");
  });

  test("E2E-CNS-012 OTP correcto navega a /decision (UX-CNS-002, API-CNS-104)", async ({ page, app }) => {
    await typeOtp(page, await app.readLatestOtp());
    await expect(page).toHaveURL(/\/decision$/);
    await expect(page.getByRole("heading", { level: 1, name: "Revisa y decide" })).toBeVisible();
  });

  test("E2E-CNS-013 OTP incorrecto: mensaje con role=alert, aria-invalid=true, permanece en /verify y no revela intentos (ERR-OT-02)", async ({ page, app }) => {
    const real = await app.readLatestOtp();
    const wrong = real === "000000" ? "111111" : "000000";
    await typeOtp(page, wrong);
    const input = page.getByLabel("Código de verificación");
    const err = page.getByRole("alert").filter({ hasText: "El código ingresado no es correcto" });
    await expect(err).toBeVisible();
    await expect(input).toHaveAttribute("aria-invalid", "true");
    await expect(page).toHaveURL(/\/verify$/);
    await expect(page.locator("main")).not.toContainText(/intentos? restantes?/i);
    // el código correcto sigue sirviendo tras un fallo
    await typeOtp(page, real);
    await expect(page).toHaveURL(/\/decision$/);
  });

  test("E2E-CNS-014 tras el rechazo, el botón 'Verificar' vuelve a estar disponible (aria-busy=false) (UX-CNS-002)", async ({ page }) => {
    await typeOtp(page, "000000");
    const btn = page.getByRole("button", { name: "Verificar", exact: true });
    await expect(btn).toHaveAttribute("aria-busy", "false");
    await expect(btn).not.toHaveAttribute("aria-disabled", "true");
  });

  test("E2E-CNS-015 bloqueado: 'Solicitar nuevo código' emite un OTP nuevo que permite continuar a /decision (UX-CNS-002, GRD-OT-08)", async ({ page, app }) => {
    const wrong = (await app.readLatestOtp()) === "000000" ? "111111" : "000000";
    const locked = page.getByRole("alert").filter({ hasText: "Bloqueamos este código por varios intentos incorrectos." });
    for (let i = 0; i < 12 && !(await locked.isVisible()); i += 1) {
      await typeOtp(page, wrong);
      await page.waitForTimeout(100);
    }
    await expect(locked).toBeVisible();
    const before = await app.otpCount();
    await locked.getByRole("button", { name: "Solicitar nuevo código" }).click();
    await expect.poll(() => app.otpCount()).toBe(before + 1);
    // la UI limpia y enfoca el campo al recibir la respuesta: esperar antes de escribir el código nuevo
    await expect(page.getByLabel("Código de verificación")).toBeFocused();
    await typeOtp(page, await app.readLatestOtp());
    await expect(page).toHaveURL(/\/decision$/);
  });

  test("E2E-CNS-016 aviso de código expirado (respuesta OTP_EXPIRED_OR_CONSUMED simulada en el navegador) con role=alert y 'Solicitar nuevo código' (UX-CNS-002)", async ({ page, app }) => {
    // No hay reloj de servidor controlable (TTL P-02 = 10 min, sin hook CNS_TEST_*): se simula la respuesta en el navegador.
    await page.route("**/otp/submit", (route) =>
      route.fulfill({ status: 409, contentType: "application/problem+json", body: JSON.stringify({ code: "OTP_EXPIRED_OR_CONSUMED", status: 409 }) }),
      { times: 1 });
    await typeOtp(page, "123456");
    const expired = page.getByRole("alert").filter({ hasText: "Este código ya no es válido." });
    await expect(expired).toBeVisible();
    await expect(expired).toContainText("Puede haber expirado o haberse usado antes");
    await expired.getByRole("button", { name: "Solicitar nuevo código" }).click();
    await expect(expired).toBeHidden();
    await expect(page.getByLabel("Código de verificación")).toBeFocused();
    await typeOtp(page, await app.readLatestOtp());
    await expect(page).toHaveURL(/\/decision$/);
  });

  test("E2E-CNS-017 bloqueo por intentos fallidos: aviso 'Bloqueamos este código…' con role=alert; el código correcto deja de servir (SEC-CNS-021, P-03)", async ({ page, app }) => {
    const real = await app.readLatestOtp();
    const wrong = real === "000000" ? "111111" : "000000";
    const locked = page.getByRole("alert").filter({ hasText: "Bloqueamos este código por varios intentos incorrectos." });
    for (let i = 0; i < 12 && !(await locked.isVisible()); i += 1) {
      await typeOtp(page, wrong);
      await page.waitForTimeout(100);
    }
    await expect(locked).toBeVisible();
    await expect(locked.getByRole("button", { name: "Solicitar nuevo código" })).toBeVisible();
    await expect(page).toHaveURL(/\/verify$/);
  });

  test("E2E-CNS-018 observación O-3: con la política LOCAL, 'Reenviar código' responde ya el límite (P-06 sin valor) en una región de estado y no emite OTP (UX-CNS-002, API-CNS-105)", async ({ page, app }) => {
    const before = await app.otpCount();
    await page.getByRole("button", { name: "Reenviar código" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Alcanzaste el límite de reenvíos disponible por ahora." })).toBeVisible();
    expect(await app.otpCount()).toBe(before);
  });

  test("E2E-CNS-019 el aviso de límite de reenvíos no revela cifra y el código original sigue sirviendo (P-06)", async ({ page, app }) => {
    await page.getByRole("button", { name: "Reenviar código" }).click();
    const limit = page.getByText("Alcanzaste el límite de reenvíos disponible por ahora.");
    await expect(limit).toBeVisible();
    await expect(limit).not.toContainText(/\d/);
    await typeOtp(page, await app.readLatestOtp());
    await expect(page).toHaveURL(/\/decision$/);
  });

  test("E2E-CNS-020 error de red al verificar: 'No pudimos conectar.' con 'Reintentar' que reenvía la acción (UX-CNS-002)", async ({ page, app }) => {
    await page.route("**/otp/submit", (route) => route.abort("failed"), { times: 1 });
    await typeOtp(page, await app.readLatestOtp());
    const net = page.getByRole("alert").filter({ hasText: "No pudimos conectar." });
    await expect(net).toBeVisible();
    await net.getByRole("button", { name: "Reintentar" }).click();
    await expect(page).toHaveURL(/\/decision$/);
  });

  test("E2E-CNS-021 navegación por teclado: Tab llega al campo, Enter en 'Verificar' envía y Escape no rompe el flujo (WCAG 2.1.1)", async ({ page, app }) => {
    await page.getByLabel("Código de verificación").focus();
    await page.keyboard.type(await app.readLatestOtp());
    await page.getByRole("button", { name: "Verificar", exact: true }).focus();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/decision$/);
  });
});

test.describe("verify sin sesión", () => {
  test("E2E-CNS-022 GET /verify sin sesión entrega la pantalla de error uniforme en HTML (INV-CM-05)", async ({ page }) => {
    const res = await page.goto("/verify");
    expect(res!.status()).toBe(404);
    expect(res!.headers()["content-type"]).toContain("text/html");
    await expect(page.getByRole("heading", { level: 1, name: "Verifica el código" })).toBeVisible();
    await expect(page.getByRole("alert")).toContainText("No pudimos continuar con esta verificación.");
    await expect(page.getByLabel("Código de verificación")).toHaveCount(0);
  });
});
