// Rutas /m/{token} -> /manage, /manage/verify: UX-CNS-004, API-CNS-130 (R0..R2), INV-OT-06, INV-CM-05.
import { test, expect } from "../fixtures/index.ts";
import { reachManageStatus, typeOtp } from "../fixtures/flows.ts";

async function toManageVerify(page: import("@playwright/test").Page, path: string): Promise<void> {
  await page.goto(path);
  await expect(page).toHaveURL(/\/manage$/);
  await page.getByRole("button", { name: "Verificar mi identidad" }).click();
  await expect(page).toHaveURL(/\/manage\/verify$/);
}

test.describe("manage", () => {
  test("E2E-CNS-035 canje GET /m/{token} responde 303 a /manage sin leer ni exponer el token (UX-CNS-004)", async ({ app, request }) => {
    const res = await request.get(app.managementPath, { maxRedirects: 0 });
    expect(res.status()).toBe(303);
    expect(res.headers()["location"]).toBe("/manage");
  });

  test("E2E-CNS-036 /manage (entrada) pide verificar identidad antes de mostrar información (UX-CNS-004)", async ({ page, app }) => {
    await page.goto(app.managementPath);
    await expect(page.getByRole("heading", { level: 1, name: "Tu consentimiento" })).toBeVisible();
    await expect(page.getByText("necesitamos verificar tu identidad con un código")).toBeVisible();
    await expect(page.getByRole("button", { name: "Verificar mi identidad" })).toBeVisible();
    await expect(page.getByText("Consentimiento otorgado")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Retirar mi consentimiento" })).toHaveCount(0);
  });

  test("E2E-CNS-037 'Verificar mi identidad' emite un OTP de gestión y navega a /manage/verify sin paso de decisión (UX-CNS-004)", async ({ page, app }) => {
    const before = await app.otpCount();
    await toManageVerify(page, app.managementPath);
    expect(await app.otpCount()).toBe(before + 1);
    await expect(page.getByRole("heading", { level: 1, name: "Verifica el código" })).toBeVisible();
    await expect(page.getByText(/Paso \d de 3/)).toHaveCount(0);
  });

  test("E2E-CNS-047 hallazgo F-E2E-01: el enlace de gestión sembrado por dev.ts permite verificar el OTP y llegar al estado (hoy POST /otp/submit responde 500 LedgerPayloadViolationError)", async ({ page, app }) => {
    test.fail(true, "F-E2E-01 (P1, LOCAL): la siembra MGMT_* de dev.ts usa refs no-UUID y el ledger rechaza el evento en V3 de scope MANAGE");
    await toManageVerify(page, app.managementPath);
    await typeOtp(page, await app.readLatestOtp());
    await expect(page).toHaveURL(/\/manage$/, { timeout: 3000 });
  });

  test("E2E-CNS-038 OTP de gestión correcto muestra el estado: 'Consentimiento otorgado', 4 finalidades y 'Retirar mi consentimiento' (UX-CNS-004)", async ({ page, app }) => {
    await reachManageStatus(page, app);
    const status = page.getByRole("status").filter({ hasText: "Consentimiento otorgado" });
    await expect(status).toBeVisible();
    for (const t of ["Participar en el Estudio Beta", "Grabación de audio", "Análisis automatizado", "Revisión humana"]) {
      await expect(status.getByText(t)).toBeVisible();
    }
    await expect(page.getByText("Puedes retirar tu consentimiento en cualquier momento.")).toBeVisible();
  });

  test("E2E-CNS-039 OTP de gestión incorrecto: error con role=alert y se permanece en /manage/verify (ERR-OT-02)", async ({ page, app }) => {
    await toManageVerify(page, app.managementPath);
    const real = await app.readLatestOtp();
    await typeOtp(page, real === "000000" ? "111111" : "000000");
    await expect(page.getByRole("alert").filter({ hasText: "El código ingresado no es correcto" })).toBeVisible();
    await expect(page).toHaveURL(/\/manage\/verify$/);
  });

  test("E2E-CNS-040 bloqueo en gestión: nunca ofrece 'Solicitar nuevo código'; ofrece enlace de recuperación y caso humano, con foco en el aviso (INV-OT-06, SEC-CNS-021)", async ({ page, app }) => {
    await toManageVerify(page, app.managementPath);
    const wrong = (await app.readLatestOtp()) === "000000" ? "111111" : "000000";
    const locked = page.getByRole("alert").filter({ hasText: "Bloqueamos este código por varios intentos incorrectos." });
    for (let i = 0; i < 12 && !(await locked.isVisible()); i += 1) {
      await typeOtp(page, wrong);
      await page.waitForTimeout(100);
    }
    await expect(locked).toBeVisible();
    await expect(locked).toBeFocused();
    await expect(locked).toContainText("Nunca pierdes la posibilidad de retirar tu consentimiento");
    await expect(page.getByRole("button", { name: "Solicitar nuevo código" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Enviar enlace de recuperación" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Abrir caso con soporte humano" })).toBeVisible();
    await expect(page.getByLabel("Código de verificación")).toBeHidden();
  });

  test("E2E-CNS-041 desde el bloqueo, 'Enviar enlace de recuperación' responde de forma uniforme y el sink recibe /r/{token} (API-CNS-134)", async ({ page, app }) => {
    await toManageVerify(page, app.managementPath);
    const wrong = (await app.readLatestOtp()) === "000000" ? "111111" : "000000";
    const locked = page.getByRole("alert").filter({ hasText: "Bloqueamos este código" });
    for (let i = 0; i < 12 && !(await locked.isVisible()); i += 1) {
      await typeOtp(page, wrong);
      await page.waitForTimeout(100);
    }
    await expect(locked).toBeVisible();
    await page.getByRole("button", { name: "Enviar enlace de recuperación" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Si corresponde, enviamos un enlace a tu vía de contacto registrada." })).toBeVisible();
    // el enlace nunca se muestra en pantalla
    await expect(page.locator("main")).not.toContainText(/\/r\/[0-9a-f]{16,}/);
  });

  test("E2E-CNS-042 desde el bloqueo, 'Abrir caso con soporte humano' anuncia que se abrió un caso (RC1 BEARER; nunca 'denegado')", async ({ page, app }) => {
    await toManageVerify(page, app.managementPath);
    const wrong = (await app.readLatestOtp()) === "000000" ? "111111" : "000000";
    const locked = page.getByRole("alert").filter({ hasText: "Bloqueamos este código" });
    for (let i = 0; i < 12 && !(await locked.isVisible()); i += 1) {
      await typeOtp(page, wrong);
      await page.waitForTimeout(100);
    }
    await expect(locked).toBeVisible();
    await page.getByRole("button", { name: "Abrir caso con soporte humano" }).click();
    await expect(page.getByText(/Abrimos un caso; te contactaremos\./)).toBeVisible();
    await expect(page.locator("main")).not.toContainText(/denegad/i);
  });

  test("E2E-CNS-043 GET /manage sin sesión entrega 'Este enlace ya no está disponible.' en HTML con vía a soporte (INV-CM-05)", async ({ page }) => {
    const res = await page.goto("/manage");
    expect(res!.status()).toBe(404);
    expect(res!.headers()["content-type"]).toContain("text/html");
    await expect(page.getByRole("alert")).toContainText("Este enlace ya no está disponible.");
    await expect(page.getByRole("link", { name: "Contactar a soporte" })).toHaveAttribute("href", /^mailto:/);
  });

  test("E2E-CNS-044 GET /manage/verify sin sesión de gestión entrega el error uniforme en HTML (INV-CM-05)", async ({ page }) => {
    const res = await page.goto("/manage/verify");
    expect(res!.status()).toBe(404);
    expect(res!.headers()["content-type"]).toContain("text/html");
    await expect(page.getByRole("alert")).toContainText("No pudimos continuar con esta verificación.");
  });

  test("E2E-CNS-045 enlace de gestión inválido: /manage entrega el error uniforme sin 'Verificar mi identidad' ni OTP (INV-CM-05)", async ({ page, app }) => {
    const before = await app.otpCount();
    await page.goto("/m/token-que-no-existe-000");
    await expect(page).toHaveURL(/\/manage$/);
    await expect(page.getByRole("alert")).toContainText("Este enlace ya no está disponible.");
    await expect(page.getByRole("button", { name: "Verificar mi identidad" })).toHaveCount(0);
    expect(await app.otpCount()).toBe(before);
  });

  test("E2E-CNS-046 error de red en 'Verificar mi identidad': 'No pudimos conectar.' y 'Reintentar' continúa (UX-CNS-004)", async ({ page, app }) => {
    await page.goto(app.managementPath);
    await page.route("**/otp/request", (route) => route.abort("failed"), { times: 1 });
    await page.getByRole("button", { name: "Verificar mi identidad" }).click();
    const net = page.getByRole("alert").filter({ hasText: "No pudimos conectar." });
    await expect(net).toBeVisible();
    await net.getByRole("button", { name: "Reintentar" }).click();
    await expect(page).toHaveURL(/\/manage\/verify$/);
  });
});
