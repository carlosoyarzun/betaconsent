// Rutas /manage/revocation/verify y /manage/revocation/confirm: UX-CNS-004, UX-CNS-015 (ERR-RV-21 interino),
// REQ-CNS-033 (retiro total), API-CNS-131/132 (R3), INV-OT-06, INV-CM-05.
import { test, expect } from "../fixtures/index.ts";
import { reachManageStatus, reachRevocationConfirm, typeOtp } from "../fixtures/flows.ts";

test.describe("revocation", () => {
  test("E2E-CNS-048 'Retirar mi consentimiento' lleva a /manage/revocation/verify (OTP de clase RIGHTS, sin paso de decisión) y emite un OTP (UX-CNS-004)", async ({ page, app }) => {
    await reachManageStatus(page, app);
    const before = await app.otpCount();
    await page.getByRole("button", { name: "Retirar mi consentimiento" }).click();
    await expect(page).toHaveURL(/\/manage\/revocation\/verify$/);
    await expect(page.getByRole("heading", { level: 1, name: "Verifica el código" })).toBeVisible();
    await expect(page.getByText(/Paso \d de 3/)).toHaveCount(0);
    expect(await app.otpCount()).toBe(before + 1);
  });

  test("E2E-CNS-049 OTP de retiro incorrecto: error con role=alert y se permanece en /manage/revocation/verify (ERR-OT-02)", async ({ page, app }) => {
    await reachManageStatus(page, app);
    await page.getByRole("button", { name: "Retirar mi consentimiento" }).click();
    await expect(page).toHaveURL(/\/manage\/revocation\/verify$/);
    const real = await app.readLatestOtp();
    await typeOtp(page, real === "000000" ? "111111" : "000000");
    await expect(page.getByRole("alert").filter({ hasText: "El código ingresado no es correcto" })).toBeVisible();
    await expect(page).toHaveURL(/\/manage\/revocation\/verify$/);
  });

  test("E2E-CNS-050 bloqueo en retiro: sin 'Solicitar nuevo código', con recuperación y soporte humano (INV-OT-06: el retiro nunca se cierra)", async ({ page, app }) => {
    await reachManageStatus(page, app);
    await page.getByRole("button", { name: "Retirar mi consentimiento" }).click();
    await expect(page).toHaveURL(/\/manage\/revocation\/verify$/);
    const wrong = (await app.readLatestOtp()) === "000000" ? "111111" : "000000";
    const locked = page.getByRole("alert").filter({ hasText: "Bloqueamos este código por varios intentos incorrectos." });
    for (let i = 0; i < 12 && !(await locked.isVisible()); i += 1) {
      await typeOtp(page, wrong);
      await page.waitForTimeout(100);
    }
    await expect(locked).toBeVisible();
    await expect(locked).toBeFocused();
    await expect(page.getByRole("button", { name: "Solicitar nuevo código" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Enviar enlace de recuperación" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Abrir caso con soporte humano" })).toBeVisible();
  });

  test("E2E-CNS-051 /manage/revocation/confirm muestra el alcance del retiro total y los botones 'Confirmar retiro total' / 'Cancelar solicitud de retiro' (UX-CNS-004, REQ-CNS-033)", async ({ page, app }) => {
    await reachRevocationConfirm(page, app);
    await expect(page.getByRole("heading", { level: 1, name: "Confirmar retiro" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Vas a retirar tu consentimiento" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Confirmar retiro total" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Cancelar solicitud de retiro" })).toBeVisible();
  });

  test("E2E-CNS-052 flujo completo hasta APPLIED: 'Retiramos tu consentimiento', comprobante, marca IT0 y foco en el título (UX-CNS-004, API-CNS-132)", async ({ page, app }) => {
    await reachRevocationConfirm(page, app);
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    const h1 = page.getByRole("heading", { level: 1, name: "Retiramos tu consentimiento" });
    await expect(h1).toBeVisible();
    await expect(h1).toBeFocused();
    await expect(page.getByRole("heading", { name: "Comprobante" })).toBeVisible();
    await expect(page.getByText("Comprobante de prueba · marca de agua IT0 · datos sintéticos").filter({ visible: true })).toBeVisible();
    await expect(page.getByText("Nunca te mostraremos aquí el enlace de gestión")).toBeVisible();
    // formulario de confirmación oculto: no se puede confirmar dos veces
    await expect(page.getByRole("button", { name: "Confirmar retiro total" })).toHaveCount(0);
  });

  test("E2E-CNS-053 al aplicar el retiro, el outbox LOCAL recibe un consent.revoked con refs opacas (CA-127, PRIV: sin PII)", async ({ page, app }) => {
    await reachRevocationConfirm(page, app);
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Retiramos tu consentimiento" })).toBeVisible();
    const res = await fetch(`${app.baseURL}/__dev/outbox-sink`);
    const body = (await res.json()) as { enqueued: Record<string, unknown>[] };
    const events = JSON.stringify(body.enqueued);
    expect(events).toMatch(/consent\.revoked|CONSENT_REVOKED/i);
    expect(events).not.toMatch(/@|\bRUT\b|\d{7,8}-[\dkK]/);
  });

  test("E2E-CNS-054 tras APPLIED, el enlace de gestión muestra 'Tu consentimiento ya fue retirado.' sin acción de retiro pendiente (UX-CNS-004)", async ({ page, app }) => {
    const mgmt = await reachRevocationConfirm(page, app);
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Retiramos tu consentimiento" })).toBeVisible();
    await page.goto(mgmt);
    await expect(page.getByRole("status").filter({ hasText: "Tu consentimiento ya fue retirado." })).toBeVisible();
    await expect(page.getByRole("link", { name: "Contactar a soporte" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Retirar mi consentimiento" })).toHaveCount(0);
  });

  test("E2E-CNS-055 'Cancelar solicitud de retiro': 'Cancelamos tu solicitud de retiro', el consentimiento sigue vigente (UX-CNS-004, API-CNS-133)", async ({ page, app }) => {
    const mgmt = await reachRevocationConfirm(page, app);
    await page.getByRole("button", { name: "Cancelar solicitud de retiro" }).click();
    const h1 = page.getByRole("heading", { level: 1, name: "Cancelamos tu solicitud de retiro" });
    await expect(h1).toBeVisible();
    await expect(h1).toBeFocused();
    await expect(page.getByText("Tu consentimiento sigue vigente.")).toBeVisible();
    // sigue vigente: el enlace de gestión no dice "ya fue retirado"
    await page.goto(mgmt);
    await expect(page.getByText("Tu consentimiento ya fue retirado.")).toHaveCount(0);
  });

  test("E2E-CNS-056 ERR-RV-21 (copy interino): ante 503 en confirmar se muestra 'No pudimos completar tu retiro', código ERR-RV-21, role=alert con foco y salidas (UX-CNS-015)", async ({ page, app }) => {
    await reachRevocationConfirm(page, app);
    await app.forceApplyFailure(page, "/manage/revocation/confirm");
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    const alert = page.getByRole("alert").filter({ hasText: "No pudimos completar tu retiro" });
    await expect(alert).toBeVisible();
    await expect(alert).toBeFocused();
    await expect(alert).toContainText("Tu autorización sigue vigente");
    await expect(alert).toContainText("Código: ERR-RV-21");
    await expect(alert.getByRole("link", { name: "Empezar de nuevo" })).toHaveAttribute("href", "/manage");
    await expect(alert.getByRole("link", { name: "Escribir al equipo del estudio" })).toHaveAttribute("href", /^mailto:/);
    await expect(page.getByRole("heading", { name: "Retiramos tu consentimiento" })).toBeHidden();
  });

  test("E2E-CNS-057 ERR-RV-21: 'Empezar de nuevo' vuelve a /manage y el retiro puede completarse con un OTP nuevo (UX-CNS-015)", async ({ page, app }) => {
    await reachRevocationConfirm(page, app);
    await app.forceApplyFailure(page, "/manage/revocation/confirm");
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    await page.getByRole("alert").filter({ hasText: "No pudimos completar tu retiro" }).getByRole("link", { name: "Empezar de nuevo" }).click();
    await expect(page).toHaveURL(/\/manage$/);
  });

  test("E2E-CNS-058 hook de servidor para 503 del retiro (GUARD_EVALUATOR_UNAVAILABLE) y token/OTP no consumido tras 503", async () => {
    test.skip(true, "No automatizable sin hook: el proceso web no expone CNS_TEST_* ni inyección de fallo del apply-guard (solo platform/Postgres). E2E-CNS-056/057 cubren la UI con el 503 simulado en el navegador.");
  });

  test("E2E-CNS-059 GET /manage/revocation/confirm sin OTP de retiro verificado entrega el error uniforme en HTML (INV-CM-05)", async ({ page }) => {
    const res = await page.goto("/manage/revocation/confirm");
    expect(res!.status()).toBe(404);
    expect(res!.headers()["content-type"]).toContain("text/html");
    await expect(page.getByRole("alert")).toContainText("No pudimos continuar con este retiro.");
    await expect(page.getByRole("button", { name: "Confirmar retiro total" })).toHaveCount(0);
  });

  test("E2E-CNS-060 GET /manage/revocation/verify sin sesión entrega el error uniforme en HTML (INV-CM-05)", async ({ page }) => {
    const res = await page.goto("/manage/revocation/verify");
    expect(res!.status()).toBe(404);
    await expect(page.getByRole("alert")).toContainText("No pudimos continuar con esta verificación.");
  });

  test("E2E-CNS-061 error de red al confirmar: 'No pudimos conectar.' y 'Reintentar' completa el retiro (UX-CNS-004)", async ({ page, app }) => {
    await reachRevocationConfirm(page, app);
    await page.route("**/manage/revocation/confirm", (route) => route.abort("failed"), { times: 1 });
    await page.getByRole("button", { name: "Confirmar retiro total" }).click();
    const net = page.getByRole("alert").filter({ hasText: "No pudimos conectar." });
    await expect(net).toBeVisible();
    await net.getByRole("button", { name: "Reintentar" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Retiramos tu consentimiento" })).toBeVisible();
  });

  test("E2E-CNS-062 flujo de revocación operable solo con teclado (Tab/Enter/Space) desde /manage hasta APPLIED (WCAG 2.1.1, 2.4.3)", async ({ page, app }) => {
    await reachManageStatus(page, app);
    const retirar = page.getByRole("button", { name: "Retirar mi consentimiento" });
    await retirar.focus();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/\/manage\/revocation\/verify$/);
    const code = await app.readLatestOtp();
    await page.getByLabel("Código de verificación").focus();
    await page.keyboard.type(code);
    await page.getByRole("button", { name: "Verificar", exact: true }).focus();
    await page.keyboard.press("Space");
    await expect(page).toHaveURL(/\/manage\/revocation\/confirm$/);
    // orden de tabulación: Confirmar antes que Cancelar; ninguno oculto a teclado
    await page.getByRole("button", { name: "Confirmar retiro total" }).focus();
    await page.keyboard.press("Tab");
    await expect(page.getByRole("button", { name: "Cancelar solicitud de retiro" })).toBeFocused();
    await page.keyboard.press("Shift+Tab");
    await expect(page.getByRole("button", { name: "Confirmar retiro total" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { level: 1, name: "Retiramos tu consentimiento" })).toBeFocused();
  });
});
