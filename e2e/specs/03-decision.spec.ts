// Ruta /decision: UX-CNS-003, REQ-CNS-004 (consentimiento por finalidad), GRD-CD-03/04, API-CNS-106..109, INV-CM-05/08.
import { test, expect } from "../fixtures/index.ts";
import { fillDecision, openInvitation, reachDecision } from "../fixtures/flows.ts";

const PURPOSES = ["Participar en el Estudio Beta", "Grabación de audio", "Análisis automatizado", "Revisión humana"];

test.describe("decision", () => {
  test("E2E-CNS-023 /decision muestra paso 2 de 3, texto y versión del consentimiento, alumno sintético y 4 finalidades (UX-CNS-003, GRD-CD-03)", async ({ page, app }) => {
    await reachDecision(page, app);
    await expect(page.getByRole("heading", { level: 1, name: "Revisa y decide" })).toBeVisible();
    await expect(page.getByText("Paso 2 de 3 · Revisa y decide")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Texto del consentimiento" })).toBeVisible();
    await expect(page.getByText(/Versión vigente del texto: .+ · Aviso de privacidad: .+/)).toBeVisible();
    await expect(page.getByText(/^Alumno de prueba \d+ · Colegio Ejemplo$/)).toBeVisible();
    for (const title of PURPOSES) {
      const group = page.getByRole("radiogroup", { name: title });
      await expect(group.getByRole("radio", { name: "Acepto", exact: true })).toBeVisible();
      await expect(group.getByRole("radio", { name: "No acepto", exact: true })).toBeVisible();
    }
    await expect(page.getByLabel("¿Cuál es tu relación con el estudiante?")).toBeVisible();
    await expect(page.getByRole("checkbox")).toBeVisible();
  });

  test("E2E-CNS-024 'Enviar decisión' parte deshabilitado (aria-disabled) con ayuda de estado y se habilita al completar todo (UX-CNS-003)", async ({ page, app }) => {
    await reachDecision(page, app);
    const submit = page.getByRole("button", { name: "Enviar decisión" });
    await expect(submit).toHaveAttribute("aria-disabled", "true");
    await expect(page.getByText("Completa todas las secciones para continuar.")).toBeVisible();
    await fillDecision(page);
    await expect(submit).not.toHaveAttribute("aria-disabled", "true");
  });

  test("E2E-CNS-025 enviar incompleto muestra 'Falta completar algo antes de enviar.' con role=alert y no registra la decisión (UX-CNS-003)", async ({ page, app }) => {
    await reachDecision(page, app);
    await page.getByRole("radio", { name: "Sí, es correcto" }).click();
    // aria-disabled="true" hace que Playwright espere "habilitado": force para pulsar el botón anunciado como deshabilitado.
    await page.getByRole("button", { name: "Enviar decisión" }).click({ force: true });
    const alert = page.getByRole("alert").filter({ hasText: "Falta completar algo antes de enviar." });
    await expect(alert).toBeVisible();
    await expect(page).toHaveURL(/\/decision$/);
    await expect(page.getByRole("heading", { name: "Listo, registramos tu decisión" })).toBeHidden();
  });

  test("E2E-CNS-026 aceptar las 4 finalidades: confirmación 'Listo, registramos tu decisión', comprobante, marca IT0 y foco en el título (UX-CNS-003, WCAG 2.4.3)", async ({ page, app }) => {
    await reachDecision(page, app);
    await fillDecision(page);
    await page.getByRole("button", { name: "Enviar decisión" }).click();
    const h1 = page.getByRole("heading", { level: 1, name: "Listo, registramos tu decisión" });
    await expect(h1).toBeVisible();
    await expect(h1).toBeFocused();
    await expect(page.getByText("Paso 3 de 3 · Registro").filter({ visible: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Comprobante" })).toBeVisible();
    await expect(page.getByText("Registrado", { exact: true }).filter({ visible: true })).toBeVisible();
    await expect(page.getByText("Marca de agua IT0 · comprobante de prueba").filter({ visible: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Qué pasa ahora" })).toBeVisible();
    // el enlace de gestión nunca se muestra en pantalla
    await expect(page.locator("main")).not.toContainText(/\/m\/[0-9a-z-]{8,}/);
  });

  test("E2E-CNS-027 al aceptar, el sink recibe comprobante y, aparte, el enlace de gestión (UX-CNS-006/006b, D-03)", async ({ page, app }) => {
    await reachDecision(page, app);
    await fillDecision(page);
    await page.getByRole("button", { name: "Enviar decisión" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Listo, registramos tu decisión" })).toBeVisible();
    await expect.poll(async () => (await app.guestMessages()).length).toBe(2);
    const msgs = await app.guestMessages();
    const withLink = msgs.filter((m) => /\/m\/[0-9a-zA-Z_-]{8,}/.test(m.text));
    expect(withLink, "exactamente un mensaje lleva el enlace de gestión").toHaveLength(1);
    expect(msgs.filter((m) => !/\/m\/[0-9a-zA-Z_-]{8,}/.test(m.text)), "el comprobante no lleva enlace").toHaveLength(1);
    for (const m of msgs) expect(m.recipientChannelRef).toMatch(/@example\.invalid$/);
  });

  test("E2E-CNS-028 no aceptar una finalidad: aviso previo y confirmación 'Registramos tu decisión' (el estudiante no participará) (UX-CNS-003, Q-13)", async ({ page, app }) => {
    await reachDecision(page, app);
    await fillDecision(page, { decline: true });
    await expect(page.getByRole("status").filter({ hasText: "Elegiste no aceptar al menos una finalidad." })).toBeVisible();
    await page.getByRole("button", { name: "Enviar decisión" }).click();
    const h1 = page.getByRole("heading", { level: 1, name: "Registramos tu decisión" });
    await expect(h1).toBeVisible();
    await expect(h1).toBeFocused();
    await expect(page.getByText("El estudiante no participará en el Estudio Beta.", { exact: true })).toBeVisible();
    await expect(page.getByText("Registrado", { exact: true }).filter({ visible: true })).toBeVisible();
  });

  test("E2E-CNS-029 'No es mi estudiante' (subject mismatch): aviso, 'Informar…' cancela la invitación y no registra decisión (UX-CNS-003, API-CNS-109)", async ({ page, app }) => {
    await reachDecision(page, app);
    await page.getByRole("radio", { name: "No es mi estudiante" }).click();
    const note = page.getByRole("alert").filter({ hasText: "No podemos continuar si no es tu estudiante." });
    await expect(note).toBeVisible();
    await note.getByRole("button", { name: "Informar que no es mi estudiante" }).click();
    const h1 = page.getByRole("heading", { level: 1, name: "Registramos tu aviso" });
    await expect(h1).toBeVisible();
    await expect(h1).toBeFocused();
    await expect(page.getByText("Cancelamos esta invitación.")).toBeVisible();
    await expect(page.getByText("No se registró ninguna decisión.")).toBeVisible();
    // la invitación quedó cancelada: la sesión ya no sirve para /decision
    const res = await page.goto("/decision");
    expect(res!.status()).toBe(404);
  });

  test("E2E-CNS-030 tras registrar la decisión, volver a /decision entrega el error uniforme (INV-CM-05, no doble envío)", async ({ page, app }) => {
    await reachDecision(page, app);
    await fillDecision(page);
    await page.getByRole("button", { name: "Enviar decisión" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Listo, registramos tu decisión" })).toBeVisible();
    const res = await page.goto("/decision");
    expect(res!.status()).toBe(404);
    await expect(page.getByRole("alert")).toContainText("No pudimos continuar con esta decisión.");
  });

  test("E2E-CNS-031 invitación COMPLETADA: reabrir /i/{token} en otro contexto no permite continuar (INV-CM-05)", async ({ page, app, browser }) => {
    const path = await app.invitationPath();
    await page.goto(path);
    await page.getByRole("button", { name: "Continuar" }).click();
    await expect(page).toHaveURL(/\/verify$/);
    await page.getByLabel("Código de verificación").fill(await app.readLatestOtp());
    await page.getByRole("button", { name: "Verificar", exact: true }).click();
    await expect(page).toHaveURL(/\/decision$/);
    await fillDecision(page);
    await page.getByRole("button", { name: "Enviar decisión" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Listo, registramos tu decisión" })).toBeVisible();
    const ctx2 = await browser.newContext({ baseURL: app.baseURL });
    const page2 = await ctx2.newPage();
    await page2.goto(path);
    await page2.getByRole("button", { name: "Continuar" }).click();
    await expect(page2.getByRole("alert").filter({ hasText: "No pudimos abrir esta invitación." })).toBeVisible();
    await expect(page2).not.toHaveURL(/\/verify$/);
    await ctx2.close();
  });

  test("E2E-CNS-032 GET /decision sin sesión verificada entrega el error uniforme en HTML (INV-CM-05)", async ({ page, app }) => {
    await openInvitation(page, app);
    const res = await page.goto("/decision");
    expect(res!.status()).toBe(404);
    expect(res!.headers()["content-type"]).toContain("text/html");
    await expect(page.getByRole("alert")).toContainText("No pudimos continuar con esta decisión.");
  });

  test("E2E-CNS-033 error de red al enviar: 'No pudimos conectar.' y 'Reintentar' registra la decisión (UX-CNS-003)", async ({ page, app }) => {
    await reachDecision(page, app);
    await fillDecision(page);
    await page.route("**/decision/submit", (route) => route.abort("failed"), { times: 1 });
    await page.getByRole("button", { name: "Enviar decisión" }).click();
    const net = page.getByRole("alert").filter({ hasText: "No pudimos conectar." });
    await expect(net).toBeVisible();
    await net.getByRole("button", { name: "Reintentar" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Listo, registramos tu decisión" })).toBeVisible();
  });

  test("E2E-CNS-034 los controles del formulario son operables con teclado (radios, casilla, select) (WCAG 2.1.1)", async ({ page, app }) => {
    await reachDecision(page, app);
    const yes = page.getByRole("radio", { name: "Sí, es correcto" });
    await yes.focus();
    await page.keyboard.press("Space");
    await expect(yes).toHaveAttribute("aria-checked", "true");
    const box = page.getByRole("checkbox");
    await box.focus();
    await page.keyboard.press("Space");
    await expect(box).toBeChecked();
    const accept = page.getByRole("radiogroup", { name: PURPOSES[0]! }).getByRole("radio", { name: "Acepto", exact: true });
    await accept.focus();
    await page.keyboard.press("Space");
    await expect(accept).toHaveAttribute("aria-checked", "true");
  });
});
