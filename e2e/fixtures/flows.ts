// Flujos compuestos sobre la UI (solo selectores semánticos).
import { expect, type Page } from "@playwright/test";
import type { App } from "./index.ts";

export const WELCOME_H1 = "Bienvenida a la invitación";

/** /i/<token> -> 303 -> /welcome. */
export async function openInvitation(page: Page, app: App): Promise<void> {
  await page.goto(await app.invitationPath());
  await expect(page).toHaveURL(/\/welcome$/);
}

export async function typeOtp(page: Page, code: string): Promise<void> {
  await page.getByLabel("Código de verificación").fill(code);
  await page.getByRole("button", { name: "Verificar", exact: true }).click();
}

/** Welcome -> Continuar -> /verify con OTP emitido. */
export async function continueToVerify(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Continuar" }).click();
  await expect(page).toHaveURL(/\/verify$/);
}

/** Invitación -> OTP correcto -> /decision. */
export async function reachDecision(page: Page, app: App): Promise<void> {
  await openInvitation(page, app);
  await continueToVerify(page);
  await typeOtp(page, await app.readLatestOtp());
  await expect(page).toHaveURL(/\/decision$/);
}

/** Rellena /decision con las 4 finalidades aceptadas (o rechazando `decline`). */
export async function fillDecision(page: Page, opts: { decline?: boolean } = {}): Promise<void> {
  await page.getByRole("radio", { name: "Sí, es correcto" }).click();
  await page.getByLabel("¿Cuál es tu relación con el estudiante?").selectOption({ index: 1 });
  await page.getByRole("checkbox").check();
  for (const title of ["Participar en el Estudio Beta", "Grabación de audio", "Análisis automatizado", "Revisión humana"]) {
    const group = page.getByRole("radiogroup", { name: title });
    const decline = opts.decline === true && title === "Revisión humana";
    await group.getByRole("radio", { name: decline ? "No acepto" : "Acepto", exact: true }).click();
  }
}

/** Decisión GRANTED por la UI -> enlace /m/<token> real del sink -> Verificar identidad -> OTP -> /manage (estado). */
export async function reachManageStatus(page: Page, app: App): Promise<string> {
  const mgmt = await app.createManagementLink(page);
  await page.goto(mgmt);
  await expect(page).toHaveURL(/\/manage$/);
  await page.getByRole("button", { name: "Verificar mi identidad" }).click();
  await expect(page).toHaveURL(/\/manage\/verify$/);
  await typeOtp(page, await app.readLatestOtp());
  await expect(page).toHaveURL(/\/manage$/);
  await expect(page.getByRole("button", { name: "Retirar mi consentimiento" })).toBeVisible();
  return mgmt;
}

/** /manage (estado) -> Retirar -> OTP -> /manage/revocation/confirm. */
export async function reachRevocationConfirm(page: Page, app: App): Promise<string> {
  const mgmt = await reachManageStatus(page, app);
  await page.getByRole("button", { name: "Retirar mi consentimiento" }).click();
  await expect(page).toHaveURL(/\/manage\/revocation\/verify$/);
  await typeOtp(page, await app.readLatestOtp());
  await expect(page).toHaveURL(/\/manage\/revocation\/confirm$/);
  return mgmt;
}

export type PageVisit = (name: string) => Promise<void>;

/**
 * Recorre las 8 pantallas HTML del titular en su estado por defecto (200), invocando `visit(nombre)` en cada una.
 * Orden: /welcome, /verify, /decision, /manage (entrada), /manage/verify, /manage/revocation/verify,
 * /manage/revocation/confirm, /recovery/confirm. Usa el enlace de gestión REAL (ver F-E2E-01).
 */
export async function walkAllPages(page: Page, app: App, visit: PageVisit): Promise<void> {
  await openInvitation(page, app);
  await visit("/welcome");
  await continueToVerify(page);
  await visit("/verify");
  await typeOtp(page, await app.readLatestOtp());
  await expect(page).toHaveURL(/\/decision$/);
  await visit("/decision");
  await fillDecision(page);
  await page.getByRole("button", { name: "Enviar decisión" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Listo, registramos tu decisión" })).toBeVisible();
  await expect.poll(async () => (await app.guestMessages()).length).toBeGreaterThanOrEqual(2);
  const mgmt = (await app.guestMessages()).map((m) => /\/m\/[0-9A-Za-z_-]{8,}/.exec(m.text)?.[0]).find(Boolean)!;
  await page.goto(mgmt);
  await visit("/manage");
  await page.getByRole("button", { name: "Verificar mi identidad" }).click();
  await expect(page).toHaveURL(/\/manage\/verify$/);
  await visit("/manage/verify");
  await typeOtp(page, await app.readLatestOtp());
  await expect(page).toHaveURL(/\/manage$/);
  await page.getByRole("button", { name: "Retirar mi consentimiento" }).click();
  await expect(page).toHaveURL(/\/manage\/revocation\/verify$/);
  await visit("/manage/revocation/verify");
  await typeOtp(page, await app.readLatestOtp());
  await expect(page).toHaveURL(/\/manage\/revocation\/confirm$/);
  await visit("/manage/revocation/confirm");
  // recuperación: segundo titular (otra invitación), enlace /r/ real
  const link = await app.createRecoveryLink(page);
  await page.goto(link);
  await expect(page).toHaveURL(/\/recovery\/confirm$/);
  await visit("/recovery/confirm");
}
