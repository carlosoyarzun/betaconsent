// Fixtures Playwright: servidor LOCAL sintético por test + helpers de buzón (OTP, enlaces).
// Selectores de las specs: SOLO roles / nombres accesibles / texto visible (equivalencia SSR -> SPA).
import { test as base, expect, type Page } from "@playwright/test";
import { startDevServer, type DevServer } from "./dev-server.ts";
import { createInvitation, readGuestMessages, readLatestOtp, readOtps, readRecoveryPaths } from "./sinks.ts";

export interface App {
  readonly baseURL: string;
  /** Ruta /i/<token> de la invitación sembrada (1.ª llamada) o creada por el flujo STAFF (siguientes). */
  invitationPath(): Promise<string>;
  /** Ruta /m/<token> sobre la decisión GRANTED sembrada por dev.ts (literal fijo LOCAL). */
  readonly managementPath: string;
  /**
   * Ruta /m/<token> REAL de gestión: completa el flujo de decisión por la UI en `page` y lee el enlace del message-sink (D-03).
   * El enlace sembrado (`managementPath`) no sirve para verificar OTP en LOCAL: ver E2E-CNS-047 (hallazgo F-E2E-01).
   */
  createManagementLink(page: Page): Promise<string>;
  createInvitation(student?: number): Promise<string>;
  readLatestOtp(): Promise<string>;
  otpCount(): Promise<number>;
  /** Pide un enlace de recuperación (POST /manage/recovery-link con el handle de gestión de `page`) y devuelve /r/<token>. */
  createRecoveryLink(page: Page): Promise<string>; // requiere un enlace de gestión real: recorre antes el flujo de decisión en `page`
  guestMessages(): ReturnType<typeof readGuestMessages>;
  /**
   * No existe hook de servidor para forzar el 503 (GUARD_EVALUATOR_UNAVAILABLE) en el proceso web (grep CNS_TEST_*: 0).
   * Sustituto a nivel de navegador: intercepta el POST y responde 503 uniforme (misma forma que revocation-flow.handler.ts:72).
   * Verifica la UI ante el 503, no el servidor (no sirve para "token no consumido").
   */
  forceApplyFailure(page: Page, path: "/manage/revocation/confirm" | "/recovery/revoke"): Promise<void>;
}

// Contador de alumnos sintéticos del modo externo (servidor compartido: 6 por arranque, workers=1).
let nextStudent = 0;

const external = process.env.E2E_BASE_URL !== undefined || process.env.E2E_START_SERVER === "1";

export const test = base.extend<{ server: DevServer | null; app: App }>({
  server: async ({}, use) => {
    if (external) return use(null);
    const s = await startDevServer();
    await use(s);
    await s.stop();
  },
  baseURL: async ({ server, baseURL }, use) => use(server ? server.baseURL : baseURL),
  app: async ({ server, baseURL }, use) => {
    const url = baseURL!;
    let seededUsed = false;
    const app: App = {
      baseURL: url,
      managementPath: server?.managementPath ?? process.env.E2E_MANAGEMENT_PATH ?? "/m/dev-mgmt-token-001",
      async invitationPath() {
        if (server && !seededUsed) { seededUsed = true; return server.seededInvitationPath; }
        return createInvitation(url, nextStudent++);
      },
      async createManagementLink(page) {
        const { reachDecision, fillDecision } = await import("./flows.ts");
        await reachDecision(page, app);
        await fillDecision(page);
        await page.getByRole("button", { name: "Enviar decisión" }).click();
        await expect(page.getByRole("heading", { level: 1, name: "Listo, registramos tu decisión" })).toBeVisible();
        await expect.poll(async () => (await readGuestMessages(url)).length).toBeGreaterThanOrEqual(2);
        const msgs = await readGuestMessages(url);
        for (const m of msgs) {
          const hit = /\/m\/[0-9A-Za-z_-]{8,}/.exec(m.text);
          if (hit) return hit[0];
        }
        throw new Error("el message-sink no contiene enlace de gestión");
      },
      createInvitation: (student) => createInvitation(url, student ?? nextStudent++),
      readLatestOtp: () => readLatestOtp(url),
      otpCount: async () => (await readOtps(url)).length,
      guestMessages: () => readGuestMessages(url),
      async createRecoveryLink(page) {
        const before = (await readRecoveryPaths(url)).length;
        // Con el enlace de gestión REAL (el sembrado no sirve en LOCAL: F-E2E-01).
        await page.goto(await app.createManagementLink(page));
        const status = await page.evaluate(async () => {
          const csrf = document.cookie.split(";").map((c) => c.trim()).find((c) => c.startsWith("__Host-cns-csrf="));
          const res = await fetch("/manage/recovery-link", {
            method: "POST",
            headers: { "content-type": "application/json", ...(csrf ? { "x-csrf-token": decodeURIComponent(csrf.split("=")[1]!) } : {}) },
            body: "{}",
            credentials: "same-origin",
          });
          return res.status;
        });
        expect(status, "POST /manage/recovery-link debe responder 202 uniforme").toBe(202);
        const all = await readRecoveryPaths(url);
        expect(all.length, "el recovery-sink debe recibir el enlace").toBeGreaterThan(before);
        return all.at(-1)!;
      },
      async forceApplyFailure(page, path) {
        await page.route(`**${path}`, (route) =>
          route.request().method() === "POST"
            ? route.fulfill({ status: 503, contentType: "application/problem+json", body: JSON.stringify({ code: "GUARD_EVALUATOR_UNAVAILABLE", status: 503, correlationId: "00000000-0000-4000-8000-000000000000" }) })
            : route.continue(),
        );
      },
    };
    await use(app);
  },
});

export { expect };
