// Suite E2E de la UI de titulares (SPA, único modo tras el retiro del SSR; ADR-001 F1). Requiere `npm run build:frontend` (dist/).
// Cero PII: solo datos sintéticos del entrypoint LOCAL (dev.ts).
//
// Modos:
//  - Por defecto (sin E2E_BASE_URL): cada test arranca su propio `dev.ts` (store en memoria, puerto libre)
//    desde e2e/fixtures/index.ts; estado aislado por test, sin base de datos.
//  - E2E_BASE_URL=http://host:puerto: apunta a un servidor ya levantado (p. ej. `node src/server/entrypoints/dev.ts` con `dist/` construido).
//  - E2E_START_SERVER=1: levanta UN dev.ts compartido (webServer) en 127.0.0.1:3000 y lo usa como externo.
import { defineConfig, devices } from "@playwright/test";

const external = process.env.E2E_BASE_URL !== undefined || process.env.E2E_START_SERVER === "1";
const baseURL = process.env.E2E_BASE_URL ?? "http://127.0.0.1:3000";

export default defineConfig({
  testDir: "./specs",
  outputDir: "./test-results",
  fullyParallel: !external,
  workers: external ? 1 : undefined,
  retries: 0,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  reporter: [["list"], ["html", { outputFolder: "./report", open: "never" }]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    locale: "es-CL",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer:
    process.env.E2E_START_SERVER === "1"
      ? {
          command: "node src/server/entrypoints/dev.ts",
          cwd: "..",
          url: baseURL,
          env: { CNS_ENVIRONMENT: "LOCAL", PORT: "3000" },
          reuseExistingServer: false,
          timeout: 30_000,
        }
      : undefined,
});
