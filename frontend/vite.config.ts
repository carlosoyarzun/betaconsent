// Gobierna: ADR-001 rev. 8 F1 (React + TypeScript estricto, SPA estática servida por el backend) y §3 (CSP sin inline).
// Build a ../dist con nombres con hash, sin polyfill de modulepreload (inyectaría JS inline), sin assets embebidos
// como data: y con el CSS en UN archivo. Vitest comparte este archivo (jsdom).
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const BACKEND = process.env.CNS_DEV_BACKEND ?? "http://127.0.0.1:3000";

/** Rutas HTML de los titulares: en `dev:frontend` las sirve Vite (SPA); todo lo demás va al backend. */
const PAGE_PATHS = new Set([
  "/welcome",
  "/verify",
  "/decision",
  "/manage",
  "/manage/verify",
  "/manage/revocation/verify",
  "/manage/revocation/confirm",
  "/recovery/confirm",
]);

export default defineConfig({
  root: import.meta.dirname,
  plugins: [react()],
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    manifest: true,
    sourcemap: false,
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      // API JSON, canjes 303 (/i /m /r) y sinks dev -> backend. El navegador envía Origin del dev server; se reescribe al
      // del backend para pasar GRD-CM-10 sin tocar CNS_ALLOWED_ORIGIN (ver frontend/README.md, limitaciones).
      "^/(invitation|otp|decision|manage|recovery|rights-case|i|m|r|__dev)(/|$)": {
        target: BACKEND,
        changeOrigin: false,
        bypass(req) {
          const path = (req.url ?? "").split("?", 1)[0] ?? "";
          if (req.method === "GET" && PAGE_PATHS.has(path)) return "/index.html";
          return undefined;
        },
        configure(proxy) {
          proxy.on("proxyReq", (proxyReq) => {
            if (proxyReq.getHeader("origin")) proxyReq.setHeader("origin", BACKEND);
          });
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    environmentOptions: { jsdom: { url: "https://localhost/" } }, // las cookies __Host- exigen origen seguro
    include: ["tests/**/*.test.{ts,tsx}"],
    setupFiles: ["tests/setup.ts"],
    restoreMocks: true,
  },
});
