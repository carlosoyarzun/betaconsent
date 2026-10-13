// Gobierna: ADR-010 rev. 4 §7 fila PR-6 (entrypoint del proceso platform; rol platform_rw), INV-DBR-02. Minimo en 6a: solo GET /healthz (sin rutas de login).
// Uso (LOCAL, datos sinteticos): CNS_ENVIRONMENT=LOCAL CNS_DATABASE_URL=postgresql://platform_rw:...@host:PORT/DB [CNS_PLATFORM_PORT=8788] node src/server/entrypoints/platform/main.ts
// Exit: 0 parada ordenada, 1 arranque fallido (fail-closed; sin detalles ni secretos).

import { startPlatformProcess } from "./platform-process.ts";

try {
  const proc = await startPlatformProcess();
  for (const sig of ["SIGINT", "SIGTERM"] as const) process.once(sig, () => void proc.stop().then(() => process.exit(0)));
  console.log(`platform: escuchando en http://127.0.0.1:${proc.port} (rol platform_rw)`);
} catch (error) {
  console.error(`platform: no arranca (${(error as Error).name}). ${(error as Error).message}`);
  process.exitCode = 1;
}
