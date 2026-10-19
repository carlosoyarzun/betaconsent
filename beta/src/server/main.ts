// Gobierna: plan v2 H1-05 (arranque de producción, un solo proceso). Orden fail-closed: config -> pool consent_app -> assertEnvironment + assertRuntimeRole (F-SB-02)
// -> readDataClass -> outbox worker -> HTTP. SIGTERM/SIGINT: deja de aceptar, espera en vuelo (<= 10 s), para el worker y cierra el pool.
//
// Pool del mailer (coordinación P0 consent_mailer): si existe CNS_MAILER_DATABASE_URL se avisa que aún no se usa; hasta integrar la rama pr-a-mailer-role
// (createPgPorts(uow, {mailerUow}) y assertRuntimeRole(pool, rol)) todo corre por el pool consent_app.
import { loadConfig } from "../config.ts";
import { createPgPorts } from "../db/adapters/index.ts";
import { assertEnvironment } from "../db/assert-environment.ts";
import { assertRuntimeRole } from "../db/assert-runtime-role.ts";
import { createPool } from "../db/pool.ts";
import { PgUnitOfWork } from "../db/unit-of-work.ts";
import { createSmtpMailer } from "../mail/smtp-mailer.ts";
import { enqueueEmail, startOutboxWorker } from "../mail/outbox-worker.ts";
import { readDataClass } from "../mail/recipient-policy.ts";
import { createApp } from "./app.ts";
import { MANAGE_TOKEN_TTL_SECONDS, signManageToken } from "./handles.ts";
import { startHttpServer } from "./http-server.ts";
import { createJsonLogger } from "./log.ts";
import { createPgRecipientLookup } from "./recipients.ts";
import { loadSpaBundle } from "./spa-assets.ts";

async function main(): Promise<void> {
  const logger = createJsonLogger();
  const config = loadConfig();
  const pool = createPool({ connectionString: config.databaseUrl });
  try {
    await assertEnvironment(pool, config);
    await assertRuntimeRole(pool);
    const dataClass = await readDataClass(pool);
    if (process.env.CNS_MAILER_DATABASE_URL) logger.warn("CNS_MAILER_DATABASE_URL definida pero el pool del mailer aún no está integrado: se usa el pool de consent_app");
    else logger.warn("sin CNS_MAILER_DATABASE_URL: OTP e invitaciones usan el pool de consent_app");

    const mailer = createSmtpMailer(config);
    const policy = { dataClass, allowlist: config.mailAllowlist };
    const manageLinkPath = (consentId: string): string => `/m/${signManageToken(config.sessionSecret, consentId, Math.floor(Date.now() / 1000) + MANAGE_TOKEN_TTL_SECONDS)}`;
    const stopWorker = startOutboxWorker({ db: pool, mailer, policy, logger, manageLinkPath });
    const spa = process.env.CNS_SPA_DIST_DIR ? loadSpaBundle(process.env.CNS_SPA_DIST_DIR) : loadSpaBundle(); // CNS_SPA_DIST_DIR: solo para pruebas
    const app = createApp({
      config,
      ports: createPgPorts(new PgUnitOfWork(pool)),
      recipients: createPgRecipientLookup(pool),
      mailer,
      policy,
      outbox: { enqueue: async (i) => void (await enqueueEmail(pool, i)) },
      spa,
      logger,
      checkHealth: async () => void (await pool.query("SELECT 1")),
    });
    const running = await startHttpServer({ app, bind: config.bind, port: config.port, logger, requireSecure: config.environment === "REAL" });
    logger.info("servidor escuchando", { port: running.port, environment: config.environment });

    let closing = false;
    const shutdown = (signal: string): void => {
      if (closing) return;
      closing = true;
      logger.info("cierre ordenado", { signal });
      void running
        .close(10_000)
        .then(() => stopWorker())
        .then(() => pool.end())
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
    };
    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  } catch (e) {
    await pool.end().catch(() => undefined);
    throw e;
  }
}

main().catch((e: unknown) => {
  // Solo el nombre y el mensaje de los gates propios (no incluyen secretos ni valores).
  const err = e as { name?: string; message?: string };
  process.stderr.write(`ARRANQUE ABORTADO: ${err.name ?? "Error"}: ${err.message ?? ""}\n`);
  process.exit(1);
});
