// Gobierna: plan v2 H1-05 + SEC-CNS-024-V1 (arranque de producción, un solo proceso, DOS pools). Orden fail-closed: config -> createPools({appUrl, mailerUrl}) ->
// assertEnvironment + assertPoolRoles (app = consent_app, mailer = consent_mailer; F-SB-02) -> readDataClass -> outbox worker (pool mailer) -> HTTP.
// SIGTERM/SIGINT: deja de aceptar, espera en vuelo (<= 10 s), para el worker y cierra ambos pools.
// Pool app (HTTP): sin acceso a secretos. Pool mailer: issue_otp, arm_invitation_token, outbox y readGuardianEmail para enviar el OTP.
import { loadConfig } from "../config.ts";
import { createPgPorts } from "../db/adapters/index.ts";
import { assertEnvironment } from "../db/assert-environment.ts";
import { assertPoolRoles, createPools } from "../db/pool.ts";
import { PgUnitOfWork } from "../db/unit-of-work.ts";
import { readGuardianEmail } from "../mail/otp.ts";
import { createSmtpMailer } from "../mail/smtp-mailer.ts";
import { startOutboxWorker } from "../mail/outbox-worker.ts";
import { readDataClass } from "../mail/recipient-policy.ts";
import { createApp } from "./app.ts";
import { startHttpServer } from "./http-server.ts";
import { createJsonLogger } from "./log.ts";
import { createPgRecipientLookup } from "./recipients.ts";
import { loadSpaBundle } from "./spa-assets.ts";

async function main(): Promise<void> {
  const logger = createJsonLogger();
  const config = loadConfig();
  const pools = createPools({ appUrl: config.databaseUrl, mailerUrl: config.mailerDatabaseUrl });
  const pool = pools.app;
  try {
    await assertEnvironment(pools.app, config);
    await assertPoolRoles(pools); // antes de aceptar tráfico: app = consent_app y mailer = consent_mailer
    const dataClass = await readDataClass(pools.app);

    const mailer = createSmtpMailer(config);
    const policy = { dataClass, allowlist: config.mailAllowlist };
    const stopWorker = startOutboxWorker({ db: pools.mailer, mailer, policy, logger });
    const spa = process.env.CNS_SPA_DIST_DIR ? loadSpaBundle(process.env.CNS_SPA_DIST_DIR) : loadSpaBundle(); // CNS_SPA_DIST_DIR: solo para pruebas
    const app = createApp({
      config,
      ports: createPgPorts(new PgUnitOfWork(pools.app), { mailerUow: new PgUnitOfWork(pools.mailer) }),
      recipients: createPgRecipientLookup(pools.app),
      readGuardianEmail: (invitationRef) => readGuardianEmail(pools.mailer, invitationRef),
      mailer,
      policy,
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
        .then(() => Promise.all([pools.app.end(), pools.mailer.end()]))
        .then(() => process.exit(0))
        .catch(() => process.exit(1));
    };
    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
  } catch (e) {
    await Promise.all([pools.app.end(), pools.mailer.end()]).catch(() => undefined);
    throw e;
  }
}

main().catch((e: unknown) => {
  // Solo el nombre y el mensaje de los gates propios (no incluyen secretos ni valores).
  const err = e as { name?: string; message?: string };
  process.stderr.write(`ARRANQUE ABORTADO: ${err.name ?? "Error"}: ${err.message ?? ""}\n`);
  process.exit(1);
});
