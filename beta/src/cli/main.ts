// Gobierna: DEC de Carlos "Reconstrucción mínima" (2026-10-19) y plan v2 H1-09. Ejecutable: `node src/cli/main.ts <comando>` (script `npm run admin -- <comando>`), por SSH, por el operador.
// Entorno mínimo: CNS_ENVIRONMENT, CNS_DATABASE_URL, CNS_MAILER_DATABASE_URL. Solo con --run-worker-once se exige además la config completa (SMTP, allowlist).
import { loadConfig } from "../config.ts";
import { assertEnvironment } from "../db/assert-environment.ts";
import { assertPoolRoles, createPools } from "../db/pool.ts";
import { createSmtpMailer } from "../mail/smtp-mailer.ts";
import { readDataClass } from "../mail/recipient-policy.ts";
import { runCli } from "./cli.ts";

function need(name: string): string {
  const v = process.env[name];
  if (v === undefined || v.trim() === "") throw new Error(`${name} es obligatoria y no está definida.`);
  return v.trim();
}

async function main(): Promise<number> {
  const environment = need("CNS_ENVIRONMENT");
  if (environment !== "LOCAL" && environment !== "REAL") throw new Error("CNS_ENVIRONMENT debe ser LOCAL o REAL.");
  const appUrl = need("CNS_DATABASE_URL");
  const mailerUrl = need("CNS_MAILER_DATABASE_URL");
  if (appUrl === mailerUrl) throw new Error("CNS_MAILER_DATABASE_URL debe ser distinta de CNS_DATABASE_URL (otro rol).");
  const pools = createPools({ appUrl, mailerUrl });
  try {
    await assertEnvironment(pools.app, { environment });
    await assertPoolRoles(pools);
    const result = await runCli(process.argv.slice(2), {
      app: pools.app,
      mailer: pools.mailer,
      makeWorker: async () => {
        const config = loadConfig();
        return { mailer: createSmtpMailer(config), policy: { dataClass: await readDataClass(pools.app), allowlist: config.mailAllowlist } };
      },
    });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    return result.exitCode;
  } finally {
    await Promise.all([pools.app.end(), pools.mailer.end()]).catch(() => undefined);
  }
}

main().then(
  (code) => process.exit(code),
  (e: unknown) => {
    const err = e as { name?: string; message?: string };
    process.stderr.write(`ERROR: ${err.name ?? "Error"}: ${err.message ?? ""}\n`);
    process.exit(1);
  },
);
