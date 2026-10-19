// Gobierna: DEC de Carlos "Reconstrucción mínima de Consent App para un colegio beta" (2026-10-19), plan v2 H1-01.
// origen (ideas): src/server/entrypoints/http/server-secrets.config.ts@9345b78 (secretos base64 >=32 bytes, distintos entre sí)
// y src/server/entrypoints/http/config.ts@9345b78 (origen permitido sin default, fail-closed).
//
// Config por entorno con lista NOMINAL de variables: si falta una, el proceso aborta con un mensaje que
// nombra la variable (nunca su valor). Sin proveedor de secretos: solo variables de entorno.
// CNS_CSRF_SECRET no existe: el CSRF se deriva por HKDF de CNS_SESSION_SECRET (como en el repo raíz).

export type Environment = "LOCAL" | "REAL";

export interface ApiKey {
  readonly keyId: string;
  readonly secret: Buffer;
}

export interface Config {
  readonly environment: Environment;
  readonly databaseUrl: string;
  readonly sessionSecret: Buffer;
  readonly publicOrigin: string;
  readonly smtpUrl: string;
  readonly smtpFrom: string;
  /** Entradas `correo@dominio` o `@dominio` en minúsculas. En LOCAL solo se envía a ellas. */
  readonly mailAllowlist: readonly string[];
  /** 1 o 2 claves activas (rotación sin corte). */
  readonly apiKeys: readonly ApiKey[];
  readonly port: number;
  readonly bind: string;
}

type Env = Readonly<Record<string, string | undefined>>;

/** Nombres exigidos, en el orden en que se validan. */
export const REQUIRED_VARIABLES = [
  "CNS_ENVIRONMENT",
  "CNS_DATABASE_URL",
  "CNS_SESSION_SECRET",
  "CNS_PUBLIC_ORIGIN",
  "CNS_SMTP_URL",
  "CNS_SMTP_FROM",
  "CNS_MAIL_ALLOWLIST",
  "CNS_API_KEYS",
  "PORT",
  "BIND",
] as const;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

function required(env: Env, name: (typeof REQUIRED_VARIABLES)[number]): string {
  const v = env[name];
  if (v === undefined || v.trim() === "") throw new ConfigError(`${name} es obligatoria y no está definida. Abortando (fail-closed).`);
  return v.trim();
}

function decodeSecret(raw: string, name: string): Buffer {
  if (raw.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw) || Buffer.from(raw, "base64").length < 32) {
    throw new ConfigError(`${name} debe ser base64 estricto de al menos 32 bytes. Abortando (fail-closed).`);
  }
  return Buffer.from(raw, "base64");
}

export function loadConfig(env: Env = process.env): Config {
  const missing = REQUIRED_VARIABLES.filter((n) => env[n] === undefined || env[n]?.trim() === "");
  if (missing.length > 0) throw new ConfigError(`Faltan variables obligatorias: ${missing.join(", ")}. Abortando (fail-closed).`);

  const environment = required(env, "CNS_ENVIRONMENT");
  if (environment !== "LOCAL" && environment !== "REAL") throw new ConfigError("CNS_ENVIRONMENT debe ser LOCAL o REAL. Abortando (fail-closed).");

  const databaseUrl = required(env, "CNS_DATABASE_URL");
  if (!/^postgres(ql)?:\/\//.test(databaseUrl)) throw new ConfigError("CNS_DATABASE_URL debe empezar por postgresql://. Abortando (fail-closed).");

  const sessionSecret = decodeSecret(required(env, "CNS_SESSION_SECRET"), "CNS_SESSION_SECRET");

  const publicOrigin = required(env, "CNS_PUBLIC_ORIGIN");
  let origin: URL;
  try {
    origin = new URL(publicOrigin);
  } catch {
    throw new ConfigError("CNS_PUBLIC_ORIGIN no es una URL válida. Abortando (fail-closed).");
  }
  if (origin.origin !== publicOrigin || (environment === "REAL" && origin.protocol !== "https:")) {
    throw new ConfigError("CNS_PUBLIC_ORIGIN debe ser un origen exacto (sin ruta ni barra final) y https en REAL. Abortando (fail-closed).");
  }

  const smtpUrl = required(env, "CNS_SMTP_URL");
  if (!/^smtps?:\/\//.test(smtpUrl)) throw new ConfigError("CNS_SMTP_URL debe empezar por smtp:// o smtps://. Abortando (fail-closed).");
  const smtpFrom = required(env, "CNS_SMTP_FROM");
  if (!/^[^@\s]+@[^@\s]+$/.test(smtpFrom)) throw new ConfigError("CNS_SMTP_FROM debe ser una dirección de correo. Abortando (fail-closed).");

  const mailAllowlist = required(env, "CNS_MAIL_ALLOWLIST")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s !== "");
  if (mailAllowlist.length === 0 || mailAllowlist.some((e) => !/^([^@\s]+)?@[^@\s]+$/.test(e))) {
    throw new ConfigError("CNS_MAIL_ALLOWLIST debe listar correos o @dominios separados por coma. Abortando (fail-closed).");
  }

  const apiKeys = required(env, "CNS_API_KEYS")
    .split(",")
    .map((entry): ApiKey => {
      const [keyId, secret, ...rest] = entry.trim().split(":");
      if (!keyId || !secret || rest.length > 0 || !/^[A-Za-z0-9_-]{1,40}$/.test(keyId)) {
        throw new ConfigError("CNS_API_KEYS debe tener la forma keyId:secretoBase64[,keyId2:secretoBase64]. Abortando (fail-closed).");
      }
      return { keyId, secret: decodeSecret(secret, "CNS_API_KEYS") };
    });
  if (apiKeys.length > 2 || new Set(apiKeys.map((k) => k.keyId)).size !== apiKeys.length) {
    throw new ConfigError("CNS_API_KEYS admite 1 o 2 claves con keyId distinto. Abortando (fail-closed).");
  }

  const port = Number(required(env, "PORT"));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new ConfigError("PORT debe ser un entero entre 1 y 65535. Abortando (fail-closed).");
  const bind = required(env, "BIND");

  return { environment, databaseUrl, sessionSecret, publicOrigin, smtpUrl, smtpFrom, mailAllowlist, apiKeys, port, bind };
}
