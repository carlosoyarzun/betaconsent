// Gobierna: INV-CM-09 / OPEN-CM-10, revision lampone-security P2-6 (continuacion): claves de sesion y OTP sin default
// aleatorio. Una clave aleatoria por proceso invalida sesiones y OTP pendientes al reiniciar y no es determinista entre
// replicas. Cada proposito tiene su propia variable (no se reutiliza una para otra):
//   CNS_SESSION_SECRET  firma de la sesion y raiz HKDF de los handles/CSRF/sesiones CASE y STAFF (consent-flow-server.ts)
//   CNS_OTP_SECRET      HMAC del codigo OTP y del canal opaco (otp-challenge.ts)
// (CNS_CHAIN_REF_SECRET, CNS_DECISION_MAKER_REF_SECRET* y CNS_STAFF_ROSTER_CURSOR_SECRET viven en sus modulos.)
// Valor: base64 estricto de al menos 32 bytes. Los mensajes de error nunca incluyen valores de secretos.
// Sin proveedor de secretos ni SDK: solo variables de entorno.

export const SERVER_SECRET_MIN_BYTES = 32;

type Env = Readonly<Record<string, string | undefined>>;

/** Base64 estricto: ida y vuelta (re-encode == entrada, sin padding ni espacios de borde) y >= 32 bytes. */
function decodeStrictSecret(raw: string, name: string): Buffer {
  const secret = Buffer.from(raw, "base64");
  const norm = (x: string): string => x.trim().replace(/=+$/, "");
  if (norm(secret.toString("base64")) !== norm(raw) || secret.length < SERVER_SECRET_MIN_BYTES) {
    throw new Error(`${name} debe ser base64 valido de al menos ${SERVER_SECRET_MIN_BYTES} bytes. Abortando (fail-closed).`);
  }
  return secret;
}

/** Fuera de LOCAL, sin la variable: aborta. En LOCAL sin ella: `localFallback()` (explicito en el caller; datos sinteticos). */
export function loadRequiredServerSecret(env: Env, environment: string, name: string, localFallback: () => Buffer): Buffer {
  const raw = env[name];
  if (raw === undefined || raw === "") {
    if (environment !== "LOCAL") {
      throw new Error(`${name} es obligatorio fuera de LOCAL. Abortando (fail-closed).`);
    }
    return localFallback();
  }
  return decodeStrictSecret(raw, name);
}

export function loadSessionSecret(env: Env, environment: string, localFallback: () => Buffer): Buffer {
  return loadRequiredServerSecret(env, environment, "CNS_SESSION_SECRET", localFallback);
}

export function loadOtpSecret(env: Env, environment: string, localFallback: () => Buffer): Buffer {
  return loadRequiredServerSecret(env, environment, "CNS_OTP_SECRET", localFallback);
}
