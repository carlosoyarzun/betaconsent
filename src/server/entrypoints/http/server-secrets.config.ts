// Gobierna: INV-CM-09 / OPEN-CM-10, revision lampone-security P2-6 (continuacion): claves de sesion y OTP sin default
// aleatorio. Una clave aleatoria por proceso invalida sesiones y OTP pendientes al reiniciar y no es determinista entre
// replicas. Cada proposito tiene su propia variable (no se reutiliza una para otra):
//   CNS_SESSION_SECRET  firma de la sesion y raiz HKDF de los handles/CSRF/sesiones CASE y STAFF (consent-flow-server.ts)
//   CNS_OTP_SECRET      HMAC del codigo OTP y del canal opaco (otp-challenge.ts)
// (CNS_CHAIN_REF_SECRET, CNS_DECISION_MAKER_REF_SECRET* y CNS_STAFF_ROSTER_CURSOR_SECRET viven en sus modulos.)
// Valor: base64 estricto de al menos 32 bytes. Los mensajes de error nunca incluyen valores de secretos.
// Sin proveedor de secretos ni SDK: solo variables de entorno.

import { decodeStrictSecret } from "../../modules/secrets/strict-secret.ts";

type Env = Readonly<Record<string, string | undefined>>;

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

const SECRET_VAR_RE = /^CNS_[A-Z0-9_]*_SECRET(_V[1-9]\d{0,3})?$/;

/** P2-6 (C2): los secretos CRUDOS de todas las CNS_*_SECRET presentes (sesion, OTP, cursor, chainRef y todas las
 * versiones de decisionMakerRef) deben ser distintos entre si: una clave por proposito. Compara los bytes
 * decodificados, no el texto. El error nombra las variables, nunca los valores. */
export function assertDistinctServerSecrets(env: Env): void {
  const seen = new Map<string, string>();
  for (const name of Object.keys(env).sort()) {
    const raw = env[name];
    if (!SECRET_VAR_RE.test(name) || raw === undefined || raw === "") continue;
    const id = decodeStrictSecret(raw, name).toString("hex");
    const other = seen.get(id);
    if (other !== undefined) {
      throw new Error(`${other} y ${name} tienen el mismo secreto; cada proposito debe usar su propia clave. Abortando (fail-closed).`);
    }
    seen.set(id, name);
  }
}
