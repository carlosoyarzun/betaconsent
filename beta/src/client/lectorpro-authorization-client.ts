// Gobierna: plan v2 H1-08; API-CNS-001; DEC-BR-022 rev. 2 (b) consultar antes de cada lectura y (c) fail-closed.
// Cliente de referencia que LectorPro integra. TS puro: solo node:crypto y fetch global (sin dependencias, sin importar nada del servidor a propósito).
// Contrato: isAuthorized() devuelve true SOLO con 200 {status:"AUTHORIZED"}; cualquier error, timeout, 401/429/503 o respuesta mal formada => false.
import { createHash, createHmac, randomBytes } from "node:crypto";

export interface ClientLogEvent {
  /** Código estable sin PII (nunca el studentRef, la clave ni la firma). */
  readonly event: "authorization_denied_fail_closed" | "authorization_not_authorized";
  readonly reason: string;
}

export interface AuthorizationClientOptions {
  /** Origen de Consent App, p. ej. https://consent.lectorpro.cl (sin barra final). */
  readonly baseUrl: string;
  readonly keyId: string;
  /** Secreto en bytes (>= 32). */
  readonly secret: Buffer;
  readonly timeoutMs?: number;
  readonly fetchImpl?: typeof fetch;
  readonly now?: () => number;
  readonly onEvent?: (e: ClientLogEvent) => void;
}

export const DEFAULT_TIMEOUT_MS = 3000;

export function createAuthorizationClient(opts: AuthorizationClientOptions): { isAuthorized(studentRef: string): Promise<boolean> } {
  const doFetch = opts.fetchImpl ?? fetch;
  const now = opts.now ?? Date.now;
  const emit = (e: ClientLogEvent): void => {
    try {
      opts.onEvent?.(e);
    } catch {
      // un logger defectuoso no cambia la decisión
    }
  };
  const deny = (reason: string): false => {
    emit({ event: "authorization_denied_fail_closed", reason });
    return false;
  };

  return {
    async isAuthorized(studentRef) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? DEFAULT_TIMEOUT_MS);
      try {
        const path = `/api/v1/authorization-status/${encodeURIComponent(studentRef)}`;
        const timestamp = String(Math.floor(now() / 1000));
        const nonce = randomBytes(16).toString("base64url");
        const canonical = ["GET", path, timestamp, nonce, createHash("sha256").update("").digest("hex")].join("\n");
        const signature = createHmac("sha256", opts.secret).update(canonical).digest("base64url");
        const res = await doFetch(opts.baseUrl + path, {
          method: "GET",
          signal: controller.signal,
          redirect: "error",
          headers: { "x-cns-key-id": opts.keyId, "x-cns-timestamp": timestamp, "x-cns-nonce": nonce, "x-cns-signature": signature },
        });
        if (res.status !== 200) return deny(`HTTP_${res.status}`);
        let json: unknown;
        try {
          json = await res.json();
        } catch {
          return deny("MALFORMED_RESPONSE");
        }
        const status = typeof json === "object" && json !== null ? (json as { status?: unknown }).status : undefined;
        if (status === "AUTHORIZED") return true;
        if (status === "NOT_AUTHORIZED") {
          emit({ event: "authorization_not_authorized", reason: "NOT_AUTHORIZED" });
          return false;
        }
        return deny("MALFORMED_RESPONSE");
      } catch (e) {
        return deny((e as { name?: string } | null)?.name === "AbortError" ? "TIMEOUT" : "NETWORK_ERROR");
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
