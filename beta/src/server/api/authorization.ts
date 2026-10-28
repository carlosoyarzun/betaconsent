// Gobierna: DEC de Carlos "Reconstrucción mínima" (2026-10-19), plan v2 H1-08; API-CNS-001 (contracts/lectorpro-authorization.openapi.yaml); DEC-BR-022 rev. 2 (a)(b)(c)(e).
// GET /api/v1/authorization-status/{studentRef}: LectorPro consulta antes de cada lectura. Autenticación HMAC-SHA256 (esquema hmac-v1), sin cookies ni CSRF.
// Orden: forma de cabeceras -> keyId conocido -> ventana de tiempo -> firma (tiempo constante) -> rate limit por keyId -> nonce (BD) -> lectura FRESCA de authorization_status.
// El rate limit cuenta solo peticiones autenticadas (un tercero sin secreto no puede agotar la cuota de LectorPro). Un studentRef desconocido responde 200 NOT_AUTHORIZED.
// Nunca se registran secretos, firmas ni nonces en logs; api_access_log guarda key_id, student_ref opaco, resultado y status HTTP.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import type { ApiKey } from "../../config.ts";
import type { Queryable } from "../../db/pool.ts";
import type { Logger } from "../log.ts";

export const SIGNATURE_WINDOW_SECONDS = 60;
export const DEFAULT_RATE_LIMIT_PER_MINUTE = 60;
const PREFIX = "/api/v1/authorization-status/";
const STUDENT_REF_RE = /^[A-Za-z0-9._:-]{1,100}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22,128}$/; // >= 16 bytes en base64url
const KEY_ID_RE = /^[A-Za-z0-9_-]{1,40}$/;

/** Cadena canónica firmada: METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(body) (hex en minúsculas). */
export function canonicalString(method: string, path: string, timestamp: string, nonce: string, body: Buffer | string): string {
  return [method, path, timestamp, nonce, createHash("sha256").update(body).digest("hex")].join("\n");
}

export function signRequest(secret: Buffer, canonical: string): string {
  return createHmac("sha256", secret).update(canonical).digest("base64url");
}

export type VerifyFailure = "BAD_HEADERS" | "UNKNOWN_KEY" | "SKEW" | "BAD_SIGNATURE";

/** Verifica forma, clave, ventana y firma. Puro (sin BD): el nonce se registra aparte. */
export function verifySignature(
  keys: readonly ApiKey[],
  input: { method: string; path: string; keyId?: string; timestamp?: string; nonce?: string; signature?: string; body: Buffer },
  nowSeconds: number,
): { ok: true; keyId: string } | { ok: false; reason: VerifyFailure; keyId?: string } {
  const { keyId, timestamp, nonce, signature } = input;
  if (!keyId || !timestamp || !nonce || !signature || !KEY_ID_RE.test(keyId) || !/^\d{1,12}$/.test(timestamp) || !NONCE_RE.test(nonce) || !/^[A-Za-z0-9_-]{43}$/.test(signature)) {
    return { ok: false, reason: "BAD_HEADERS" };
  }
  const key = keys.find((k) => k.keyId === keyId);
  if (!key) return { ok: false, reason: "UNKNOWN_KEY" };
  if (Math.abs(nowSeconds - Number(timestamp)) > SIGNATURE_WINDOW_SECONDS) return { ok: false, reason: "SKEW", keyId };
  const expected = Buffer.from(signRequest(key.secret, canonicalString(input.method, input.path, timestamp, nonce, input.body)), "base64url");
  const given = Buffer.from(signature, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return { ok: false, reason: "BAD_SIGNATURE", keyId };
  return { ok: true, keyId };
}

/** Rate limit en memoria por keyId: ventana fija de un minuto. */
export function createRateLimiter(limitPerMinute: number, now: () => number): (keyId: string) => boolean {
  const buckets = new Map<string, { windowStart: number; count: number }>();
  return (keyId) => {
    const t = now();
    const b = buckets.get(keyId);
    if (!b || t - b.windowStart >= 60_000) {
      buckets.set(keyId, { windowStart: t, count: 1 });
      return true;
    }
    b.count += 1;
    return b.count <= limitPerMinute;
  };
}

export interface AuthorizationApiDeps {
  readonly keys: readonly ApiKey[];
  /** Pool consent_app. */
  readonly db: Queryable;
  readonly logger: Logger;
  readonly now?: () => number;
  readonly rateLimitPerMinute?: number;
}

export interface AuthorizationApi {
  handle(req: IncomingMessage, res: ServerResponse, requestId: string): Promise<number>;
}

type AccessResult = "AUTHORIZED" | "NOT_AUTHORIZED" | "UNAUTHENTICATED" | "ERROR";

async function readSmallBody(req: IncomingMessage): Promise<Buffer | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > 1024) return null;
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks);
}

export function createAuthorizationApi(deps: AuthorizationApiDeps): AuthorizationApi {
  const { keys, db, logger } = deps;
  const now = deps.now ?? Date.now;
  const allow = createRateLimiter(deps.rateLimitPerMinute ?? DEFAULT_RATE_LIMIT_PER_MINUTE, now);

  function send(res: ServerResponse, requestId: string, status: number, body: unknown, extra: Record<string, string> = {}): number {
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "x-request-id": requestId, ...extra });
    res.end(JSON.stringify(body));
    return status;
  }

  /** Registro de auditoría (DEC-BR-022 (e)). Si la BD falla no se puede registrar: solo queda la línea de log sin PII. */
  async function audit(keyId: string | undefined, studentRef: string | undefined, result: AccessResult, statusCode: number, requestId: string, outcome: string): Promise<void> {
    logger.info("authorization-api", { keyId: keyId ?? "-", result, status: statusCode, outcome, requestId });
    if (!keyId) return; // clave desconocida: sin fila (evita inundar la tabla desde fuera)
    try {
      await db.query("INSERT INTO app.api_access_log (key_id, student_ref, result, status_code) VALUES ($1, $2, $3, $4)", [keyId, studentRef ?? null, result, statusCode]);
    } catch {
      logger.error("authorization-api: no se pudo escribir api_access_log", { requestId });
    }
  }

  return {
    async handle(req, res, requestId) {
      if (req.method !== "GET") return send(res, requestId, 405, { code: "METHOD_NOT_ALLOWED", status: 405 }, { allow: "GET" });
      const path = (req.url ?? "").split("?")[0] ?? "";
      const body = await readSmallBody(req);
      const h = (n: string): string | undefined => {
        const v = req.headers[n];
        return Array.isArray(v) ? v[0] : v;
      };
      const unauth = async (keyId: string | undefined, outcome: string): Promise<number> => {
        await audit(keyId, undefined, "UNAUTHENTICATED", 401, requestId, outcome);
        return send(res, requestId, 401, { code: "UNAUTHENTICATED", status: 401 });
      };
      if (body === null) return unauth(undefined, "BODY_NOT_ALLOWED");
      const v = verifySignature(keys, { method: "GET", path, keyId: h("x-cns-key-id"), timestamp: h("x-cns-timestamp"), nonce: h("x-cns-nonce"), signature: h("x-cns-signature"), body }, Math.floor(now() / 1000));
      if (!v.ok) return unauth("keyId" in v ? v.keyId : undefined, v.reason);

      if (!allow(v.keyId)) {
        await audit(v.keyId, undefined, "ERROR", 429, requestId, "RATE_LIMITED");
        return send(res, requestId, 429, { code: "RATE_LIMITED", status: 429 }, { "retry-after": "60" });
      }

      // Raw del path: el studentRef va percent-decodificado solo si el resultado sigue siendo opaco y válido.
      let studentRef: string | undefined;
      try {
        const d = decodeURIComponent(path.slice(PREFIX.length));
        if (path.startsWith(PREFIX) && STUDENT_REF_RE.test(d)) studentRef = d;
      } catch {
        studentRef = undefined;
      }

      try {
        const nonce = h("x-cns-nonce") as string;
        const fresh = await db.query<{ fresh: boolean }>("SELECT app.record_api_nonce($1, $2) AS fresh", [v.keyId, nonce]);
        if (fresh.rows[0]?.fresh !== true) return unauth(v.keyId, "REPLAY");
        if (studentRef === undefined) {
          // Referencia mal formada: misma respuesta que un desconocido (no revela nada) y sin consultar la BD.
          const asOf = new Date(now()).toISOString();
          await audit(v.keyId, undefined, "NOT_AUTHORIZED", 200, requestId, "MALFORMED_REF");
          return send(res, requestId, 200, { status: "NOT_AUTHORIZED", asOf });
        }
        // Lectura fresca, sin caché: la lectura posterior al commit de revoke_decision ya ve la revocación (DEC-BR-022 (a)).
        const r = await db.query<{ status: "AUTHORIZED" | "NOT_AUTHORIZED"; as_of: Date; decision_ref: string | null }>("SELECT status, as_of, decision_ref FROM app.authorization_status($1)", [studentRef]);
        const row = r.rows[0];
        if (!row) throw new Error("authorization_status sin fila");
        const status = row.status === "AUTHORIZED" ? "AUTHORIZED" : "NOT_AUTHORIZED"; // cualquier otro valor es NOT_AUTHORIZED (fail-closed)
        await audit(v.keyId, studentRef, status, 200, requestId, "OK");
        return send(res, requestId, 200, { status, asOf: row.as_of.toISOString(), ...(status === "AUTHORIZED" && row.decision_ref ? { decisionRef: row.decision_ref } : {}) });
      } catch {
        await audit(v.keyId, studentRef, "ERROR", 503, requestId, "DB_UNAVAILABLE");
        return send(res, requestId, 503, { code: "UNAVAILABLE", status: 503 }, { "retry-after": "5" });
      }
    },
  };
}
