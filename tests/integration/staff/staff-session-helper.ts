// Gobierna: CA-138 (SEC-CNS-018 rev. 2 D-3). Ayuda de tests: emite una sesion STAFF registrada en el almacen IN-MEMORY del
// harness (la cookie sola ya no basta: el servidor exige el registro). Sincrona a proposito (create del adaptador in-memory se
// ejecuta sin esperas); para Postgres usar issueStaffSession (async). Memoriza por (almacen, principal, tenant, rol, etiqueta): el
// mismo llamado devuelve la misma sesion (mismo sid, misma cookie, mismo CSRF), como un navegador que conserva su cookie.

import { createHash } from "node:crypto";

import {
  encodeStaffSession,
  hashStaffSid,
  staffCsrfTokenFor,
  type StaffSessionPayload,
} from "../../../src/server/entrypoints/http/staff-session.ts";
import { PROPOSED_STAFF_SESSION_ABSOLUTE_TTL_MS } from "../../../src/server/modules/common/approved-parameters.ts";
import type { StaffRole } from "../../../src/server/ports/staff-identity.port.ts";
import type { StaffSessionStorePort } from "../../../src/server/ports/staff-session-store.port.ts";

export interface MintedStaffSession {
  readonly sid: string;
  /** Valor de la cookie `__Host-cns-staff`. */
  readonly cookieValue: string;
  /** Token CSRF ligado a este sid. */
  readonly csrf: string;
  readonly payload: StaffSessionPayload;
}

const memo = new WeakMap<StaffSessionStorePort, Map<string, MintedStaffSession>>();

export function mintStaffSession(
  sessions: StaffSessionStorePort,
  key: Buffer,
  who: { readonly tenantId: string; readonly principalRef: string; readonly role?: StaffRole },
  label = "",
): MintedStaffSession {
  const role = who.role ?? "TENANT_ADMIN";
  const id = [who.tenantId, who.principalRef, role, label].join("|");
  let cache = memo.get(sessions);
  if (cache === undefined) memo.set(sessions, (cache = new Map()));
  const hit = cache.get(id);
  if (hit !== undefined) return hit;
  const sid = createHash("sha256").update(`test-sid|${id}`).digest("base64url"); // 43 caracteres, 256 bits
  const now = Date.now();
  const payload: StaffSessionPayload = { sid, tenantId: who.tenantId, principalRef: who.principalRef, role, iat: now, exp: now + PROPOSED_STAFF_SESSION_ABSOLUTE_TTL_MS };
  void sessions.create({ tenantId: who.tenantId, sidHash: hashStaffSid(sid), principalRef: who.principalRef, role, issuedAtMs: payload.iat, expiresAtMs: payload.exp });
  const minted: MintedStaffSession = { sid, cookieValue: encodeStaffSession(key, payload), csrf: staffCsrfTokenFor(key, sid), payload };
  cache.set(id, minted);
  return minted;
}
