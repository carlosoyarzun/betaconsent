// Gobierna: ADR-010 rev. 5 PR-6c §5.2 pasos 5-7; src/server/ports/platform-session.port.ts. Helper de TESTS (no es codigo de produccion): dobles en memoria del puerto de sesiones para las pruebas de las
// rutas HTTP del proceso platform sin base de datos. FakePlatformSessions imita el contrato de la base (la asercion se consume una sola vez, el principal sale de la asercion, validate revalida,
// revoke en cascada); DENY_ALL_SESSIONS deniega todo (fail-closed).

import { randomBytes } from "node:crypto";
import type { PlatformSessionPort, SessionKind, SessionLifetime, ValidatedSession } from "../../src/server/ports/platform-session.port.ts";

export const DENY_ALL_SESSIONS: PlatformSessionPort = {
  async openPlatformSession() { return null; },
  async openCaseSession() { return null; },
  async validate() { return null; },
  async revoke() { return false; },
};

interface Row { sid: string; kind: SessionKind; principalRef: string; caseRef: string | null; parent: string | null; revoked: boolean }

export class FakePlatformSessions implements PlatformSessionPort {
  /** Aserciones ATTESTED disponibles: clave `${exchangeRef}|${state}`. */
  readonly assertions = new Map<string, { kind: "LOGIN_PLATFORM" | "LOGIN_CASE"; principalRef: string; targetCaseRef?: string }>();
  readonly rows = new Map<string, Row>();
  /** Casos con grant vigente por principal (`${principal}|${caseRef}`). */
  readonly grants = new Set<string>();
  calls: string[] = [];
  lifetimes: SessionLifetime[] = [];
  failWith: Error | null = null;

  allow(exchangeRef: string, state: string, a: { kind: "LOGIN_PLATFORM" | "LOGIN_CASE"; principalRef: string; targetCaseRef?: string }): void {
    this.assertions.set(`${exchangeRef}|${state}`, a);
  }

  private newSid(): string { return randomBytes(32).toString("hex"); }

  async openPlatformSession(input: { exchangeRef: string; state: string; lifetime: SessionLifetime; previousSid?: string | null }): Promise<string | null> {
    this.calls.push("openPlatformSession");
    this.lifetimes.push(input.lifetime);
    if (this.failWith !== null) throw this.failWith;
    const a = this.assertions.get(`${input.exchangeRef}|${input.state}`);
    if (a === undefined || a.kind !== "LOGIN_PLATFORM") return null;
    this.assertions.delete(`${input.exchangeRef}|${input.state}`); // un solo uso
    if (input.previousSid != null) this.revokeTree(input.previousSid, "PLATFORM");
    const sid = this.newSid();
    this.rows.set(sid, { sid, kind: "PLATFORM", principalRef: a.principalRef, caseRef: null, parent: null, revoked: false });
    return sid;
  }

  async openCaseSession(input: { exchangeRef: string; state: string; caseRef: string; platformSid: string; lifetime: SessionLifetime; previousCaseSid?: string | null }): Promise<string | null> {
    this.calls.push("openCaseSession");
    if (this.failWith !== null) throw this.failWith;
    const a = this.assertions.get(`${input.exchangeRef}|${input.state}`);
    if (a === undefined || a.kind !== "LOGIN_CASE" || a.targetCaseRef !== input.caseRef) return null;
    this.assertions.delete(`${input.exchangeRef}|${input.state}`);
    const parent = this.rows.get(input.platformSid);
    if (parent === undefined || parent.revoked || parent.kind !== "PLATFORM" || parent.principalRef !== a.principalRef) return null;
    if (!this.grants.has(`${a.principalRef}|${input.caseRef}`)) return null;
    if (input.previousCaseSid != null) this.revokeTree(input.previousCaseSid, "CASE");
    const sid = this.newSid();
    this.rows.set(sid, { sid, kind: "CASE", principalRef: a.principalRef, caseRef: input.caseRef, parent: input.platformSid, revoked: false });
    return sid;
  }

  async validate(input: { sid: string; kind: SessionKind }): Promise<ValidatedSession | null> {
    this.calls.push(`validate:${input.kind}`);
    const r = this.rows.get(input.sid);
    if (r === undefined || r.revoked || r.kind !== input.kind) return null;
    if (r.parent !== null && this.rows.get(r.parent)?.revoked !== false) return null;
    return { sessionRef: "00000000-0000-4000-8000-000000000000", kind: r.kind, principalRef: r.principalRef, caseRef: r.caseRef };
  }

  async revoke(input: { sid: string; kind: SessionKind }): Promise<boolean> {
    this.calls.push(`revoke:${input.kind}`);
    return this.revokeTree(input.sid, input.kind);
  }

  private revokeTree(sid: string, kind: SessionKind): boolean {
    const r = this.rows.get(sid);
    if (r === undefined || r.kind !== kind || r.revoked) return false;
    r.revoked = true;
    if (kind === "PLATFORM") for (const c of this.rows.values()) if (c.parent === sid) c.revoked = true;
    return true;
  }
}
