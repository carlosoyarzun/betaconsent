// Gobierna: DEC-BR-014 rev. 8 §3 X5 ("escaneo de PII, tokens, OTP y cookies en logs y URLs (/i/*, /m/*,
// /r/*)"), SEC-CNS-014 (enlaces de un solo uso: el token solo viaja en el request inicial), INV-OT-02
// (el codigo OTP en claro no sale del sink), PRIV (cero PII en URLs/logs). Driver compartido por
// pii-scan-http.test.ts (memoria, TEST-CNS-952) y postgres/pii-scan-http-pg.test.ts (pg, TEST-CNS-953):
// recorre por HTTP real los flujos /i -> OTP -> decision, /m -> retiro -> recibo, /r recuperacion,
// RH3 (staff, cuatro ojos) y consola STAFF (enrolar/invitar), mientras captura TODO lo escrito a
// stdout/stderr y todas las URLs observadas (request, Location, href/src/action del HTML, Link).
// SYNTHETIC DATA ONLY. Este archivo no es un test (no termina en .test.ts).

import { fixtureUuid } from "../../contract/uuid-fixture.ts";
import assert from "node:assert/strict";

import { RH3_DEV_CASE_REF } from "../../../src/server/entrypoints/dev-rh3-seed.ts";
import { LECTORPRO_BETA_CONFIG } from "../../../src/server/modules/consent-decision/lectorpro-beta.config.ts";
import { LOCAL_ONLY_DEV_PARTICIPATION_REF, LOCAL_ONLY_DEV_STAFF_CHANNEL_REF, LOCAL_ONLY_DEV_STAFF_SUBJECT_REF } from "../../../src/server/entrypoints/dev-local-config.ts";

export const SCAN_ORIGIN = "http://consola-consent.test.localhost";
const GRANT_ALL = LECTORPRO_BETA_CONFIG.requiredPurposes.map((purpose) => ({ purpose, choice: "GRANT" as const }));

export interface ScanEnv {
  readonly baseUrl: string;
  readonly otpSink: { readonly sent: readonly { readonly code: string; readonly channelRef: string }[] };
  readonly recoverySink: { readonly sent: readonly { readonly recoveryPath: string }[] };
  readonly invitationSink: { readonly sent: readonly { readonly invitationPath: string; readonly recipientChannelRef?: string }[] };
  /** Invitacion SENT lista para canjear; devuelve el token en claro (solo para que el test lo busque en logs/URLs). */
  seedInvitation(label: string): Promise<{ readonly token: string }>;
  /** Decision GRANTED + handle de gestion /m/{token}. */
  seedManage(label: string): Promise<{ readonly handleToken: string }>;
  seedRh3(): Promise<void>;
  /** Secretos de entorno/proceso (sessionSecret, claves, password de BD) que nunca deben aparecer. */
  readonly envSecrets: readonly string[];
}

export interface Corpus {
  /** Todo lo escrito a stdout/stderr durante el recorrido. */
  logs: string;
  /** Path+query de cada request emitido, en orden. */
  requestUrls: string[];
  /** Location, Link, href/src/action y meta refresh de las respuestas (NO los cuerpos JSON de los sinks de dev). */
  responseUrls: string[];
  otpCodes: Set<string>;
  tokens: Set<string>;
  cookieValues: Set<string>;
  emails: Set<string>;
  envSecrets: string[];
  stats: { requests: number; locations: number; htmlLinks: number; cookiesSeen: number };
}

export function newCorpus(envSecrets: readonly string[]): Corpus {
  return {
    logs: "",
    requestUrls: [],
    responseUrls: [],
    otpCodes: new Set(),
    tokens: new Set(),
    cookieValues: new Set(),
    emails: new Set(),
    envSecrets: [...envSecrets],
    stats: { requests: 0, locations: 0, htmlLinks: 0, cookiesSeen: 0 },
  };
}

/** Captura stdout y stderr (console.* incluido). Los chunks binarios (eventos serializados del propio runner
 * de node:test, que viajan por el stdout del subproceso) pasan intactos al stream real y no se capturan; todo
 * texto (console.log/error, process.stdout.write de string) se captura y NO se emite. Devuelve stop(), que
 * restaura ambos streams y entrega el texto capturado. */
export function startCapture(): () => string {
  const chunks: string[] = [];
  const realOut = process.stdout.write;
  const realErr = process.stderr.write;
  const wrap = (real: typeof process.stdout.write, stream: NodeJS.WriteStream): typeof process.stdout.write =>
    ((chunk: unknown, ...rest: unknown[]): boolean => {
      if (typeof chunk !== "string") return (real as (...a: unknown[]) => boolean).call(stream, chunk, ...rest);
      chunks.push(chunk);
      const cb = rest.find((a) => typeof a === "function") as (() => void) | undefined;
      cb?.();
      return true;
    }) as typeof process.stdout.write;
  process.stdout.write = wrap(realOut, process.stdout);
  process.stderr.write = wrap(realErr, process.stderr);
  return () => {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
    return chunks.join("");
  };
}

/** Contacto de soporte ESTATICO de las paginas (copy placeholder en dominio reservado, no dato de usuario). Es la
 * unica direccion admitida en las URLs/HTML; cualquier otra, incluidos destinatarios sinteticos del sink, es fuga. */
export const STATIC_SUPPORT_MAILTO = "mailto:ayuda@example.invalid";
const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+/g;
const LINK_ATTR_RE = /\b(?:href|src|action)\s*=\s*["']([^"']*)["']/gi;
const META_REFRESH_RE = /http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url=([^"']*)["']/gi;

class Jar {
  readonly values = new Map<string, string>();
  absorb(res: Response, corpus: Corpus): void {
    for (const raw of res.headers.getSetCookie()) {
      const first = raw.split(";", 1)[0] ?? "";
      const eq = first.indexOf("=");
      if (eq <= 0) continue;
      const name = first.slice(0, eq);
      const value = first.slice(eq + 1);
      if (value === "" || /expires=Thu, 01 Jan 1970/i.test(raw)) {
        this.values.delete(name);
        continue;
      }
      this.values.set(name, value);
      if (name.startsWith("__Host-")) {
        corpus.cookieValues.add(value);
        corpus.stats.cookiesSeen++;
      }
    }
  }
  set(name: string, value: string): void {
    this.values.set(name, value);
  }
  get(name: string): string | undefined {
    return this.values.get(name);
  }
  header(): string {
    return [...this.values].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

interface CallOpts {
  readonly method?: "GET" | "POST";
  readonly body?: unknown;
  readonly csrfCookie?: string;
  readonly headers?: Record<string, string>;
}

async function call(env: ScanEnv, corpus: Corpus, jar: Jar, path: string, opts: CallOpts = {}): Promise<Response> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (jar.values.size > 0) headers.cookie = jar.header();
  if (method === "POST") {
    headers["content-type"] = "application/json";
    headers.origin = SCAN_ORIGIN;
    const csrf = jar.get(opts.csrfCookie ?? "__Host-cns-csrf");
    if (csrf !== undefined) headers["x-csrf-token"] = csrf;
  }
  corpus.requestUrls.push(path);
  corpus.stats.requests++;
  const res = await fetch(`${env.baseUrl}${path}`, {
    method,
    headers,
    redirect: "manual",
    ...(method === "POST" ? { body: JSON.stringify(opts.body ?? {}) } : {}),
  });
  jar.absorb(res, corpus);
  const location = res.headers.get("location");
  if (location !== null) {
    corpus.responseUrls.push(location);
    corpus.stats.locations++;
  }
  const link = res.headers.get("link");
  if (link !== null) corpus.responseUrls.push(link);
  const type = res.headers.get("content-type") ?? "";
  const text = await res.text();
  if (type.includes("html") && !path.startsWith("/__dev/")) {
    for (const re of [LINK_ATTR_RE, META_REFRESH_RE]) {
      re.lastIndex = 0;
      for (let m = re.exec(text); m !== null; m = re.exec(text)) {
        corpus.responseUrls.push(m[1] ?? "");
        corpus.stats.htmlLinks++;
      }
    }
  }
  // El cuerpo ya se consumio; se devuelve una Response equivalente para que el caller lea status/json.
  return new Response(text, { status: res.status, headers: res.headers });
}

function lastOtp(env: ScanEnv, corpus: Corpus): string {
  const code = env.otpSink.sent[env.otpSink.sent.length - 1]?.code ?? "";
  assert.ok(code.length > 0, "el sink debe tener el OTP emitido");
  corpus.otpCodes.add(code);
  return code;
}

async function redeem(env: ScanEnv, corpus: Corpus, jar: Jar, path: string, handleCookie: string): Promise<void> {
  const res = await call(env, corpus, jar, path);
  assert.equal(res.status, 303, `GET ${path.split("/").slice(0, 2).join("/")}/{token}`);
  assert.ok(jar.get(handleCookie) !== undefined, `${handleCookie} fijada por el canje`);
}

/** Flujo 1: /i/{token} -> /welcome -> OTP (un intento erroneo y uno correcto) -> pasos -> decision. */
async function flowInvitation(env: ScanEnv, corpus: Corpus): Promise<void> {
  const { token } = await env.seedInvitation("scan-inv");
  corpus.tokens.add(token);
  const jar = new Jar();
  jar.set("__Host-cns-csrf", "csrf-token-abcdefgh");
  await redeem(env, corpus, jar, `/i/${token}`, "__Host-cns-i-handle");
  assert.equal((await call(env, corpus, jar, "/welcome")).status, 200);
  assert.equal((await call(env, corpus, jar, "/invitation/open", { method: "POST" })).status, 200);
  assert.equal((await call(env, corpus, jar, "/otp/request", { method: "POST" })).status, 202);
  const code = lastOtp(env, corpus);
  const wrong = code === "000000" ? "111111" : "000000";
  corpus.otpCodes.add(wrong);
  const bad = await call(env, corpus, jar, "/otp/submit", { method: "POST", body: { code: wrong } });
  assert.notEqual(bad.status, 500);
  assert.equal((await call(env, corpus, jar, "/otp/submit", { method: "POST", body: { code } })).status, 200);
  for (const body of [
    { stepKind: "CONTEXT_INFORMATION_VIEWED" },
    { stepKind: "CONSENT_VERSION_VIEWED" },
    { stepKind: "DECISION_MAKER_AUTHORITY_DECLARED", relationshipRef: "SYNTHETIC_GUARDIAN", authorityDeclared: true },
    { stepKind: "SUBJECT_CONFIRMED", subjectConfirmed: true },
  ]) {
    assert.equal((await call(env, corpus, jar, "/decision/steps", { method: "POST", body })).status, 200);
  }
  const decided = await call(env, corpus, jar, "/decision/submit", { method: "POST", body: { purposes: GRANT_ALL } });
  assert.equal(decided.status, 200);
  // Paginas posteriores del flujo (recibo/estado): sus enlaces tambien se escanean.
  for (const p of ["/welcome", "/verify", "/decision"]) assert.notEqual((await call(env, corpus, jar, p)).status, 500);
}

/** Flujo 2: /m/{token} -> /manage -> OTP MANAGE -> R1 -> OTP -> R2 -> R3 (retiro) -> /manage ya-retirado. */
async function flowManageRevocation(env: ScanEnv, corpus: Corpus): Promise<void> {
  const { handleToken } = await env.seedManage("scan-mgmt");
  corpus.tokens.add(handleToken);
  const jar = new Jar();
  jar.set("__Host-cns-csrf", "csrf-token-abcdefgh");
  await redeem(env, corpus, jar, `/m/${handleToken}`, "__Host-cns-m-handle");
  assert.equal((await call(env, corpus, jar, "/manage")).status, 200);
  assert.equal((await call(env, corpus, jar, "/otp/request", { method: "POST" })).status, 202);
  assert.equal((await call(env, corpus, jar, "/otp/submit", { method: "POST", body: { code: lastOtp(env, corpus) } })).status, 200);
  assert.equal((await call(env, corpus, jar, "/manage/revocation", { method: "POST" })).status, 200);
  assert.equal((await call(env, corpus, jar, "/otp/request", { method: "POST" })).status, 202);
  assert.equal((await call(env, corpus, jar, "/otp/submit", { method: "POST", body: { code: lastOtp(env, corpus) } })).status, 200);
  assert.equal((await call(env, corpus, jar, "/manage/revocation/verify", { method: "POST" })).status, 200);
  const confirmed = await call(env, corpus, jar, "/manage/revocation/confirm", { method: "POST" });
  assert.equal(confirmed.status, 200);
  assert.equal((await call(env, corpus, jar, "/manage")).status, 200);
}

/** Flujo 3: /m -> /manage/recovery-link -> /r/{token} (del sink) -> /recovery/confirm -> /recovery/revoke. */
async function flowRecovery(env: ScanEnv, corpus: Corpus): Promise<void> {
  const { handleToken } = await env.seedManage("scan-rec");
  corpus.tokens.add(handleToken);
  const jar = new Jar();
  jar.set("__Host-cns-csrf", "csrf-token-abcdefgh");
  await redeem(env, corpus, jar, `/m/${handleToken}`, "__Host-cns-m-handle");
  assert.equal((await call(env, corpus, jar, "/manage")).status, 200);
  assert.equal((await call(env, corpus, jar, "/manage/recovery-link", { method: "POST" })).status, 202);
  const path = env.recoverySink.sent[env.recoverySink.sent.length - 1]?.recoveryPath ?? "";
  assert.match(path, /^\/r\/[^/]+$/);
  corpus.tokens.add(path.slice("/r/".length));
  const rjar = new Jar();
  await redeem(env, corpus, rjar, path, "__Host-cns-recovery");
  const confirm = await call(env, corpus, rjar, "/recovery/confirm");
  assert.equal(confirm.status, 200);
  const done = await call(env, corpus, rjar, "/recovery/revoke", { method: "POST", body: { confirmTotalWithdrawal: true } });
  assert.equal(done.status, 200);
  // (El reintento del enlace de un solo uso lo cubre TEST-CNS-874; aqui el token solo se solicita una vez.)
}

/** Flujo 4: staff RH3 (cuatro ojos): login dev, registro y co-firma por dos operadores distintos. */
async function flowRh3(env: ScanEnv, corpus: Corpus, tenantId: string): Promise<void> {
  await env.seedRh3();
  const login = async (principalRef: string): Promise<Jar> => {
    const jar = new Jar();
    const res = await call(env, corpus, jar, "/__dev/staff-login", { method: "POST", body: { tenantId, caseRef: RH3_DEV_CASE_REF, principalRef } });
    assert.equal(res.status, 200);
    return jar;
  };
  const op1 = await login(fixtureUuid("staff-synthetic-01"));
  const first = await call(env, corpus, op1, `/platform/rights-cases/${RH3_DEV_CASE_REF}/confirmation`, { method: "POST", csrfCookie: "__Host-cns-case-csrf", body: { confirmationGivenOnCasePage: true } });
  assert.equal(first.status, 200);
  const op2 = await login(fixtureUuid("staff-synthetic-02"));
  const second = await call(env, corpus, op2, `/platform/rights-cases/${RH3_DEV_CASE_REF}/confirmation/cosign`, { method: "POST", csrfCookie: "__Host-cns-case-csrf", body: {} });
  assert.equal(second.status, 200);
}

/** Flujo 5: consola STAFF (TENANT_ADMIN): enrolar, invitar, ready, send, enlace del sink -> /i/{token}. */
async function flowStaff(env: ScanEnv, corpus: Corpus): Promise<void> {
  const jar = new Jar();
  const login = await call(env, corpus, jar, "/__dev/staff-login", { method: "POST", body: { principalRef: fixtureUuid("staff-synthetic-05") } });
  assert.equal(login.status, 200);
  const post = (path: string, body: unknown, headers: Record<string, string> = {}): Promise<Response> =>
    call(env, corpus, jar, path, { method: "POST", csrfCookie: "__Host-cns-staff-csrf", body, headers });
  const enrolled = await post("/staff/enrollments", { subjectRef: LOCAL_ONLY_DEV_STAFF_SUBJECT_REF, participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF });
  assert.equal(enrolled.status, 201, await enrolled.clone().text());
  const { enrollmentRef } = (await enrolled.json()) as { enrollmentRef: string };
  const invited = await post(
    "/staff/invitations",
    { subjectRef: LOCAL_ONLY_DEV_STAFF_SUBJECT_REF, enrollmentRef, participationRef: LOCAL_ONLY_DEV_PARTICIPATION_REF, contextRef: LECTORPRO_BETA_CONFIG.contextRef },
    { "idempotency-key": "pii-scan-idem-key-0001" },
  );
  assert.equal(invited.status, 201, await invited.clone().text());
  const { invitationRef } = (await invited.json()) as { invitationRef: string };
  assert.equal((await post(`/staff/invitations/${invitationRef}/ready`, { consentVersion: "v1-dev", recipientBinding: "RECIPIENT_CHANNEL", recipientChannelRef: LOCAL_ONLY_DEV_STAFF_CHANNEL_REF })).status, 200);
  assert.equal((await post(`/staff/invitations/${invitationRef}/send`, {})).status, 200);
  const path = env.invitationSink.sent[env.invitationSink.sent.length - 1]?.invitationPath ?? "";
  assert.match(path, /^\/i\/[^/]+$/);
  corpus.tokens.add(path.slice("/i/".length));
  const bearer = new Jar();
  await redeem(env, corpus, bearer, path, "__Host-cns-i-handle");
  assert.equal((await call(env, corpus, bearer, "/welcome")).status, 200);
}

/** Flujo 6: entradas invalidas (token inexistente, cookies basura, OTP sin sesion): nada debe llegar a logs/URLs. */
async function flowNegatives(env: ScanEnv, corpus: Corpus): Promise<void> {
  for (const [path, secret] of [["/i/", "tok-i-inexistente-0001"], ["/m/", "tok-m-inexistente-0002"], ["/r/", "tok-r-inexistente-0003"]] as const) {
    corpus.tokens.add(secret);
    const res = await call(env, corpus, new Jar(), `${path}${secret}`);
    assert.notEqual(res.status, 500, path);
  }
  const junk = new Jar();
  junk.set("__Host-cns-session", "basura-sesion-0004");
  junk.set("__Host-cns-csrf", "csrf-token-abcdefgh");
  corpus.cookieValues.add("basura-sesion-0004");
  for (const p of ["/otp/submit", "/decision/submit", "/manage/revocation/confirm", "/recovery/revoke"]) {
    assert.notEqual((await call(env, corpus, junk, p, { method: "POST", body: { code: "999999" } })).status, 500, p);
  }
  corpus.otpCodes.add("999999");
}

export async function runAllFlows(env: ScanEnv, tenantId: string, corpus: Corpus): Promise<void> {
  await flowInvitation(env, corpus);
  await flowManageRevocation(env, corpus);
  await flowRecovery(env, corpus);
  await flowRh3(env, corpus, tenantId);
  await flowStaff(env, corpus);
  await flowNegatives(env, corpus);
  // Destinatarios sinteticos (incluidos los de reservado .invalid): jamas en logs/URLs.
  for (const m of env.otpSink.sent) corpus.emails.add(m.channelRef);
  for (const m of env.invitationSink.sent) if (m.recipientChannelRef) corpus.emails.add(m.recipientChannelRef);
}

/** Devuelve la lista de hallazgos (vacia = limpio). Nunca incluye el valor filtrado, solo su clase y posicion. */
export function scanForLeaks(corpus: Corpus): string[] {
  const findings: string[] = [];
  const surfaces: ReadonlyArray<readonly [string, string]> = [
    ["logs", corpus.logs],
    ["urls", [...corpus.requestUrls, ...corpus.responseUrls].join("\n")],
  ];
  for (const [surface, text] of surfaces) {
    if (/\bdm:[A-Za-z0-9]/.test(text)) findings.push(`${surface}: hash dm:`);
    const withoutStatic = text.replaceAll(STATIC_SUPPORT_MAILTO, "");
    for (const m of withoutStatic.matchAll(EMAIL_RE)) findings.push(`${surface}: email-like (${m[0].length} chars)`);
    for (const e of corpus.emails) if (text.includes(e)) findings.push(`${surface}: destinatario del sink`);
    for (const code of corpus.otpCodes) if (new RegExp(`(?<![0-9A-Za-z])${code}(?![0-9A-Za-z])`).test(text)) findings.push(`${surface}: codigo OTP`);
    for (const v of corpus.cookieValues) if (v.length >= 8 && text.includes(v)) findings.push(`${surface}: valor de cookie __Host-*`);
    for (const s of corpus.envSecrets) if (s.length >= 8 && text.includes(s)) findings.push(`${surface}: secreto de entorno`);
  }
  for (const token of corpus.tokens) {
    if (corpus.logs.includes(token)) findings.push("logs: token en claro");
    for (const u of corpus.responseUrls) if (u.includes(token)) findings.push("response-url: token en claro (Location/href)");
    // El token solo puede viajar en el request inicial (el GET de canje); ninguna otra request lo reutiliza.
    const hits = corpus.requestUrls.filter((u) => u.includes(token)).length;
    if (hits > 1) findings.push(`request-url: token en ${hits} requests (debe ser solo el inicial)`);
    if (corpus.cookieValues.has(token)) findings.push("cookie: el handle repite el token en claro");
  }
  return findings;
}

export function describeStats(corpus: Corpus): string {
  const s = corpus.stats;
  return `requests=${s.requests} locations=${s.locations} htmlLinks=${s.htmlLinks} cookies=${s.cookiesSeen} tokens=${corpus.tokens.size} otp=${corpus.otpCodes.size} logsBytes=${corpus.logs.length}`;
}

/** Garantiza que el escaneo vio algo (anti-vacuo): sin trafico real un "0 hallazgos" no prueba nada. */
export function assertNonVacuous(corpus: Corpus): void {
  assert.ok(corpus.stats.requests >= 40, `requests observadas: ${corpus.stats.requests}`);
  assert.ok(corpus.stats.locations >= 5, `Location observados: ${corpus.stats.locations}`);
  assert.ok(corpus.stats.htmlLinks >= 1, `enlaces HTML observados: ${corpus.stats.htmlLinks}`);
  assert.ok(corpus.stats.cookiesSeen >= 10, `Set-Cookie __Host-* observadas: ${corpus.stats.cookiesSeen}`);
  assert.ok(corpus.tokens.size >= 8, `tokens rastreados: ${corpus.tokens.size}`);
  assert.ok(corpus.otpCodes.size >= 4, `OTP rastreados: ${corpus.otpCodes.size}`);
  assert.ok(corpus.emails.size >= 1, "destinatarios del sink rastreados");
}
