// Gobierna: plan v2 H1-05. Utilidades de test HTTP: dist de fixture, "navegador" con jar de cookies (las __Host- son Secure, fetch no las guarda solo) y extracción del OTP del correo.
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { MemoryMailer } from "../src/mail/memory-mailer.ts";

export const ORIGIN = "https://consent.example.invalid";

export function makeFixtureDist(): string {
  const dir = mkdtempSync(join(tmpdir(), "cns-dist-"));
  mkdirSync(join(dir, "assets"));
  mkdirSync(join(dir, ".vite"));
  writeFileSync(join(dir, "index.html"), '<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="cns-page-state" content="ready"><title>Consent App</title></head><body><div id="root"></div><script type="module" src="/assets/app-abc12345.js"></script></body></html>');
  writeFileSync(join(dir, "assets", "app-abc12345.js"), "console.log('fixture');");
  writeFileSync(join(dir, ".vite", "manifest.json"), JSON.stringify({ "index.html": { file: "assets/app-abc12345.js" } }));
  return dir;
}

export interface Res {
  readonly status: number;
  readonly headers: Headers;
  readonly text: string;
  readonly json: any;
}

export class Browser {
  readonly jar = new Map<string, string>();
  private readonly base: string;
  private readonly origin: string;
  constructor(base: string, origin: string = ORIGIN) {
    this.base = base;
    this.origin = origin;
  }

  private cookieHeader(): string {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  private absorb(res: Response): void {
    for (const c of res.headers.getSetCookie()) {
      const [pair = ""] = c.split(";");
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (/Max-Age=0/i.test(c) || value === "") this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }

  private async finish(res: Response): Promise<Res> {
    this.absorb(res);
    const text = await res.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { status: res.status, headers: res.headers, text, json };
  }

  async get(path: string, headers: Record<string, string> = {}): Promise<Res> {
    return this.finish(await fetch(this.base + path, { redirect: "manual", headers: { cookie: this.cookieHeader(), ...headers } }));
  }

  /** POST como la SPA: JSON, Origin y x-csrf-token copiado de la cookie (si `csrf` es false no lo envía). */
  async post(path: string, body: unknown = {}, opts: { csrf?: boolean; origin?: string | null } = {}): Promise<Res> {
    const headers: Record<string, string> = { "content-type": "application/json", cookie: this.cookieHeader() };
    if (opts.origin !== null) headers.origin = opts.origin ?? this.origin;
    const csrf = this.jar.get("__Host-cns-csrf");
    if (opts.csrf !== false && csrf) headers["x-csrf-token"] = csrf;
    return this.finish(await fetch(this.base + path, { method: "POST", redirect: "manual", headers, body: JSON.stringify(body) }));
  }
}

/** Último código OTP enviado (6 dígitos del texto del correo). */
export function lastOtp(mailer: MemoryMailer): string {
  const m = [...mailer.sent].reverse().find((x) => x.template === "otp");
  const code = m && /\b(\d{6})\b/.exec(m.text)?.[1];
  if (!code) throw new Error("no hay OTP enviado");
  return code;
}
