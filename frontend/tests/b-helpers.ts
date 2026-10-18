// Utilidades de test de la fase B (/verify, /decision, /manage). Mock de fetch por "MÉTODO /ruta" y comprobaciones comunes.
import { expect, vi } from "vitest";

export type Reply = Response | Error | (() => Response | Error | Promise<Response>);
export type Routes = Record<string, Reply | Reply[]>;

export interface FetchCall {
  readonly method: string;
  readonly path: string;
  readonly init: RequestInit;
}

/** Cada clave es "POST /otp/submit"; un arreglo se consume en orden (el último se repite). Rutas sin mock lanzan. */
export function stubRoutes(routes: Routes): { readonly calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const counters = new Map<string, number>();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init: RequestInit = {}) => {
      const method = init.method ?? "GET";
      const key = `${method} ${path}`;
      calls.push({ method, path, init });
      const entry = routes[key];
      if (entry === undefined) throw new Error(`sin mock para ${key}`);
      const index = counters.get(key) ?? 0;
      counters.set(key, index + 1);
      const reply = Array.isArray(entry) ? entry[Math.min(index, entry.length - 1)]! : entry;
      const resolved = typeof reply === "function" ? await reply() : reply;
      if (resolved instanceof Error) throw resolved;
      return resolved.clone();
    }),
  );
  return { calls };
}

export const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
export const empty = (status = 200) => new Response("{}", { status });
export const problem = (status: number, code?: string) => new Response(JSON.stringify({ status, ...(code ? { code } : {}) }), { status, headers: { "content-type": "application/problem+json" } });
export const offline = () => new TypeError("offline");

export const CSRF = "csrf-token-1";
export function setCsrfCookie(): void {
  document.cookie = `__Host-cns-csrf=${CSRF}; Path=/; Secure`;
}

/** Cada POST lleva Content-Type JSON, x-csrf-token y credenciales same-origin (GRD-CM-10). */
export function expectPostHeaders(call: FetchCall): void {
  expect(call.init.method).toBe("POST");
  expect(call.init.credentials).toBe("same-origin");
  expect(call.init.headers).toEqual({ "content-type": "application/json", "x-csrf-token": CSRF });
}

/** CSP del SSR/SPA (ADR-001 §3): ni `style=""` ni `<script>`/`<style>` en el DOM renderizado. */
export function expectNoInlineStyleOrScript(container: HTMLElement): void {
  expect(container.querySelectorAll("[style]")).toHaveLength(0);
  expect(container.querySelectorAll("script, style")).toHaveLength(0);
  expect(container.querySelectorAll("[onclick], [onchange], [onsubmit]")).toHaveLength(0);
}

export function postBody(call: FetchCall): unknown {
  return JSON.parse(String(call.init.body));
}
