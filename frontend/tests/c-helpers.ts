// Ayudas de las pruebas de la fase C (TEST-CNS-1934…1960). Sin PII: solo refs sintéticas.
import { expect, vi } from "vitest";

export const json = (status: number, body: unknown = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": status >= 400 ? "application/problem+json" : "application/json" } });

export type Handler = (call: number) => Response | Promise<Response> | Error;

/** Mock de fetch por ruta: cada ruta es un handler (recibe el nº de llamada, 1-based) o una respuesta fija. */
export function stubFetch(routes: Record<string, Handler | Response | Error>) {
  const counts: Record<string, number> = {};
  const fn = vi.fn(async (path: string) => {
    const route = routes[path];
    if (!route) throw new Error(`sin mock para ${path}`);
    counts[path] = (counts[path] ?? 0) + 1;
    const result = typeof route === "function" ? route(counts[path]!) : route instanceof Error ? route : route.clone();
    if (result instanceof Error) throw result;
    return result;
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

export function calls(fn: ReturnType<typeof stubFetch>): [string, RequestInit][] {
  return fn.mock.calls as unknown as [string, RequestInit][];
}

export const EXPECTED_HEADERS = { "content-type": "application/json", "x-csrf-token": "csrf-token-1" };

/** Sin inline (ADR-001 §3): ni style="", ni on*=, ni <script>/<style> en el DOM renderizado. */
export function expectNoInline(container: HTMLElement): void {
  expect(container.querySelector("[style]")).toBeNull();
  expect(container.querySelector("script, style")).toBeNull();
  for (const el of container.querySelectorAll("*")) {
    for (const attr of el.getAttributeNames()) expect(attr.startsWith("on")).toBe(false);
  }
}
