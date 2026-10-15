// Helper SOLO de tests: GET con node:http que NO sigue redirecciones y SI deja fijar headers Sec-Fetch-* (el fetch de undici los trata como headers prohibidos y los descarta).

import { request } from "node:http";

export interface RawResponse {
  readonly status: number;
  readonly headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}

export function rawFetch(url: string, init: { headers?: Record<string, string>; redirect?: string } = {}): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = request(url, { method: "GET", headers: init.headers ?? {} }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        resolve({
          status: res.statusCode ?? 0,
          headers: { get: (name: string) => { const v = res.headers[name.toLowerCase()]; return Array.isArray(v) ? v.join(", ") : (v ?? null); } },
          json: async () => JSON.parse(body) as unknown,
        });
      });
    });
    req.on("error", reject);
    req.end();
  });
}
