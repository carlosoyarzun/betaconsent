import { afterEach, describe, expect, it, vi } from "vitest";
import { postJson, readCookie } from "../../src/api/client.ts";

function mockFetch(response: Response | Error) {
  const fn = vi.fn(async () => {
    if (response instanceof Error) throw response;
    return response;
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => vi.unstubAllGlobals());

describe("readCookie", () => {
  it("lee y decodifica por nombre exacto", () => {
    expect(readCookie("__Host-cns-csrf", "a=1; __Host-cns-csrf=tok%2Fen; b=2")).toBe("tok/en");
    expect(readCookie("__Host-cns-csrf", "x__Host-cns-csrf=1")).toBeNull();
    expect(readCookie("c", "")).toBeNull();
  });
});

describe("postJson", () => {
  it("envía POST JSON same-origin con x-csrf-token tomado de la cookie __Host-cns-csrf", async () => {
    document.cookie = "__Host-cns-csrf=abc123; Path=/; Secure";
    const fetchMock = mockFetch(new Response(JSON.stringify({ hello: "x" }), { status: 200 }));
    const result = await postJson("/otp/request");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [path, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe("/otp/request");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("same-origin");
    expect(init.body).toBe("{}");
    expect(init.headers).toEqual({ "content-type": "application/json", "x-csrf-token": "abc123" });
    expect(result).toEqual({ ok: true, status: 200, data: { hello: "x" } });
  });

  it("sin cookie CSRF no envía la cabecera", async () => {
    const fetchMock = mockFetch(new Response("{}", { status: 200 }));
    await postJson("/x");
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(init.headers).toEqual({ "content-type": "application/json" });
  });

  it("4xx con {code, correlationId} (también problem+json) -> error http uniforme", async () => {
    mockFetch(new Response(JSON.stringify({ code: "CSRF_REJECTED", correlationId: "c-1" }), { status: 403, headers: { "content-type": "application/problem+json" } }));
    expect(await postJson("/x")).toEqual({ ok: false, error: { kind: "http", status: 403, code: "CSRF_REJECTED", correlationId: "c-1" } });
  });

  it("503 sin cuerpo JSON no lanza", async () => {
    mockFetch(new Response("", { status: 503 }));
    expect(await postJson("/x")).toEqual({ ok: false, error: { kind: "http", status: 503 } });
  });

  it("falla de red -> kind network, status 0", async () => {
    mockFetch(new TypeError("fail"));
    expect(await postJson("/x")).toEqual({ ok: false, error: { kind: "network", status: 0 } });
  });
});
