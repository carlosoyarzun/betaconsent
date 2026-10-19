// Gobierna: ADR-001 F1 (fase C). Las funciones de api/pages-c.ts hacen el mismo POST que los assets/*.js (ruta, método,
// cabeceras CSRF y cuerpo). TEST-CNS-1960.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as api from "../../src/api/pages-c.ts";

beforeEach(() => {
  document.cookie = "__Host-cns-csrf=csrf-token-1; Path=/; Secure";
});
afterEach(() => vi.unstubAllGlobals());

describe("api/pages-c", () => {
  it.each([
    ["submitOtp", () => api.submitOtp("123456"), "/otp/submit", { code: "123456" }],
    ["requestOtp", () => api.requestOtp(), "/otp/request", {}],
    ["resendOtp", () => api.resendOtp(), "/otp/resend", {}],
    ["sendRecoveryLink", () => api.sendRecoveryLink(), "/manage/recovery-link", {}],
    ["verifyRevocation", () => api.verifyRevocation(), "/manage/revocation/verify", {}],
    ["confirmRevocation", () => api.confirmRevocation(), "/manage/revocation/confirm", {}],
    ["withdrawRevocation", () => api.withdrawRevocation(), "/manage/revocation/withdraw", {}],
    ["recoveryRevoke", () => api.recoveryRevoke(), "/recovery/revoke", { confirmTotalWithdrawal: true }],
  ])("TEST-CNS-1960: %s -> POST %s con content-type y x-csrf-token", async (_name, call, path, body) => {
    const fn = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fn);
    await call();
    const [url, init] = fn.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(path);
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("same-origin");
    expect(init.headers).toEqual({ "content-type": "application/json", "x-csrf-token": "csrf-token-1" });
    expect(init.body).toBe(JSON.stringify(body));
  });
});
