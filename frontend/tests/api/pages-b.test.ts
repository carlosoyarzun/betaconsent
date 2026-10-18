import { afterEach, describe, expect, it, vi } from "vitest";
import { loadDecisionPageState, loadManagePageState, parseDecisionPageState, parseManagePageState } from "../../src/api/pages-b.ts";
import { empty, json, offline, stubRoutes } from "../b-helpers.ts";

afterEach(() => vi.unstubAllGlobals());

const SERVED = { consentVersion: "v1", privacyNoticeVersion: "v1", text: "t" };

describe("api/pages-b (GET page-state)", () => {
  it("TEST-CNS-1923: GET same-origin sin CSRF ni cuerpo; 200 válido -> ready con los datos", async () => {
    const { calls } = stubRoutes({ "GET /decision/page-state": json({ relationshipRefs: ["A"], servedVersion: SERVED, subjectLabel: "Alumno de prueba 1" }) });
    const result = await loadDecisionPageState();
    expect(result).toEqual({ kind: "ready", data: { relationshipRefs: ["A"], servedVersion: SERVED, subjectLabel: "Alumno de prueba 1" } });
    expect(calls[0]!.init.method).toBe("GET");
    expect(calls[0]!.init.credentials).toBe("same-origin");
    expect(calls[0]!.init.body).toBeUndefined();
    expect(calls[0]!.init.headers).toEqual({ accept: "application/json" });
  });

  it("TEST-CNS-1923: 404 -> uniform; 5xx, red, JSON inválido o fuera de contrato -> unavailable; campos extra se descartan", async () => {
    stubRoutes({ "GET /manage/page-state": [empty(404), empty(503), offline(), new Response("no-json", { status: 200 }), json({ variant: "otra" }), json({ variant: "status", extra: 1 })] });
    expect(await loadManagePageState()).toEqual({ kind: "uniform" });
    expect(await loadManagePageState()).toEqual({ kind: "unavailable" });
    expect(await loadManagePageState()).toEqual({ kind: "unavailable" });
    expect(await loadManagePageState()).toEqual({ kind: "unavailable" });
    expect(await loadManagePageState()).toEqual({ kind: "unavailable" });
    expect(await loadManagePageState()).toEqual({ kind: "ready", data: { variant: "status" } });
  });

  it("TEST-CNS-1923: los parsers rechazan formas inválidas y no copian campos desconocidos (p. ej. consentTextHash)", () => {
    expect(parseDecisionPageState(null)).toBeUndefined();
    expect(parseDecisionPageState({ relationshipRefs: [1], servedVersion: SERVED })).toBeUndefined();
    expect(parseDecisionPageState({ relationshipRefs: [], servedVersion: { consentVersion: "v1" } })).toBeUndefined();
    expect(parseDecisionPageState({ relationshipRefs: [], servedVersion: { ...SERVED, consentTextHash: "h" } })).toEqual({ relationshipRefs: [], servedVersion: SERVED });
    expect(parseManagePageState([])).toBeUndefined();
    expect(parseManagePageState({ variant: "entry" })).toEqual({ variant: "entry" });
  });
});
