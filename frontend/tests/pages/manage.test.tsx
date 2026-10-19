import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ManagePage } from "../../src/pages/manage.tsx";
import { navigation } from "../../src/router.ts";
import { empty, expectNoInlineStyleOrScript, expectPostHeaders, json, offline, setCsrfCookie, stubRoutes, type Routes } from "../b-helpers.ts";

beforeEach(() => {
  setCsrfCookie();
  vi.spyOn(navigation, "assign").mockImplementation(() => undefined);
});
afterEach(() => vi.unstubAllGlobals());

async function renderVariant(variant: "entry" | "status" | "revoked", extra: Routes = {}) {
  const stub = stubRoutes({ "GET /manage/page-state": json({ variant }), ...extra });
  const view = render(<ManagePage pageState="ready" />);
  await screen.findByRole("heading", { level: 1 });
  await waitFor(() => expect(screen.getByRole("main")).not.toHaveAttribute("aria-busy"));
  return { ...stub, ...view };
}

describe("/manage (equivale a manage-page.ts + manage.js)", () => {
  it("TEST-CNS-1919: entrada (33:2): copy, ids, CTA 'Verificar mi identidad', avisos ocultos; pide GET /manage/page-state", async () => {
    const { calls, container } = await renderVariant("entry");
    expect(calls[0]).toMatchObject({ method: "GET", path: "/manage/page-state" });
    expect(document.title).toBe("Tu consentimiento · Consent App");
    expect(screen.getByRole("main")).toHaveClass("lp-page-container", "lp-manage-page");
    expect(screen.getByRole("main")).toHaveAccessibleName("Tu consentimiento");
    expect(screen.getByText("Antes de mostrarte cualquier información, necesitamos verificar tu identidad con un código.")).toBeInTheDocument();
    const btn = screen.getByRole("button", { name: "Verificar mi identidad" });
    expect(btn).toHaveAttribute("id", "start-verify-btn");
    expect(btn).toHaveAttribute("aria-disabled", "false");
    expect(btn).toHaveAttribute("aria-busy", "false");
    expect(btn).toHaveClass("lp-btn", "lp-btn-primary", "lp-cta", "lp-verify-tap-target");
    expect(container.querySelector("#start-revocation-btn")).toBeNull();
    expect(container.querySelector("#error-network")).toHaveAttribute("hidden");
    expect(container.querySelector("#error-uniform")).toHaveAttribute("hidden");
    expect(container.querySelector("#error-uniform")).toHaveTextContent("No pudimos continuar.");
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toBeInTheDocument();
    expectNoInlineStyleOrScript(container);
  });

  it("TEST-CNS-1919: estado (33:21): badge, finalidades con check decorativo, marcador [LEGAL DECISION] visible y CTA de retiro", async () => {
    const { container } = await renderVariant("status");
    const status = container.querySelector(".lp-manage-status")!;
    expect(status).toHaveAttribute("role", "status");
    expect(status).toHaveAttribute("aria-live", "polite");
    expect(screen.getByText("Consentimiento otorgado")).toHaveClass("lp-badge-success");
    expect(screen.getAllByRole("listitem").map((li) => li.textContent)).toEqual(["✓ Participar en el Estudio Beta", "✓ Grabación de audio", "✓ Análisis automatizado", "✓ Revisión humana"]);
    expect(status).toHaveTextContent("[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro (total, sin retiro parcial), protocolo l.423]");
    const btn = screen.getByRole("button", { name: "Retirar mi consentimiento" });
    expect(btn).toHaveAttribute("id", "start-revocation-btn");
    expect(btn).toHaveClass("lp-btn-danger", "lp-revocation-cta");
    expect(container.querySelector("#start-verify-btn")).toBeNull();
    expectNoInlineStyleOrScript(container);
  });

  it("TEST-CNS-1919: ya retirado (73:2): sin CTA de retirar, status neutro y enlace 'Contactar a soporte' como mailto", async () => {
    const { container } = await renderVariant("revoked");
    const status = container.querySelector("#manage-revoked")!;
    expect(status).toHaveAttribute("role", "status");
    expect(screen.getByText("Tu consentimiento ya fue retirado.")).toBeInTheDocument();
    expect(status).toHaveTextContent("protocolo l.522");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Contactar a soporte" })).toHaveAttribute("href", "mailto:ayuda@example.invalid");
    expect(screen.getByRole("link", { name: "Contactar a soporte" })).toHaveAttribute("id", "contact-support-btn");
    expect(container.textContent).not.toContain("GRANTED");
  });

  it("TEST-CNS-1920: 'Verificar mi identidad' -> POST /otp/request con CSRF, etiqueta de carga y va a /manage/verify", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => { release = r; });
    const { calls } = await renderVariant("entry", { "POST /otp/request": async () => { await gate; return empty(202); } });
    await userEvent.click(screen.getByRole("button", { name: "Verificar mi identidad" }));
    const busy = await screen.findByRole("button", { name: "Enviando código…" });
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await userEvent.click(busy);
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
    release();
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/manage/verify"));
    expectPostHeaders(calls.at(-1)!);
    expect(calls.at(-1)!.init.body).toBe("{}");
    expect(screen.getByRole("button", { name: "Verificar mi identidad" })).toHaveAttribute("aria-busy", "false");
  });

  it("TEST-CNS-1920: entrada: respuesta no OK -> error uniforme; red -> aviso con Reintentar que repite el envío", async () => {
    const { calls } = await renderVariant("entry", { "POST /otp/request": [empty(404), offline(), empty(202)] });
    await userEvent.click(screen.getByRole("button", { name: "Verificar mi identidad" }));
    const uniform = await screen.findByRole("alert");
    expect(uniform).toHaveAttribute("id", "error-uniform");
    expect(uniform).toHaveAttribute("aria-live", "assertive");
    expect(navigation.assign).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Verificar mi identidad" }));
    const net = await screen.findByRole("alert");
    expect(net).toHaveAttribute("id", "error-network");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/manage/verify"));
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(3);
  });

  it("TEST-CNS-1921: estado: 'Retirar mi consentimiento' -> POST /manage/revocation y luego POST /otp/request y va a /manage/revocation/verify", async () => {
    const { calls } = await renderVariant("status", { "POST /manage/revocation": json({ revocationRef: "x", status: "REQUESTED" }), "POST /otp/request": empty(202) });
    await userEvent.click(screen.getByRole("button", { name: "Retirar mi consentimiento" }));
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/manage/revocation/verify"));
    const posts = calls.filter((c) => c.method === "POST");
    expect(posts.map((c) => c.path)).toEqual(["/manage/revocation", "/otp/request"]);
    posts.forEach(expectPostHeaders);
  });

  it("TEST-CNS-1921: estado: R1 no OK -> uniforme sin pedir OTP; OTP no OK -> uniforme; red -> aviso y Reintentar vuelve a R1", async () => {
    const first = await renderVariant("status", { "POST /manage/revocation": empty(409) });
    await userEvent.click(screen.getByRole("button", { name: "Retirar mi consentimiento" }));
    expect((await screen.findByRole("alert")).id).toBe("error-uniform");
    expect(first.calls.filter((c) => c.method === "POST").map((c) => c.path)).toEqual(["/manage/revocation"]);
    first.unmount();
    vi.unstubAllGlobals();

    const second = await renderVariant("status", { "POST /manage/revocation": [empty(200), offline(), empty(200)], "POST /otp/request": [empty(404), empty(202)] });
    await userEvent.click(screen.getByRole("button", { name: "Retirar mi consentimiento" }));
    expect((await screen.findByRole("alert")).id).toBe("error-uniform");
    await userEvent.click(screen.getByRole("button", { name: "Retirar mi consentimiento" }));
    await waitFor(() => expect(screen.getByRole("alert").id).toBe("error-network"));
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/manage/revocation/verify"));
    expect(second.calls.filter((c) => c.path === "/manage/revocation")).toHaveLength(3);
  });

  it("TEST-CNS-1922: sin sesión (uniform-error o page-state 404) muestra 'Gestiona tu consentimiento' con alerta uniforme, 'Contactar a soporte' y ayuda; page-state caído ofrece Reintentar", async () => {
    const view = render(<ManagePage pageState="uniform-error" />);
    expect(screen.getByRole("heading", { level: 1, name: "Gestiona tu consentimiento" })).toHaveAttribute("id", "manage-h1");
    expect(screen.getByRole("alert")).toHaveTextContent("Este enlace ya no está disponible.");
    expect(screen.getByRole("alert")).toHaveTextContent("Esto no significa que se haya perdido tu posibilidad de gestionar tu consentimiento.");
    expect(screen.getByRole("link", { name: "Contactar a soporte" })).toHaveClass("lp-btn", "lp-btn-primary", "lp-cta", "lp-verify-tap-target");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    view.unmount();
    vi.unstubAllGlobals();

    stubRoutes({ "GET /manage/page-state": empty(404) });
    const notFound = render(<ManagePage pageState="ready" />);
    expect(await screen.findByRole("heading", { name: "Gestiona tu consentimiento" })).toBeInTheDocument();
    notFound.unmount();
    vi.unstubAllGlobals();

    const { calls } = stubRoutes({ "GET /manage/page-state": [offline(), json({ variant: "entry" })] });
    render(<ManagePage pageState="ready" />);
    expect((await screen.findByRole("alert")).id).toBe("error-network");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await screen.findByRole("button", { name: "Verificar mi identidad" });
    expect(calls).toHaveLength(2);
  });
});
