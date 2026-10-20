// Gobierna: UX-CNS-004 (33:45/33:54/33:64), revocation.spec.yaml R2/R3/R8, F-PR6-25 (copy interino ERR-RV-21), ADR-001 F1 (fase C).
// /manage/revocation/confirm (revocation-page.ts + revocation.js). TEST-CNS-1945…1953.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RevocationConfirmPage } from "../../src/pages/revocation-confirm.tsx";
import { calls, EXPECTED_HEADERS, expectNoInline, json, stubFetch } from "../c-helpers.ts";

const REVOCATION_REF = "8e2c4a6b-1d3f-4a5c-9b7e-0f2d4c6a8b10"; // sintética
const LEGAL_EFFECT = "[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]";
const LEGAL_SCOPE = "[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro (total, sin retiro parcial) e irreversibilidad desde esta pantalla (protocolo l.423)]";

beforeEach(() => {
  document.cookie = "__Host-cns-csrf=csrf-token-1; Path=/; Secure";
});
afterEach(() => vi.unstubAllGlobals());

const confirmBtn = () => screen.getByRole("button", { name: /Confirmar retiro total|Confirmando…/ });

describe("/manage/revocation/confirm (equivale a revocation-page.ts + revocation.js)", () => {
  it("TEST-CNS-1945: estructura, copy literal, marcadores [LEGAL DECISION] visibles, clases y bloques ocultos; R2 al cargar con CSRF (una sola vez)", async () => {
    const fn = stubFetch({ "/manage/revocation/verify": json(200, { status: "VERIFIED" }) });
    const { container } = render(<RevocationConfirmPage pageState="ready" />);
    await waitFor(() => expect(fn).toHaveBeenCalledTimes(1));
    const [path, init] = calls(fn)[0]!;
    expect(path).toBe("/manage/revocation/verify");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual(EXPECTED_HEADERS);
    expect(init.body).toBe("{}");
    expect(document.title).toBe("Confirmar retiro · Consent App");
    const main = screen.getByRole("main");
    expect(main).toHaveClass("lp-page-container", "lp-revocation-page");
    expect(main).toHaveAccessibleName("Confirmar retiro");
    expect(screen.getByRole("heading", { level: 2, name: "Vas a retirar tu consentimiento" })).toBeInTheDocument();
    expect(screen.getByText("Vas a retirar tu consentimiento para el Estudio Beta de LectorPro.")).toBeInTheDocument();
    const notes = container.querySelectorAll("#revocation-form .lp-legal-note");
    expect([...notes].map((n) => n.textContent)).toEqual([LEGAL_EFFECT, LEGAL_SCOPE]);
    expect(confirmBtn()).toHaveClass("lp-btn", "lp-btn-danger", "lp-cta", "lp-revocation-cta", "lp-verify-tap-target");
    expect(confirmBtn()).toHaveAttribute("aria-disabled", "false");
    expect(confirmBtn()).toHaveAttribute("aria-busy", "false");
    expect(screen.getByRole("button", { name: "Cancelar solicitud de retiro" })).toHaveClass("lp-btn-outline");
    expect(container.querySelector(".lp-actions-stack")).toBeInTheDocument();
    for (const id of ["state-applied", "state-withdrawn", "error-network", "error-uniform", "error-apply-failed"]) {
      expect(container.querySelector(`#${id}`), id).toHaveAttribute("hidden");
    }
    expect(container.querySelector("#error-apply-failed")).toHaveAttribute("tabindex", "-1");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expectNoInline(container);
  });

  it("TEST-CNS-1946: R2 al cargar: un fallo de red muestra el aviso; una respuesta HTTP de error se ignora (como el .js)", async () => {
    stubFetch({ "/manage/revocation/verify": new TypeError("offline") });
    const first = render(<RevocationConfirmPage pageState="ready" />);
    expect(await screen.findByRole("alert")).toHaveAttribute("id", "error-network");
    first.unmount();
    stubFetch({ "/manage/revocation/verify": json(404) });
    render(<RevocationConfirmPage pageState="ready" />);
    await waitFor(() => expect(fetch).toHaveBeenCalled());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("TEST-CNS-1947: Confirmar -> R3 (POST /manage/revocation/confirm) -> reemplaza el formulario por el comprobante y le da el foco al h1", async () => {
    const fn = stubFetch({ "/manage/revocation/verify": json(200), "/manage/revocation/confirm": json(200, { revocationRef: REVOCATION_REF, status: "APPLIED" }) });
    const { container } = render(<RevocationConfirmPage pageState="ready" />);
    await userEvent.click(confirmBtn());
    const heading = await screen.findByRole("heading", { level: 1, name: "Retiramos tu consentimiento" });
    expect(heading).toHaveFocus();
    expect(heading).toHaveAttribute("id", "applied-heading");
    expect(container.querySelector("#revocation-form")).toHaveAttribute("hidden");
    expect(container.querySelector("#state-applied")).not.toHaveAttribute("hidden");
    expect(container.querySelector("#state-applied")).toHaveAttribute("role", "status");
    expect(container.querySelector("#applied-receipt")).toHaveTextContent(REVOCATION_REF);
    expect(container.querySelector("#applied-receipt")).toHaveClass("lp-receipt-ref");
    expect(screen.getByText("Comprobante de prueba · marca de agua IT0 · datos sintéticos")).toHaveClass("lp-badge", "lp-badge-warning");
    expect(screen.getByText("Nunca te mostraremos aquí el enlace de gestión: lo enviamos solo a la vía de contacto ya verificada.")).toBeInTheDocument();
    expect(calls(fn)[1]![0]).toBe("/manage/revocation/confirm");
    expect(calls(fn)[1]![1].headers).toEqual(EXPECTED_HEADERS);
    expect(calls(fn)[1]![1].body).toBe("{}");
  });

  it("TEST-CNS-1948: durante R3 el botón queda aria-busy/aria-disabled con 'Confirmando…' y un segundo clic no duplica", async () => {
    let release: (r: Response) => void = () => undefined;
    const pending = new Promise<Response>((resolve) => { release = resolve; });
    const fn = stubFetch({ "/manage/revocation/verify": json(200), "/manage/revocation/confirm": () => pending as unknown as Response });
    render(<RevocationConfirmPage pageState="ready" />);
    await userEvent.click(confirmBtn());
    const busy = await screen.findByRole("button", { name: "Confirmando…" });
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await userEvent.click(busy);
    expect(fn.mock.calls.filter((c) => c[0] === "/manage/revocation/confirm")).toHaveLength(1);
    release(json(200, { revocationRef: REVOCATION_REF }));
    await screen.findByRole("heading", { name: "Retiramos tu consentimiento" });
  });

  it("TEST-CNS-1949: 404 -> error uniforme; falla de red -> aviso con 'Reintentar' que repite la acción", async () => {
    let n = 0;
    stubFetch({
      "/manage/revocation/verify": json(200),
      "/manage/revocation/confirm": () => (++n === 1 ? json(404) : n === 2 ? new TypeError("offline") : json(200, { revocationRef: REVOCATION_REF })),
    });
    render(<RevocationConfirmPage pageState="ready" />);
    await userEvent.click(confirmBtn());
    const uniform = await screen.findByRole("alert");
    expect(uniform).toHaveAttribute("id", "error-uniform");
    expect(uniform).toHaveClass("lp-alert-error");
    expect(uniform).toHaveTextContent("No pudimos continuar con este retiro.");
    await userEvent.click(confirmBtn());
    const net = await screen.findByRole("alert");
    expect(net).toHaveAttribute("id", "error-network");
    expect(net).toHaveClass("lp-alert-warning");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await screen.findByRole("heading", { name: "Retiramos tu consentimiento" });
  });

  it("TEST-CNS-1950: 503 (F-PR6-25) -> aviso ERR-RV-21 con foco, NO es acuse ni error uniforme; 'Empezar de nuevo' enlaza a /manage", async () => {
    stubFetch({ "/manage/revocation/verify": json(200), "/manage/revocation/confirm": json(503, { code: "GUARD_EVALUATOR_UNAVAILABLE" }) });
    const { container } = render(<RevocationConfirmPage pageState="ready" />);
    await userEvent.click(confirmBtn());
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "error-apply-failed");
    expect(alert).toHaveFocus();
    expect(alert).toHaveClass("lp-alert-error");
    expect(alert).toHaveTextContent("No pudimos completar tu retiro");
    expect(alert).toHaveTextContent("Ocurrió un problema interno y tu retiro no se completó. Tu autorización sigue vigente.");
    expect(alert).not.toHaveTextContent(/registrad|recibid|en proceso/i);
    expect(container.querySelector("#apply-failed-code")).toHaveTextContent("Código: ERR-RV-21");
    const link = screen.getByRole("link", { name: "Empezar de nuevo" });
    expect(link).toHaveAttribute("href", "/manage");
    expect(link).toHaveAttribute("id", "new-code-link");
    expect(link).toHaveClass("lp-btn", "lp-btn-primary", "lp-cta", "lp-verify-tap-target");
    expect(screen.getByRole("link", { name: "Escribir al equipo del estudio" })).toHaveAttribute("href", "mailto:ayuda@example.invalid");
    expect(container.querySelector("#state-applied")).toHaveAttribute("hidden");
    expect(container.querySelector("#error-uniform")).toHaveAttribute("hidden");
    expect(container.querySelector("#revocation-form")).not.toHaveAttribute("hidden");
  });

  it("TEST-CNS-1951: Cancelar solicitud -> R8 (POST /manage/revocation/withdraw) -> 'Cancelamos tu solicitud de retiro' con foco; 404 -> uniforme", async () => {
    const fn = stubFetch({ "/manage/revocation/verify": json(200), "/manage/revocation/withdraw": json(200, { status: "FAILED" }) });
    const { container } = render(<RevocationConfirmPage pageState="ready" />);
    await userEvent.click(screen.getByRole("button", { name: "Cancelar solicitud de retiro" }));
    const heading = await screen.findByRole("heading", { level: 1, name: "Cancelamos tu solicitud de retiro" });
    expect(heading).toHaveFocus();
    expect(container.querySelector("#revocation-form")).toHaveAttribute("hidden");
    expect(screen.getByText("Tu consentimiento sigue vigente. Puedes volver a solicitar el retiro cuando quieras.")).toBeInTheDocument();
    expect(calls(fn)[1]![0]).toBe("/manage/revocation/withdraw");
    expect(calls(fn)[1]![1].headers).toEqual(EXPECTED_HEADERS);
    expect(calls(fn)[1]![1].body).toBe("{}");

    stubFetch({ "/manage/revocation/verify": json(200), "/manage/revocation/withdraw": json(404) });
    render(<RevocationConfirmPage pageState="ready" />);
    await userEvent.click(screen.getAllByRole("button", { name: "Cancelar solicitud de retiro" })[0]!);
    await waitFor(() => expect(screen.getAllByRole("alert").some((a) => a.id === "error-uniform")).toBe(true));
  });

  it("TEST-CNS-1952: estado uniform-error (404 del servidor): solo h1, alerta, ayuda; no se hace R2", () => {
    const fn = stubFetch({});
    const { container } = render(<RevocationConfirmPage pageState="uniform-error" />);
    expect(screen.getByRole("main")).toHaveAccessibleName("Confirmar retiro");
    expect(screen.getByRole("alert")).toHaveAttribute("id", "error-uniform");
    expect(screen.getByRole("alert")).toHaveTextContent("No pudimos continuar con este retiro.");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toBeInTheDocument();
    expect(fn).not.toHaveBeenCalled();
    expectNoInline(container);
  });
});
