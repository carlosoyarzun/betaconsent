// Gobierna: UX-CNS-004 (33:87/33:96/33:106), API-CNS-135, F-PR6-25 (copy interino ERR-RV-22, token sin consumir), UX-CNS-015 F1/F2
// (foco, PR #110), ADR-001 F1 (fase C). /recovery/confirm (recovery-page.ts + recovery.js). TEST-CNS-1953…1959.
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RecoveryConfirmPage } from "../../src/pages/recovery-confirm.tsx";
import { calls, EXPECTED_HEADERS, expectNoInline, json, stubFetch } from "../c-helpers.ts";

const REVOCATION_REF = "8e2c4a6b-1d3f-4a5c-9b7e-0f2d4c6a8b10"; // sintética
const LEGAL_EFFECT = "[LEGAL DECISION — copy pendiente de aprobación de Carlos: efecto sobre los datos ya recolectados al revocar (supresión/plazos), protocolo l.522]";
const LEGAL_SCOPE = "[LEGAL DECISION — copy pendiente de aprobación de Carlos: alcance del retiro (total, sin retiro parcial) e irreversibilidad desde esta pantalla (protocolo l.423)]";

beforeEach(() => {
  document.cookie = "__Host-cns-csrf=csrf-token-1; Path=/; Secure";
});
afterEach(() => vi.unstubAllGlobals());

const confirmBtn = () => screen.getByRole("button", { name: /Confirmar retiro total|Confirmando…/ });

describe("/recovery/confirm (equivale a recovery-page.ts + recovery.js)", () => {
  it("TEST-CNS-1953: estructura, copy literal, marcadores [LEGAL DECISION] visibles (lp-revocation-legal-note) y bloques ocultos", () => {
    const { container } = render(<RecoveryConfirmPage pageState="ready" />);
    expect(document.title).toBe("Recuperar acceso · Consent App");
    const main = screen.getByRole("main");
    expect(main).toHaveClass("lp-page-container", "lp-revocation-page");
    expect(main).toHaveAccessibleName("Confirmar retiro");
    expect(screen.getByRole("heading", { level: 2, name: "Vas a retirar tu consentimiento" })).toBeInTheDocument();
    expect([...container.querySelectorAll("#recovery-form .lp-revocation-legal-note")].map((n) => n.textContent)).toEqual([LEGAL_EFFECT, LEGAL_SCOPE]);
    expect(confirmBtn()).toHaveAttribute("id", "confirm-recovery-btn");
    expect(confirmBtn()).toHaveClass("lp-btn", "lp-btn-danger", "lp-cta", "lp-revocation-cta", "lp-verify-tap-target");
    expect(confirmBtn()).toHaveAttribute("aria-disabled", "false");
    expect(confirmBtn()).toHaveAttribute("aria-busy", "false");
    for (const id of ["state-applied", "state-in-progress", "error-network", "error-uniform", "error-apply-failed"]) {
      expect(container.querySelector(`#${id}`), id).toHaveAttribute("hidden");
    }
    expect(container.querySelector("#error-apply-failed")).toHaveAttribute("tabindex", "-1");
    expect(container.querySelector("#error-network")).not.toHaveClass("lp-alert-warning"); // el SSR de recuperación no lo lleva
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expectNoInline(container);
  });

  it("TEST-CNS-1954: Confirmar -> un solo POST /recovery/revoke {confirmTotalWithdrawal:true} con CSRF; CONFIRMED -> comprobante con foco", async () => {
    const fn = stubFetch({ "/recovery/revoke": json(200, { state: "CONFIRMED", revocationRef: REVOCATION_REF }) });
    const { container } = render(<RecoveryConfirmPage pageState="ready" />);
    await userEvent.click(confirmBtn());
    const heading = await screen.findByRole("heading", { level: 2, name: "Retiramos tu consentimiento" });
    expect(heading).toHaveFocus();
    expect(container.querySelector("#recovery-form")).toHaveAttribute("hidden");
    expect(container.querySelector("#applied-receipt")).toHaveTextContent(`Comprobante: ${REVOCATION_REF}`);
    expect(screen.getByText("Nunca te mostraremos aquí el enlace de gestión: lo enviamos solo a la vía de contacto ya verificada.")).toBeInTheDocument();
    expect(fn).toHaveBeenCalledTimes(1);
    const [path, init] = calls(fn)[0]!;
    expect(path).toBe("/recovery/revoke");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("same-origin");
    expect(init.headers).toEqual(EXPECTED_HEADERS);
    expect(init.body).toBe(JSON.stringify({ confirmTotalWithdrawal: true }));
  });

  it("TEST-CNS-1955: durante la petición: aria-busy/aria-disabled con 'Confirmando…', el foco queda en el botón principal y no se duplica", async () => {
    let release: (r: Response) => void = () => undefined;
    const pending = new Promise<Response>((resolve) => { release = resolve; });
    const fn = stubFetch({ "/recovery/revoke": () => pending as unknown as Response });
    render(<RecoveryConfirmPage pageState="ready" />);
    await userEvent.click(confirmBtn());
    const busy = await screen.findByRole("button", { name: "Confirmando…" });
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(busy).toHaveAttribute("aria-disabled", "true");
    expect(busy).toHaveFocus();
    await userEvent.click(busy);
    expect(fn).toHaveBeenCalledTimes(1);
    release(json(200, { result: "IN_PROGRESS" }));
    const heading = await screen.findByRole("heading", { level: 2, name: "Este retiro ya está en curso" });
    expect(heading).toHaveFocus();
    expect(heading).toHaveAttribute("id", "in-progress-heading");
    expect(screen.getByText("Ya confirmamos este retiro antes: no necesitas hacer nada más.")).toBeInTheDocument();
  });

  it.each([
    ["202 uniforme (ERR-RV-05)", json(202)],
    ["404", json(404)],
    ["cuerpo sin estado reconocible", json(200, {})],
    ["error HTTP no previsto", json(500)],
  ])("TEST-CNS-1956: %s -> error uniforme (role=alert assertive, lp-alert-error)", async (_name, reply) => {
    stubFetch({ "/recovery/revoke": reply });
    render(<RecoveryConfirmPage pageState="ready" />);
    await userEvent.click(confirmBtn());
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "error-uniform");
    expect(alert).toHaveAttribute("aria-live", "assertive");
    expect(alert).toHaveClass("lp-alert-error");
    expect(alert).toHaveTextContent("No pudimos continuar con este retiro.");
  });

  it("TEST-CNS-1957: 503 (F-PR6-25) -> aviso ERR-RV-22 con foco, el enlace sigue válido (no es error uniforme) y 'Volver a intentar' reintenta el mismo POST", async () => {
    const fn = stubFetch({ "/recovery/revoke": (n) => (n < 3 ? json(503, { code: "GUARD_EVALUATOR_UNAVAILABLE" }) : json(200, { state: "CONFIRMED", revocationRef: REVOCATION_REF })) });
    const { container } = render(<RecoveryConfirmPage pageState="ready" />);
    const main = confirmBtn();
    await userEvent.click(main);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "error-apply-failed");
    expect(alert).toHaveFocus();
    expect(alert).toHaveTextContent("No pudimos completar tu retiro ahora");
    expect(alert).toHaveTextContent("Tu enlace sigue siendo válido, pero ocurrió un problema interno y el retiro no se completó. Tu autorización sigue vigente.");
    expect(alert).not.toHaveTextContent(/registrad|recibid|en proceso/i);
    expect(container.querySelector("#apply-failed-code")).toHaveTextContent("Código: ERR-RV-22");
    expect(container.querySelector("#error-uniform")).toHaveAttribute("hidden");
    expect(screen.getByRole("link", { name: "Escribir al equipo del estudio" })).toHaveAttribute("href", "mailto:ayuda@example.invalid");
    // PR #110: el foco pasa al botón principal ANTES de ocultar el aviso, y vuelve al aviso si falla otra vez.
    const retry = screen.getByRole("button", { name: "Volver a intentar" });
    expect(retry).toHaveClass("lp-btn", "lp-btn-primary", "lp-cta", "lp-verify-tap-target");
    await userEvent.click(retry);
    await waitFor(() => expect(fn).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(container.querySelector("#error-apply-failed")).not.toHaveAttribute("hidden"));
    expect(container.querySelector("#error-apply-failed")).toHaveFocus();
    await userEvent.click(screen.getByRole("button", { name: "Volver a intentar" }));
    const heading = await screen.findByRole("heading", { level: 2, name: "Retiramos tu consentimiento" });
    expect(heading).toHaveFocus();
    expect(container.querySelector("#error-apply-failed")).toHaveAttribute("hidden");
  });

  it("TEST-CNS-1958: al reintentar desde el aviso el foco pasa al botón principal (visible, aria-busy) y no cae a <body>", async () => {
    let release: (r: Response) => void = () => undefined;
    const pending = new Promise<Response>((resolve) => { release = resolve; });
    stubFetch({ "/recovery/revoke": (n) => (n === 1 ? json(503) : (pending as unknown as Response)) });
    render(<RecoveryConfirmPage pageState="ready" />);
    await userEvent.click(confirmBtn());
    await screen.findByRole("alert");
    await userEvent.click(screen.getByRole("button", { name: "Volver a intentar" }));
    const busy = await screen.findByRole("button", { name: "Confirmando…" });
    expect(busy).toHaveFocus();
    expect(busy).toHaveAttribute("aria-busy", "true");
    release(json(200, { result: "IN_PROGRESS" }));
    await screen.findByRole("heading", { name: "Este retiro ya está en curso" });
  });

  it("TEST-CNS-1959: falla de red -> aviso polite; 'Reintentar' repite el POST; estado uniform-error del servidor (33:106) con su ayuda", async () => {
    const fn = stubFetch({ "/recovery/revoke": (n) => (n === 1 ? new TypeError("offline") : json(200, { state: "CONFIRMED", revocationRef: REVOCATION_REF })) });
    const first = render(<RecoveryConfirmPage pageState="ready" />);
    await userEvent.click(confirmBtn());
    const net = await screen.findByRole("alert");
    expect(net).toHaveAttribute("id", "error-network");
    expect(net).toHaveAttribute("aria-live", "polite");
    expect(net).toHaveTextContent("No pudimos conectar.");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await screen.findByRole("heading", { name: "Retiramos tu consentimiento" });
    expect(fn).toHaveBeenCalledTimes(2);
    first.unmount();

    const { container } = render(<RecoveryConfirmPage pageState="uniform-error" />);
    expect(screen.getByRole("main")).toHaveAccessibleName("Confirmar retiro");
    expect(screen.getByRole("alert")).toHaveAttribute("id", "error-uniform");
    expect(screen.getByText("¿Tampoco tienes tu enlace de gestión? Contáctanos y te ayudamos a recuperar el acceso sin revelar datos de otras personas.")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toBeInTheDocument();
    expectNoInline(container);
  });
});
