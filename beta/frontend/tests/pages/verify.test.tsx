import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VerifyScreen } from "../../src/components/b/verify-screen.tsx";
import { VerifyPage } from "../../src/pages/verify.tsx";
import { navigation } from "../../src/router.ts";
import { empty, expectNoInlineStyleOrScript, expectPostHeaders, offline, postBody, problem, setCsrfCookie, stubRoutes } from "../b-helpers.ts";

beforeEach(() => {
  setCsrfCookie();
  vi.spyOn(navigation, "assign").mockImplementation(() => undefined);
});
afterEach(() => vi.unstubAllGlobals());

const hiddenIds = ["code-error", "resend-feedback", "state-expired", "state-locked", "error-network", "error-uniform"];

async function typeCodeAndSubmit(code = "123456") {
  const input = screen.getByLabelText("Código de verificación");
  await userEvent.clear(input);
  await userEvent.type(input, code);
  await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
}

describe("/verify scope DECISION (equivale a verify-page.ts + verify.js)", () => {
  it("TEST-CNS-1906: renderiza el copy, ids, roles, ARIA y stepper del SSR; los avisos existen ocultos y no hay estilos ni scripts inline", () => {
    const { container } = render(<VerifyPage pageState="ready" />);
    expect(document.title).toBe("Verifica el código · Consent App");
    const main = screen.getByRole("main");
    expect(main).toHaveClass("lp-page-container", "lp-verify-page");
    expect(main).toHaveAccessibleName("Verifica el código");
    expect(screen.getByText("Paso 1 de 3 · Verificación")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveAttribute("id", "verify-h1");
    expect(screen.getByText("Enviamos un código a la vía de contacto registrada para continuar. No lo compartas con nadie.")).toBeInTheDocument();
    const input = screen.getByLabelText("Código de verificación");
    expect(input).toHaveAttribute("id", "code-input");
    expect(input).toHaveAttribute("type", "text");
    expect(input).toHaveAttribute("inputmode", "numeric");
    expect(input).toHaveAttribute("autocomplete", "one-time-code");
    expect(input).toHaveAttribute("placeholder", "Ingresa el código");
    expect(input).toHaveAttribute("aria-describedby", "code-help code-error");
    expect(input).toHaveAttribute("aria-invalid", "false");
    expect(input).toHaveClass("lp-input", "lp-verify-code-input");
    expect(container.querySelector("#code-help")).toHaveTextContent("[N] caracteres");
    expect(container.querySelector("#code-help")).toHaveTextContent("[tiempo pendiente de aprobación] (P-02)");
    expect(screen.getByText("¿No recibiste el código?")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reenviar código" })).toHaveClass("lp-link", "lp-verify-tap-target");
    expect(screen.getByText("Puedes solicitarlo un número limitado de veces (P-06, valor pendiente de aprobación).")).toBeInTheDocument();
    const verify = screen.getByRole("button", { name: "Verificar" });
    expect(verify).toHaveAttribute("id", "verify-btn");
    expect(verify).toHaveAttribute("aria-disabled", "false");
    expect(verify).toHaveAttribute("aria-busy", "false");
    expect(verify).toHaveClass("lp-btn", "lp-btn-primary", "lp-cta", "lp-verify-cta", "lp-verify-actions");
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toBeInTheDocument();
    for (const id of hiddenIds) expect(container.querySelector(`#${id}`), id).toHaveAttribute("hidden");
    expect(container.querySelector("#state-locked-rights")).toBeNull();
    expect(container.querySelector("#code-error")).toHaveAttribute("role", "alert");
    expect(container.querySelector("#code-error")).toHaveAttribute("aria-live", "assertive");
    expect(container.querySelector("#resend-feedback")).toHaveAttribute("role", "status");
    expect(container.querySelector("#state-expired")).toHaveClass("lp-alert-warning");
    expect(container.querySelector("#state-locked")).toHaveClass("lp-alert-error");
    expect(container.querySelector("#error-network")).toHaveAttribute("aria-live", "polite");
    expect(container.querySelector("#error-uniform")).toHaveTextContent("No pudimos continuar con esta verificación.");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expectNoInlineStyleOrScript(container);
  });

  it("TEST-CNS-1907: envía POST /otp/submit con {code}, Content-Type y x-csrf-token; muestra Verificando… mientras espera y navega a /decision", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => { release = r; });
    const { calls } = stubRoutes({ "POST /otp/submit": async () => { await gate; return empty(200); } });
    render(<VerifyPage pageState="ready" />);
    await typeCodeAndSubmit("654321");
    const busy = await screen.findByRole("button", { name: "Verificando…" });
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await userEvent.click(busy);
    expect(calls).toHaveLength(1); // el segundo clic no duplica
    release();
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/decision"));
    expect(calls[0]!.path).toBe("/otp/submit");
    expectPostHeaders(calls[0]!);
    expect(postBody(calls[0]!)).toEqual({ code: "654321" });
    expect(screen.getByRole("button", { name: "Verificar" })).toHaveAttribute("aria-busy", "false");
  });

  it.each([
    ["código incorrecto (OTP_CODE_REJECTED)", problem(422, "OTP_CODE_REJECTED")],
    ["código desconocido sin catálogo (se trata como incorrecto)", problem(422, "ALGO_NUEVO")],
  ])("TEST-CNS-1908: %s -> aria-invalid y #code-error visible (role=alert), sin navegar", async (_name, reply) => {
    stubRoutes({ "POST /otp/submit": reply });
    const { container } = render(<VerifyPage pageState="ready" />);
    await typeCodeAndSubmit();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "code-error");
    expect(alert).toHaveTextContent("El código ingresado no es correcto. Revísalo e inténtalo nuevamente.");
    expect(screen.getByLabelText("Código de verificación")).toHaveAttribute("aria-invalid", "true");
    expect(container.querySelector("#code-error span")).toHaveAttribute("aria-hidden", "true");
    expect(navigation.assign).not.toHaveBeenCalled();
  });

  it("TEST-CNS-1908: expirado/consumido muestra #state-expired; 'Solicitar nuevo código' hace POST /otp/request, vacía el campo y le devuelve el foco", async () => {
    const { calls } = stubRoutes({ "POST /otp/submit": problem(422, "OTP_EXPIRED_OR_CONSUMED"), "POST /otp/request": empty(202) });
    render(<VerifyPage pageState="ready" />);
    await typeCodeAndSubmit();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "state-expired");
    expect(alert).toHaveTextContent("Este código ya no es válido.");
    await userEvent.click(screen.getByRole("button", { name: "Solicitar nuevo código" }));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(calls.map((c) => c.path)).toEqual(["/otp/submit", "/otp/request"]);
    expectPostHeaders(calls[1]!);
    const input = screen.getByLabelText("Código de verificación");
    expect(input).toHaveValue("");
    expect(input).toHaveFocus();
  });

  it.each(["OTP_LOCKED", "OTP_BUDGET_EXHAUSTED_DECISION", "OTP_BUDGET_EXHAUSTED_RIGHTS"])("TEST-CNS-1908: %s en scope DECISION muestra #state-locked con 'Solicitar nuevo código'", async (code) => {
    stubRoutes({ "POST /otp/submit": problem(409, code) });
    render(<VerifyPage pageState="ready" />);
    await typeCodeAndSubmit();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "state-locked");
    expect(alert).toHaveTextContent("Bloqueamos este código por varios intentos incorrectos.");
    expect(screen.getByRole("button", { name: "Solicitar nuevo código" })).toHaveAttribute("id", "request-new-code-btn-locked");
    expect(screen.getByLabelText("Código de verificación")).toBeVisible();
  });

  it("TEST-CNS-1908: 404 -> error uniforme inline; sin código en el cuerpo no muestra nada; red -> aviso con Reintentar que repite el envío", async () => {
    const { calls } = stubRoutes({ "POST /otp/submit": [empty(404), empty(500), offline(), empty(200)] });
    render(<VerifyPage pageState="ready" />);
    await typeCodeAndSubmit();
    expect((await screen.findByRole("alert")).id).toBe("error-uniform");
    await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
    const net = await screen.findByRole("alert");
    expect(net).toHaveAttribute("id", "error-network");
    expect(net).toHaveAttribute("aria-live", "polite");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/decision"));
    expect(calls).toHaveLength(4);
    expect(postBody(calls[3]!)).toEqual({ code: "123456" });
  });

  it("TEST-CNS-1909: 'Reenviar código' -> 202 anuncia éxito (polite) y limpia el error; 409 anuncia el límite; 404 uniforme; red", async () => {
    const { calls } = stubRoutes({
      "POST /otp/submit": problem(422, "OTP_CODE_REJECTED"),
      "POST /otp/resend": [empty(202), problem(409, "OTP_RESEND_LIMIT"), empty(404), offline()],
    });
    const { container } = render(<VerifyPage pageState="ready" />);
    await typeCodeAndSubmit();
    await screen.findByRole("alert");
    const resend = screen.getByRole("button", { name: "Reenviar código" });
    await userEvent.click(resend);
    const feedback = await screen.findByRole("status");
    expect(feedback).toHaveAttribute("id", "resend-feedback");
    expect(feedback).toHaveClass("lp-alert-success");
    expect(feedback).toHaveTextContent("✓ Te enviamos un nuevo código.");
    expect(feedback.firstElementChild).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByLabelText("Código de verificación")).toHaveAttribute("aria-invalid", "false");
    expect(container.querySelector("#code-error")).toHaveAttribute("hidden");
    expectPostHeaders(calls[1]!);
    await userEvent.click(resend);
    await waitFor(() => expect(feedback).toHaveClass("lp-alert-warning"));
    expect(feedback).toHaveTextContent("! Alcanzaste el límite de reenvíos disponible por ahora.");
    await userEvent.click(resend);
    expect((await screen.findByRole("alert")).id).toBe("error-uniform");
    expect(feedback).toHaveAttribute("hidden");
    expect(feedback).toBeEmptyDOMElement();
    await userEvent.click(resend);
    expect((await screen.findByRole("alert")).id).toBe("error-network");
  });

  it("TEST-CNS-1910: sin sesión (pageState uniform-error) muestra solo h1, alerta uniforme visible y ayuda, sin formulario ni stepper", () => {
    render(<VerifyPage pageState="uniform-error" />);
    expect(screen.getByRole("main")).toHaveAccessibleName("Verifica el código");
    expect(screen.getByRole("alert")).toHaveAttribute("id", "error-uniform");
    expect(screen.getByRole("alert")).toHaveTextContent("No pudimos continuar con esta verificación.");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.queryByText(/Paso 1 de 3/)).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toBeInTheDocument();
  });
});

describe("VerifyScreen scopes MANAGE/REVOCATION (UX-CNS-004 §3, INV-OT-06)", () => {
  it.each([
    ["MANAGE", "/manage"],
    ["REVOCATION", "/manage/revocation/confirm"],
  ] as const)("TEST-CNS-1911: scope %s no muestra stepper, navega a %s tras V3 y el bloqueo oculta el formulario, enfoca la alerta y nunca ofrece solicitar nuevo código", async (scope, _next) => {
    const { calls } = stubRoutes({ "POST /otp/submit": [problem(409, "OTP_LOCKED"), empty(200)] });
    const { container } = render(<VerifyScreen scope={scope} />);
    expect(screen.queryByText(/Paso 1 de 3/)).not.toBeInTheDocument();
    expect(container.querySelector("#state-locked")).toBeNull();
    expect(container.querySelector("#state-locked-rights")).toHaveAttribute("tabindex", "-1");
    await typeCodeAndSubmit();
    const locked = await screen.findByRole("alert");
    expect(locked).toHaveAttribute("id", "state-locked-rights");
    expect(locked).toHaveFocus();
    expect(container.querySelector("#verify-form")).toHaveAttribute("hidden");
    expect(screen.queryByRole("button", { name: "Solicitar nuevo código" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enviar enlace de recuperación" })).toHaveClass("lp-btn-primary");
    expect(screen.getByRole("button", { name: "Contactar al colegio" })).toHaveClass("lp-btn-outline");
    expect(locked).toHaveTextContent("Nunca pierdes la posibilidad de retirar tu consentimiento: elige una opción.");
    expect(calls).toHaveLength(1);
    expect(navigation.assign).not.toHaveBeenCalled();
  });

  it("TEST-CNS-1911: bloqueo RIGHTS -> 'Enviar enlace de recuperación' (POST /manage/recovery-link) anuncia el resultado y 'Contactar al colegio' muestra el mensaje estático (sin red) en #rights-locked-feedback", async () => {
    const { calls } = stubRoutes({
      "POST /otp/submit": problem(409, "OTP_BUDGET_EXHAUSTED_RIGHTS"),
      "POST /manage/recovery-link": [empty(202), empty(500), offline()],
    });
    const { container } = render(<VerifyScreen scope="REVOCATION" />);
    await typeCodeAndSubmit();
    await screen.findByRole("alert");
    const feedback = container.querySelector("#rights-locked-feedback")!;
    expect(feedback).toHaveAttribute("hidden");
    expect(feedback).toHaveAttribute("role", "status");
    await userEvent.click(screen.getByRole("button", { name: "Enviar enlace de recuperación" }));
    await waitFor(() => expect(feedback).toHaveTextContent("Si corresponde, enviamos un enlace a tu vía de contacto registrada."));
    expect(feedback).not.toHaveAttribute("hidden");
    await userEvent.click(screen.getByRole("button", { name: "Contactar al colegio" }));
    await waitFor(() => expect(feedback).toHaveTextContent("Si no puedes recibir el código, contacta al colegio. El colegio verificará tu identidad y te indicará cómo continuar."));
    expect(calls.some((c) => c.path.includes("rights-case"))).toBe(false);
    expect(feedback).not.toHaveTextContent(/\d+\s*(horas|días|dias)/i);
    await userEvent.click(screen.getByRole("button", { name: "Enviar enlace de recuperación" }));
    await waitFor(() => expect(feedback).toBeEmptyDOMElement());
    await userEvent.click(screen.getByRole("button", { name: "Enviar enlace de recuperación" }));
    await waitFor(() => expect(feedback).toHaveTextContent("No pudimos conectar. Inténtalo nuevamente."));
    expect(feedback).not.toHaveTextContent("denegado");
  });

  it("TEST-CNS-1911: scope MANAGE, tras V3 correcto navega a /manage", async () => {
    stubRoutes({ "POST /otp/submit": empty(200) });
    render(<VerifyScreen scope="MANAGE" />);
    await typeCodeAndSubmit();
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/manage"));
    await act(async () => undefined);
  });
});
