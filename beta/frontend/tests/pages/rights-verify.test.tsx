// Gobierna: UX-CNS-004 §3, INV-OT-06, ADR-001 F1 (fase C). /manage/verify y /manage/revocation/verify (verify-page.ts + verify.js).
// TEST-CNS-1934…1941.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ManageVerifyPage } from "../../src/pages/manage-verify.tsx";
import { RevocationVerifyPage } from "../../src/pages/revocation-verify.tsx";
import { navigation } from "../../src/router.ts";
import { calls, EXPECTED_HEADERS, expectNoInline, json, stubFetch } from "../c-helpers.ts";

const PAGES = [
  ["MANAGE", ManageVerifyPage, "/manage"],
  ["REVOCATION", RevocationVerifyPage, "/manage/revocation/confirm"],
] as const;

beforeEach(() => {
  document.cookie = "__Host-cns-csrf=csrf-token-1; Path=/; Secure";
  vi.spyOn(navigation, "assign").mockImplementation(() => undefined);
});
afterEach(() => vi.unstubAllGlobals());

describe.each(PAGES)("verify scope %s", (scope, Page, next) => {
  it(`TEST-CNS-1934: ${scope}: estructura, copy literal, ARIA y bloques ocultos como el SSR (sin stepper)`, () => {
    const { container } = render(<Page pageState="ready" />);
    const main = screen.getByRole("main");
    expect(main).toHaveClass("lp-page-container", "lp-verify-page");
    expect(main).toHaveAccessibleName("Verifica el código");
    expect(screen.getByRole("heading", { level: 1 })).toHaveAttribute("id", "verify-h1");
    expect(document.title).toBe("Verifica el código · Consent App");
    expect(container.querySelector(".lp-stepper")).toBeNull();
    const input = screen.getByLabelText("Código de verificación");
    expect(input).toHaveAttribute("id", "code-input");
    expect(input).toHaveAttribute("inputmode", "numeric");
    expect(input).toHaveAttribute("autocomplete", "one-time-code");
    expect(input).toHaveAttribute("placeholder", "Ingresa el código");
    expect(input).toHaveAttribute("aria-describedby", "code-help code-error");
    expect(input).toHaveAttribute("aria-invalid", "false");
    expect(container.querySelector("#code-help")).toHaveTextContent("Ingresa el código de [N] caracteres que enviamos (P-01, valor pendiente de aprobación). El código deja de funcionar después de [tiempo pendiente de aprobación] (P-02).");
    expect(screen.getByText("Puedes solicitarlo un número limitado de veces (P-06, valor pendiente de aprobación).")).toBeInTheDocument();
    const verify = screen.getByRole("button", { name: "Verificar" });
    expect(verify).toHaveClass("lp-btn", "lp-btn-primary", "lp-cta", "lp-verify-cta", "lp-verify-actions");
    expect(verify).toHaveAttribute("aria-disabled", "false");
    expect(verify).toHaveAttribute("aria-busy", "false");
    expect(screen.getByRole("button", { name: "Reenviar código" })).toHaveClass("lp-link", "lp-verify-tap-target");
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toHaveAttribute("href", "mailto:ayuda@example.invalid");
    for (const id of ["code-error", "state-expired", "state-locked-rights", "error-network", "error-uniform", "resend-feedback", "rights-locked-feedback"]) {
      expect(container.querySelector(`#${id}`), id).toHaveAttribute("hidden");
    }
    expect(container.querySelector("#state-locked")).toBeNull(); // el bloque de DECISION no existe en estos scopes
    expect(container.querySelector("#state-locked-rights")).toHaveAttribute("tabindex", "-1");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expectNoInline(container);
  });

  it(`TEST-CNS-1935: ${scope}: Verificar -> POST /otp/submit {code} con CSRF; 200 navega a ${next}`, async () => {
    const fn = stubFetch({ "/otp/submit": json(200, { result: "VERIFIED", scope }) });
    render(<Page pageState="ready" />);
    await userEvent.type(screen.getByLabelText("Código de verificación"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith(next));
    const [path, init] = calls(fn)[0]!;
    expect(path).toBe("/otp/submit");
    expect(init.method).toBe("POST");
    expect(init.credentials).toBe("same-origin");
    expect(init.headers).toEqual(EXPECTED_HEADERS);
    expect(init.body).toBe(JSON.stringify({ code: "123456" }));
    expect(screen.getByRole("button", { name: "Verificar" })).toHaveAttribute("aria-busy", "false");
  });
});

describe("verify scope MANAGE: estados de la respuesta de /otp/submit", () => {
  it("TEST-CNS-1936: durante la petición el botón queda aria-busy/aria-disabled con 'Verificando…' y un segundo clic no duplica", async () => {
    let release: (r: Response) => void = () => undefined;
    const pending = new Promise<Response>((resolve) => { release = resolve; });
    const fn = stubFetch({ "/otp/submit": () => pending as unknown as Response });
    render(<ManageVerifyPage pageState="ready" />);
    fireEvent.click(screen.getByRole("button", { name: "Verificar" }));
    const busy = await screen.findByRole("button", { name: "Verificando…" });
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(busy).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(busy);
    expect(fn).toHaveBeenCalledTimes(1);
    release(json(200));
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/manage"));
  });

  it.each([["OTP_CODE_REJECTED"], ["OTHER_CODE"]])("TEST-CNS-1937: código %s -> mensaje del campo (role=alert) y aria-invalid; no revela intentos", async (code) => {
    stubFetch({ "/otp/submit": json(422, { code }) });
    const { container } = render(<ManageVerifyPage pageState="ready" />);
    await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
    const err = await screen.findByRole("alert");
    expect(err).toHaveAttribute("id", "code-error");
    expect(err).toHaveTextContent("El código ingresado no es correcto. Revísalo e inténtalo nuevamente.");
    expect(screen.getByLabelText("Código de verificación")).toHaveAttribute("aria-invalid", "true");
    expect(container.querySelector("#state-locked-rights")).toHaveAttribute("hidden");
    expect(navigation.assign).not.toHaveBeenCalled();
  });

  it("TEST-CNS-1938: respuesta de error sin código en el cuerpo (p. ej. 500) no muestra ningún estado, como el .js", async () => {
    stubFetch({ "/otp/submit": new Response("", { status: 500 }) });
    render(<ManageVerifyPage pageState="ready" />);
    await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Verificar" })).toHaveAttribute("aria-busy", "false"));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(navigation.assign).not.toHaveBeenCalled();
  });

  it("TEST-CNS-1939: expirado -> aviso con 'Solicitar nuevo código' que hace POST /otp/request, limpia el campo y le da el foco", async () => {
    const fn = stubFetch({ "/otp/submit": json(409, { code: "OTP_EXPIRED_OR_CONSUMED" }), "/otp/request": json(202) });
    render(<ManageVerifyPage pageState="ready" />);
    const input = screen.getByLabelText("Código de verificación");
    await userEvent.type(input, "999999");
    await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "state-expired");
    expect(alert).toHaveClass("lp-alert-warning");
    expect(alert).toHaveTextContent("Este código ya no es válido.");
    await userEvent.click(screen.getByRole("button", { name: "Solicitar nuevo código" }));
    await waitFor(() => expect(input).toHaveFocus());
    expect(input).toHaveValue("");
    expect(calls(fn).map((c) => c[0])).toEqual(["/otp/submit", "/otp/request"]);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("TEST-CNS-1940: 404 en /otp/submit, /otp/request o /otp/resend -> error uniforme", async () => {
    stubFetch({ "/otp/submit": json(404), "/otp/resend": json(404) });
    const { unmount } = render(<ManageVerifyPage pageState="ready" />);
    await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
    expect(await screen.findByRole("alert")).toHaveAttribute("id", "error-uniform");
    expect(screen.getByRole("alert")).toHaveTextContent("No pudimos continuar con esta verificación.");
    unmount();
    render(<ManageVerifyPage pageState="ready" />);
    await userEvent.click(screen.getByRole("button", { name: "Reenviar código" }));
    expect(await screen.findByRole("alert")).toHaveAttribute("id", "error-uniform");
  });

  it.each([["OTP_LOCKED"], ["OTP_BUDGET_EXHAUSTED_DECISION"], ["OTP_BUDGET_EXHAUSTED_RIGHTS"]])(
    "TEST-CNS-1941: %s -> bloqueo RIGHTS (INV-OT-06): oculta el formulario, foco al aviso, sin 'nuevo código' ni 'denegado'; RV0/RC1 con su feedback",
    async (code) => {
      const fn = stubFetch({
        "/otp/submit": json(423, { code }),
        "/manage/recovery-link": json(202),
      });
      const { container } = render(<ManageVerifyPage pageState="ready" />);
      await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveAttribute("id", "state-locked-rights");
      expect(alert).toHaveFocus();
      expect(container.querySelector("#verify-form")).toHaveAttribute("hidden");
      expect(alert).toHaveTextContent("Bloqueamos este código por varios intentos incorrectos.");
      expect(alert).toHaveTextContent("Nunca pierdes la posibilidad de retirar tu consentimiento: elige una opción.");
      expect(alert).not.toHaveTextContent(/nuevo código|denegad/i);
      const feedback = container.querySelector("#rights-locked-feedback")!;
      await userEvent.click(screen.getByRole("button", { name: "Enviar enlace de recuperación" }));
      await waitFor(() => expect(feedback).toHaveTextContent("Si corresponde, enviamos un enlace a tu vía de contacto registrada."));
      expect(feedback).not.toHaveAttribute("hidden");
      await userEvent.click(screen.getByRole("button", { name: "Contactar al colegio" }));
      await waitFor(() => expect(feedback).toHaveTextContent("Si no puedes recibir el código, contacta al colegio. El colegio verificará tu identidad y te indicará cómo continuar."));
      const posts = calls(fn).slice(1);
      expect(posts.map((c) => c[0])).toEqual(["/manage/recovery-link"]);
      for (const [, init] of posts) {
        expect(init.headers).toEqual(EXPECTED_HEADERS);
        expect(init.body).toBe("{}");
      }
    },
  );
});

describe("verify scope MANAGE: reenvío, red y estado uniforme", () => {
  it("TEST-CNS-1942: Reenviar -> 202 'Te enviamos un nuevo código.' (status, éxito) limpia el error previo; 409 límite (aviso); icono aria-hidden", async () => {
    let n = 0;
    stubFetch({ "/otp/submit": json(422, { code: "OTP_CODE_REJECTED" }), "/otp/resend": () => (++n === 1 ? json(202) : json(409, { code: "OTP_RESEND_LIMIT" })) });
    const { container } = render(<ManageVerifyPage pageState="ready" />);
    await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
    await screen.findByRole("alert");
    await userEvent.click(screen.getByRole("button", { name: "Reenviar código" }));
    const fb = container.querySelector("#resend-feedback")!;
    await waitFor(() => expect(fb).toHaveTextContent("Te enviamos un nuevo código."));
    expect(fb).toHaveClass("lp-alert-success");
    expect(fb).toHaveAttribute("role", "status");
    expect(fb.querySelector("span")).toHaveAttribute("aria-hidden", "true");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Código de verificación")).toHaveAttribute("aria-invalid", "false");
    await userEvent.click(screen.getByRole("button", { name: "Reenviar código" }));
    await waitFor(() => expect(fb).toHaveTextContent("Alcanzaste el límite de reenvíos disponible por ahora."));
    expect(fb).toHaveClass("lp-alert-warning");
  });

  it("TEST-CNS-1943: falla de red en Verificar -> aviso polite; 'Reintentar' repite la última acción", async () => {
    const fn = stubFetch({ "/otp/submit": (n) => (n === 1 ? new TypeError("offline") : json(200)) });
    render(<ManageVerifyPage pageState="ready" />);
    await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "error-network");
    expect(alert).toHaveAttribute("aria-live", "polite");
    expect(alert).toHaveClass("lp-alert-warning");
    expect(alert).toHaveTextContent("No pudimos conectar.");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/manage"));
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("TEST-CNS-1944: estado uniform-error (404 del servidor): h1, alerta visible y ayuda; sin formulario", () => {
    const { container } = render(<RevocationVerifyPage pageState="uniform-error" />);
    expect(screen.getByRole("main")).toHaveAccessibleName("Verifica el código");
    expect(screen.getByRole("alert")).toHaveAttribute("id", "error-uniform");
    expect(screen.getByRole("alert")).toHaveTextContent("No pudimos continuar con esta verificación.");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toBeInTheDocument();
    expectNoInline(container);
  });
});
