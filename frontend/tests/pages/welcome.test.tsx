import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WelcomePage } from "../../src/pages/welcome.tsx";
import { navigation } from "../../src/router.ts";

type Reply = Response | Error;

function stubFetch(replies: Record<string, Reply>) {
  const fn = vi.fn(async (path: string) => {
    const reply = replies[path];
    if (!reply) throw new Error(`sin mock para ${path}`);
    if (reply instanceof Error) throw reply;
    return reply.clone();
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

const ok = () => new Response("{}", { status: 200 });

beforeEach(() => {
  document.cookie = "__Host-cns-csrf=csrf-token-1; Path=/; Secure";
  vi.spyOn(navigation, "assign").mockImplementation(() => undefined);
});
afterEach(() => vi.unstubAllGlobals());

describe("/welcome (equivale a welcome-page.ts + welcome.js)", () => {
  it("renderiza la estructura, el copy y los roles del SSR", () => {
    const { container } = render(<WelcomePage pageState="ready" />);
    const main = screen.getByRole("main");
    expect(main).toHaveClass("lp-page-container", "lp-welcome-page");
    expect(main).toHaveAccessibleName("Bienvenida a la invitación");
    expect(screen.getByRole("heading", { level: 1 })).toHaveAttribute("id", "welcome-h1");
    expect(screen.getByRole("region", { name: "Detalle de la invitación" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Cómo funciona" })).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    expect(screen.getByRole("complementary", { name: "¿Listo para comenzar?" })).toHaveClass("lp-welcome-aside");
    const buttons = screen.getAllByRole("button", { name: "Continuar" });
    expect(buttons.map((b) => b.id)).toEqual(["continue-btn", "continue-btn-aside"]);
    for (const b of buttons) {
      expect(b).toHaveAttribute("type", "button");
      expect(b).toHaveAttribute("data-continue");
      expect(b).toHaveAttribute("aria-disabled", "false");
      expect(b).toHaveAttribute("aria-busy", "false");
      expect(b).toHaveClass("lp-btn", "lp-btn-primary", "lp-cta", "lp-welcome-cta");
    }
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toHaveAttribute("href", "mailto:ayuda@example.invalid");
    // Los dos avisos existen pero ocultos (no son accesibles hasta mostrarse).
    expect(container.querySelector("#error-uniform")).toHaveAttribute("hidden");
    expect(container.querySelector("#error-network")).toHaveAttribute("hidden");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("flujo feliz: POST /invitation/open y /otp/request con cabeceras CSRF y luego va a /verify", async () => {
    const fetchMock = stubFetch({ "/invitation/open": ok(), "/otp/request": ok() });
    render(<WelcomePage pageState="ready" />);
    await userEvent.click(screen.getAllByRole("button", { name: "Continuar" })[0]!);
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/verify"));
    expect(fetchMock.mock.calls.map((c) => c[0])).toEqual(["/invitation/open", "/otp/request"]);
    for (const call of fetchMock.mock.calls as unknown as [string, RequestInit][]) {
      expect(call[1].method).toBe("POST");
      expect(call[1].credentials).toBe("same-origin");
      expect(call[1].headers).toEqual({ "content-type": "application/json", "x-csrf-token": "csrf-token-1" });
      expect(call[1].body).toBe("{}");
    }
  });

  it("durante la petición ambos botones quedan aria-busy/aria-disabled con la etiqueta de carga y el segundo clic no duplica", async () => {
    let release: (r: Response) => void = () => undefined;
    const pending = new Promise<Response>((resolve) => { release = resolve; });
    const fn = vi.fn((path: string) => (path === "/invitation/open" ? pending : Promise.resolve(ok())));
    vi.stubGlobal("fetch", fn);
    render(<WelcomePage pageState="ready" />);
    const [first, second] = screen.getAllByRole("button", { name: "Continuar" }) as [HTMLElement, HTMLElement];
    fireEvent.click(first);
    const busyButtons = await screen.findAllByRole("button", { name: "Abriendo invitación…" });
    expect(busyButtons).toHaveLength(2);
    for (const b of busyButtons) {
      expect(b).toHaveAttribute("aria-busy", "true");
      expect(b).toHaveAttribute("aria-disabled", "true");
    }
    fireEvent.click(second);
    expect(fn).toHaveBeenCalledTimes(1);
    release(ok());
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/verify"));
    expect(screen.getAllByRole("button", { name: "Continuar" })).toHaveLength(2);
  });

  it("respuesta no OK en /invitation/open: muestra el error uniforme (role=alert) y no pide OTP", async () => {
    const fetchMock = stubFetch({ "/invitation/open": new Response("{}", { status: 404 }) });
    render(<WelcomePage pageState="ready" />);
    await userEvent.click(screen.getAllByRole("button", { name: "Continuar" })[0]!);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "error-uniform");
    expect(alert).toHaveAttribute("aria-live", "assertive");
    expect(alert).toHaveClass("lp-alert-error");
    expect(alert).toHaveTextContent("No pudimos abrir esta invitación.");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(navigation.assign).not.toHaveBeenCalled();
    expect(screen.getAllByRole("button", { name: "Continuar" })).toHaveLength(2);
  });

  it("respuesta no OK en /otp/request: error uniforme", async () => {
    stubFetch({ "/invitation/open": ok(), "/otp/request": new Response("{}", { status: 409 }) });
    render(<WelcomePage pageState="ready" />);
    await userEvent.click(screen.getAllByRole("button", { name: "Continuar" })[1]!);
    expect(await screen.findByRole("alert")).toHaveAttribute("id", "error-uniform");
    expect(navigation.assign).not.toHaveBeenCalled();
  });

  it("falla de red: aviso polite con 'Reintentar', que reintenta el flujo", async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValue(ok());
    vi.stubGlobal("fetch", fn);
    render(<WelcomePage pageState="ready" />);
    await userEvent.click(screen.getAllByRole("button", { name: "Continuar" })[0]!);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveAttribute("id", "error-network");
    expect(alert).toHaveAttribute("aria-live", "polite");
    expect(alert).toHaveClass("lp-alert-warning");
    expect(alert).toHaveTextContent("No pudimos conectar.");
    await userEvent.click(screen.getByRole("button", { name: "Reintentar" }));
    await waitFor(() => expect(navigation.assign).toHaveBeenCalledWith("/verify"));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("no mueve el foco por su cuenta (como welcome.js): el botón pulsado conserva el foco", async () => {
    stubFetch({ "/invitation/open": new Response("{}", { status: 404 }) });
    render(<WelcomePage pageState="ready" />);
    const btn = screen.getAllByRole("button", { name: "Continuar" })[0]!;
    await userEvent.click(btn);
    await screen.findByRole("alert");
    expect(btn).toHaveFocus();
  });

  it("estado uniform-error (404 del servidor): solo h1, alerta visible y ayuda; sin botones", () => {
    render(<WelcomePage pageState="uniform-error" />);
    expect(screen.getByRole("main")).toHaveAccessibleName("Bienvenida a la invitación");
    expect(screen.getByRole("alert")).toHaveTextContent("No pudimos abrir esta invitación.");
    expect(screen.getByRole("alert")).toHaveAttribute("id", "error-uniform");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /ayuda@example.invalid/ })).toBeInTheDocument();
  });
});
