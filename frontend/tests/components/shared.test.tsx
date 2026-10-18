import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AlertHead } from "../../src/components/alert-head.tsx";
import { GuestHeader } from "../../src/components/guest-header.tsx";
import { HelpLink } from "../../src/components/help-link.tsx";
import { Stepper } from "../../src/components/stepper.tsx";
import { usePageTitle } from "../../src/components/use-page-title.ts";

describe("GuestHeader (equivale a guestHeader())", () => {
  it("expone la marca, el badge de entorno como texto y el logo decorativo oculto", () => {
    const { container } = render(<GuestHeader />);
    expect(screen.getByRole("banner")).toHaveClass("lp-guest-header");
    expect(screen.getByText("LectorPro · Estudio Beta")).toBeInTheDocument();
    expect(screen.getByText("Prueba · IT0")).toHaveClass("lp-guest-env-short");
    expect(screen.getByText("Entorno de prueba · IT0 · datos sintéticos")).toHaveClass("lp-guest-env-long");
    expect(container.querySelector(".lp-guest-logo")).toHaveAttribute("aria-hidden", "true");
  });
});

describe("Stepper (equivale a renderStepper())", () => {
  it.each([
    [1, "Paso 1 de 3 · Verificación", ["full", "none", "none"]],
    [2, "Paso 2 de 3 · Revisa y decide", ["full", "full", "none"]],
    [3, "Paso 3 de 3 · Registro", ["full", "full", "full"]],
  ] as const)("paso %i: texto y barras", (step, label, fills) => {
    const { container } = render(<Stepper step={step} />);
    expect(screen.getByText(label)).toHaveClass("lp-stepper-label");
    expect(container.querySelector(".lp-stepper-bars")).toHaveAttribute("aria-hidden", "true");
    const bars = [...container.querySelectorAll(".lp-progress-fill")].map((el) => (el.classList.contains("lp-stepper-fill-full") ? "full" : "none"));
    expect(bars).toEqual(fills);
  });
});

describe("AlertHead (equivale a alertHead())", () => {
  it.each([
    ["error", "!"],
    ["warning", "!"],
    ["success", "✓"],
    ["info", "i"],
  ] as const)("icono %s decorativo + título como texto", (icon, glyph) => {
    const { container } = render(<AlertHead icon={icon} title="Título" />);
    const iconEl = container.querySelector(".lp-alert-icon");
    expect(iconEl).toHaveTextContent(glyph);
    expect(iconEl).toHaveAttribute("aria-hidden", "true");
    expect(screen.getByText("Título")).toBeInTheDocument();
  });
});

describe("HelpLink (equivale a GUEST_HELP_LINK)", () => {
  it("es un enlace mailto con la clase lp-link", () => {
    render(<HelpLink />);
    const link = screen.getByRole("link", { name: "¿Necesitas ayuda? Escríbenos a ayuda@example.invalid" });
    expect(link).toHaveAttribute("href", "mailto:ayuda@example.invalid");
    expect(link).toHaveClass("lp-link");
  });
});

describe("usePageTitle", () => {
  it("fija document.title con el sufijo de la app", () => {
    function Probe() {
      usePageTitle("Bienvenida a la invitación");
      return null;
    }
    render(<Probe />);
    expect(document.title).toBe("Bienvenida a la invitación · Consent App");
  });
});
