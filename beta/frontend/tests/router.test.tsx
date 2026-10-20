import { render, screen } from "@testing-library/react";
import { act } from "react";
import { describe, expect, it } from "vitest";
import { App } from "../src/app.tsx";
import { matchRoute, navigate, readPageState } from "../src/router.ts";
import { ROUTES } from "../src/routes.ts";

describe("router", () => {
  it("registra exactamente las 8 rutas de los titulares", () => {
    expect(ROUTES.map((r) => r.path)).toEqual([
      "/welcome", "/verify", "/decision", "/manage", "/manage/verify", "/manage/revocation/verify", "/manage/revocation/confirm", "/recovery/confirm",
    ]);
  });

  it("matchRoute: igualdad exacta (tolera barra final, nada más)", () => {
    expect(matchRoute(ROUTES, "/welcome")?.path).toBe("/welcome");
    expect(matchRoute(ROUTES, "/welcome/")?.path).toBe("/welcome");
    expect(matchRoute(ROUTES, "/welcome/x")).toBeUndefined();
    expect(matchRoute(ROUTES, "/")).toBeUndefined();
  });

  it("readPageState lee el meta de index.html", () => {
    document.head.innerHTML = '<meta name="cns-page-state" content="uniform-error">';
    expect(readPageState()).toBe("uniform-error");
    document.head.innerHTML = '<meta name="cns-page-state" content="ready">';
    expect(readPageState()).toBe("ready");
    document.head.innerHTML = "";
    expect(readPageState()).toBe("ready");
  });

  it("App resuelve la página por pathname y reacciona a popstate", () => {
    window.history.pushState(null, "", "/welcome");
    render(<App />);
    expect(screen.getByRole("heading", { level: 1, name: "Bienvenida a la invitación" })).toBeInTheDocument();
    act(() => navigate("/verify"));
    expect(screen.getByRole("heading", { level: 1, name: "Verifica el código" })).toBeInTheDocument();
    act(() => navigate("/no-existe"));
    expect(screen.getByRole("heading", { level: 1, name: "Página no encontrada" })).toBeInTheDocument();
  });
});
