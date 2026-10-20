// Router mínimo (sin react-router): 8 rutas fijas, `history`/`popstate`, enlaces <a> normales. Las transiciones entre
// pantallas del flujo son navegaciones COMPLETAS (`navigation.assign`): cada GET lo resuelve el servidor (sesión, cookie
// CSRF nueva, 404 uniforme), igual que hoy con `window.location.assign`.
import { useSyncExternalStore, type ComponentType } from "react";

export type PageState = "ready" | "uniform-error";

export interface PageProps {
  /** `uniform-error`: el servidor respondió 404 uniforme (INV-CM-05, sin sesión/handle válido); lo comunica con
   * `<meta name="cns-page-state">` en el propio index.html (sin scripts inline ni requests extra). */
  readonly pageState: PageState;
}

export interface RouteDef {
  readonly path: string;
  readonly title: string;
  readonly Page: ComponentType<PageProps>;
}

/** Punto único de navegación completa; los tests lo espían (jsdom no implementa `location.assign`). */
export const navigation = {
  assign(path: string): void {
    window.location.assign(path);
  },
};

function subscribe(onChange: () => void): () => void {
  window.addEventListener("popstate", onChange);
  return () => window.removeEventListener("popstate", onChange);
}

export function usePathname(): string {
  return useSyncExternalStore(subscribe, () => window.location.pathname, () => "/");
}

/** Navegación interna sin recarga (reservada; el flujo del invitado usa `navigation.assign`). */
export function navigate(path: string): void {
  window.history.pushState(null, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function matchRoute(routes: readonly RouteDef[], pathname: string): RouteDef | undefined {
  const normalized = pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
  return routes.find((route) => route.path === normalized);
}

export function readPageState(doc: Document = document): PageState {
  const content = doc.querySelector('meta[name="cns-page-state"]')?.getAttribute("content");
  return content === "uniform-error" ? "uniform-error" : "ready";
}
