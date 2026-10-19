// Alertas compartidas por /verify, /decision y /manage (fase B). Equivalen a los bloques `role="alert"` de verify-page.ts,
// decision-page.ts y manage-page.ts: se renderizan SIEMPRE con `hidden` para conservar el comportamiento de `aria-live`.
import type { ReactNode } from "react";
import { AlertHead } from "../alert-head.tsx";

/** `<div role="alert" aria-live="polite" class="lp-alert-warning" id="error-network" hidden>` + «Reintentar». */
export function NetworkAlert({ hidden, buttonClassName, onRetry }: { readonly hidden: boolean; readonly buttonClassName: string; readonly onRetry: () => void }) {
  return (
    <div role="alert" aria-live="polite" className="lp-alert-warning" id="error-network" hidden={hidden}>
      <AlertHead icon="warning" title="No pudimos conectar." />
      <p>Revisa tu conexión e inténtalo nuevamente.</p>
      <button type="button" className={buttonClassName} id="retry-btn" onClick={onRetry}>Reintentar</button>
    </div>
  );
}

/** `<div role="alert" aria-live="assertive" class="lp-alert-error" id="error-uniform" [hidden]>` con título y cuerpo. */
export function UniformAlert({ hidden, title, children }: { readonly hidden?: boolean; readonly title: string; readonly children: ReactNode }) {
  return (
    <div role="alert" aria-live="assertive" className="lp-alert-error" id="error-uniform" hidden={hidden}>
      <AlertHead icon="error" title={title} />
      {children}
    </div>
  );
}
