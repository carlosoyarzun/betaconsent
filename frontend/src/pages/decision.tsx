// Gobierna: ADR-001 F1 (migración de /decision). TODO(fase B): migrar desde decision-page.ts + assets/decision.js (necesita endpoint JSON para relaciones, versión servida y etiqueta del titular); patrón en pages/README.md.
// Esqueleto: la ruta ya está registrada en routes.ts; solo reemplazar el cuerpo de este componente.
import { usePageTitle } from "../components/use-page-title.ts";
import type { PageProps } from "../router.ts";

export function DecisionPage(_props: PageProps) {
  usePageTitle("Decisión");
  return (
    <main className="lp-page-container" aria-labelledby="todo-h1">
      <h1 id="todo-h1">Pantalla pendiente de migración</h1>
    </main>
  );
}
