// Gobierna: ADR-001 F1 (migración de /manage). TODO(fase B): migrar desde manage-page.ts + assets/manage.js (necesita endpoint JSON para la variante entrada/estado/revocada); patrón en pages/README.md.
// Esqueleto: la ruta ya está registrada en routes.ts; solo reemplazar el cuerpo de este componente.
import { usePageTitle } from "../components/use-page-title.ts";
import type { PageProps } from "../router.ts";

export function ManagePage(_props: PageProps) {
  usePageTitle("Gestión");
  return (
    <main className="lp-page-container" aria-labelledby="todo-h1">
      <h1 id="todo-h1">Pantalla pendiente de migración</h1>
    </main>
  );
}
