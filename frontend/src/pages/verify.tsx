// Gobierna: ADR-001 F1 (migración de /verify). TODO(fase B): migrar desde verify-page.ts + assets/verify.js (scope INVITATION); patrón en pages/README.md.
// Esqueleto: la ruta ya está registrada en routes.ts; solo reemplazar el cuerpo de este componente.
import { usePageTitle } from "../components/use-page-title.ts";
import type { PageProps } from "../router.ts";

export function VerifyPage(_props: PageProps) {
  usePageTitle("Verificación");
  return (
    <main className="lp-page-container" aria-labelledby="todo-h1">
      <h1 id="todo-h1">Pantalla pendiente de migración</h1>
    </main>
  );
}
