// Gobierna: ADR-001 F1 (migración de /manage/revocation/verify). TODO(fase B): migrar desde verify-page.ts + assets/verify.js (scope REVOCATION; reusar el componente de verify.tsx); patrón en pages/README.md.
// Esqueleto: la ruta ya está registrada en routes.ts; solo reemplazar el cuerpo de este componente.
import { usePageTitle } from "../components/use-page-title.ts";
import type { PageProps } from "../router.ts";

export function RevocationVerifyPage(_props: PageProps) {
  usePageTitle("Verificación");
  return (
    <main className="lp-page-container" aria-labelledby="todo-h1">
      <h1 id="todo-h1">Pantalla pendiente de migración</h1>
    </main>
  );
}
