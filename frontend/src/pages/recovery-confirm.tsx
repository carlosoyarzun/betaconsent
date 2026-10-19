// Gobierna: ADR-001 F1 (migración de /recovery/confirm). TODO(fase B): migrar desde recovery-page.ts + assets/recovery.js + revocation-apply-failed-copy.ts; patrón en pages/README.md.
// Esqueleto: la ruta ya está registrada en routes.ts; solo reemplazar el cuerpo de este componente.
import { usePageTitle } from "../components/use-page-title.ts";
import type { PageProps } from "../router.ts";

export function RecoveryConfirmPage(_props: PageProps) {
  usePageTitle("Recuperación");
  return (
    <main className="lp-page-container" aria-labelledby="todo-h1">
      <h1 id="todo-h1">Pantalla pendiente de migración</h1>
    </main>
  );
}
