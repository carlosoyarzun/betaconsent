// Gobierna: UX-CNS-002 (handoff /verify, scope DECISION) + ADR-001 F1 fase B. Equivale a verify-page.ts + assets/verify.js
// (scope INVITATION/DECISION). La pantalla vive en components/b/verify-screen.tsx, parametrizada por scope, para que
// /manage/verify y /manage/revocation/verify la reutilicen sin duplicar el comportamiento.
import { usePageTitle } from "../components/use-page-title.ts";
import { VerifyScreen, VerifyUniformError } from "../components/b/verify-screen.tsx";
import type { PageProps } from "../router.ts";

export function VerifyPage({ pageState }: PageProps) {
  usePageTitle("Verifica el código");
  if (pageState === "uniform-error") return <VerifyUniformError />;
  return <VerifyScreen scope="DECISION" />;
}
