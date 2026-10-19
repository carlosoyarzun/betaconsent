// Gobierna: UX-CNS-004 §3 + ADR-001 F1 (fase C). Equivale a renderVerifyPage("MANAGE") + assets/verify.js (scope MANAGE).
import { RightsVerify } from "../components/c/rights-verify.tsx";
import type { PageProps } from "../router.ts";

export function ManageVerifyPage(props: PageProps) {
  return <RightsVerify scope="MANAGE" {...props} />;
}
