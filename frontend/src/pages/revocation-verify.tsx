// Gobierna: UX-CNS-004 §3 + ADR-001 F1 (fase C). Equivale a renderVerifyPage("REVOCATION") + assets/verify.js (scope REVOCATION).
import { RightsVerify } from "../components/c/rights-verify.tsx";
import type { PageProps } from "../router.ts";

export function RevocationVerifyPage(props: PageProps) {
  return <RightsVerify scope="REVOCATION" {...props} />;
}
