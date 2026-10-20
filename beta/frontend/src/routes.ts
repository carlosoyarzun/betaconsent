// Tabla de rutas de la SPA: las 8 rutas HTML de los titulares (las que el servidor entrega como shell).
// Una página nueva SOLO reemplaza el cuerpo de su archivo pages/*.tsx; esta tabla no se toca (ver pages/README.md).
import type { RouteDef } from "./router.ts";
import { DecisionPage } from "./pages/decision.tsx";
import { ManagePage } from "./pages/manage.tsx";
import { ManageVerifyPage } from "./pages/manage-verify.tsx";
import { RecoveryConfirmPage } from "./pages/recovery-confirm.tsx";
import { RevocationConfirmPage } from "./pages/revocation-confirm.tsx";
import { RevocationVerifyPage } from "./pages/revocation-verify.tsx";
import { VerifyPage } from "./pages/verify.tsx";
import { WelcomePage } from "./pages/welcome.tsx";

export const ROUTES: readonly RouteDef[] = [
  { path: "/welcome", title: "Bienvenida a la invitación", Page: WelcomePage },
  { path: "/verify", title: "Verificación", Page: VerifyPage },
  { path: "/decision", title: "Decisión", Page: DecisionPage },
  { path: "/manage", title: "Gestión", Page: ManagePage },
  { path: "/manage/verify", title: "Verificación", Page: ManageVerifyPage },
  { path: "/manage/revocation/verify", title: "Verificación", Page: RevocationVerifyPage },
  { path: "/manage/revocation/confirm", title: "Confirmar retiro", Page: RevocationConfirmPage },
  { path: "/recovery/confirm", title: "Recuperación", Page: RecoveryConfirmPage },
];
