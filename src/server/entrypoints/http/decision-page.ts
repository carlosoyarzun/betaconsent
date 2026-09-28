// Gobierna: CLAUDE.md (UX-CNS-002, /verify) — Carlos, 2026-09-27: "/decision, que por ahora es
// un placeholder mínimo con su test, igual que lo fue /verify". No hay handoff de ravena-ux ni
// frame de Figma para /decision todavía; este placeholder es deliberadamente mínimo y no debe
// tomarse como la pantalla final de la decisión de consentimiento. verify.js redirige aquí tras
// V3 (POST /otp/submit responde VERIFIED).

export function renderDecisionPlaceholderPage(): string {
  return `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Decisión · Consent App</title>
  <link rel="stylesheet" href="/assets/design-system/index.css">
  <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
  <main class="lp-page-container lp-welcome-page" aria-labelledby="decision-h1">
    <h1 id="decision-h1">Decisión</h1>
    <p>Esta es la siguiente pantalla pendiente del flujo (revisar y decidir). Todavía no está implementada.</p>
  </main>
</body>
</html>
`;
}
