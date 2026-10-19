// Enlace de ayuda (misma posición relativa en todas las pantallas: fin del contenido, 3.2.6). F-E2E-04: `lp-verify-tap-target`
// (app.css) da el área táctil mínima (>= 24 CSS px, WCAG 2.5.8) sin cambiar el copy ni el estilo del enlace.
export function HelpLink() {
  return (
    <p className="lp-guest-help">
      <a href="mailto:ayuda@example.invalid" className="lp-link lp-verify-tap-target">¿Necesitas ayuda? Escríbenos a ayuda@example.invalid</a>
    </p>
  );
}
