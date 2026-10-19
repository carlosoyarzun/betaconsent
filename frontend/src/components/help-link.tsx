// Equivale a GUEST_HELP_LINK de guest-layout.ts (misma posición relativa en todas las pantallas: fin del contenido, 3.2.6).
export function HelpLink() {
  return (
    <p className="lp-guest-help">
      <a href="mailto:ayuda@example.invalid" className="lp-link">¿Necesitas ayuda? Escríbenos a ayuda@example.invalid</a>
    </p>
  );
}
