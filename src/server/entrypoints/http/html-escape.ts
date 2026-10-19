// Gobierna: ADR-001 rev. 8 F1 (AD-1 cerrada: SSR de titulares retirado). Escape HTML compartido por la consola de staff
// (staff-ui-pages.ts), la consola dev y el e-mail de comprobante (guest-messages.ts). Antes vivía en guest-layout.ts /
// welcome-page.ts (páginas SSR del invitado, eliminadas). Todo valor dinámico interpolado en HTML pasa por aquí.

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
