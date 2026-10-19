// Equivale a alertHead() de guest-layout.ts: icono decorativo (aria-hidden) + título (texto, no solo color).
export type AlertIcon = "error" | "warning" | "success" | "info";

const ALERT_GLYPH: Readonly<Record<AlertIcon, string>> = { error: "!", warning: "!", success: "✓", info: "i" };

export function AlertHead({ icon, title }: { readonly icon: AlertIcon; readonly title: string }) {
  return (
    <div className="lp-alert-head">
      <span className="lp-alert-icon" aria-hidden="true">{ALERT_GLYPH[icon]}</span>
      <span>{title}</span>
    </div>
  );
}
