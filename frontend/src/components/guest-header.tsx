// Equivale a guestHeader() de guest-layout.ts. El badge "Prueba · IT0" es texto visible (no solo color).
export function GuestHeader() {
  return (
    <header className="lp-guest-header">
      <div className="lp-guest-brand">
        <span className="lp-guest-logo" aria-hidden="true">LP</span>
        <span>LectorPro · Estudio Beta</span>
      </div>
      <span className="lp-badge lp-badge-warning">
        <span className="lp-guest-env-short">Prueba · IT0</span>
        <span className="lp-guest-env-long">Entorno de prueba · IT0 · datos sintéticos</span>
      </span>
    </header>
  );
}
