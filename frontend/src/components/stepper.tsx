// Equivale a renderStepper() de guest-layout.ts: el texto "Paso n de 3 · etiqueta" es la información; las barras son aria-hidden.
export type StepNumber = 1 | 2 | 3;

const STEP_LABELS: Readonly<Record<StepNumber, string>> = { 1: "Verificación", 2: "Revisa y decide", 3: "Registro" };

export function Stepper({ step }: { readonly step: StepNumber }) {
  const bars: StepNumber[] = [1, 2, 3];
  return (
    <div className="lp-stepper">
      <div className="lp-stepper-bars" aria-hidden="true">
        {bars.map((i) => (
          <div key={i} className="lp-progress-bar">
            <div className={`lp-progress-fill ${i <= step ? "lp-stepper-fill-full" : "lp-stepper-fill-none"}`} />
          </div>
        ))}
      </div>
      <p className="lp-stepper-label">Paso {step} de 3 · {STEP_LABELS[step]}</p>
    </div>
  );
}
