// Gobierna: UX-CNS-003 (finalidades del Estudio Beta, specs/adapters/lectorpro-beta.spec.yaml:
// 4 finalidades requeridas) y UX-CNS-006 (comprobante). Copy compartido entre la pantalla de
// decisión y el comprobante por e-mail. [UX — borrador] con grounding en
// docs/LectorPro_Estudio_Beta_Protocolo_y_Metodologia_v1.0.md; la redacción final de cada
// descripción sigue siendo [LEGAL DECISION] (se marca en la pantalla; no se redacta copy legal).

export interface PurposeCopy {
  readonly purpose: string;
  readonly title: string;
  readonly description: string;
}

export const PURPOSES: readonly PurposeCopy[] = [
  {
    purpose: "STUDY_PARTICIPATION",
    title: "Participar en el Estudio Beta",
    description: "Tu hija o hijo participaría en sesiones de lectura del Estudio Beta de LectorPro.",
  },
  {
    purpose: "AUDIO_RECORDING",
    title: "Grabación de audio",
    description: "Se grabaría el audio de las sesiones de lectura para poder analizarlas.",
  },
  {
    purpose: "AUTOMATED_ANALYSIS",
    title: "Análisis automatizado",
    description: "El audio se analizaría con un motor automatizado de lectura.",
  },
  {
    purpose: "HUMAN_REVIEW",
    title: "Revisión humana",
    description: "Una persona revisaría una muestra de los resultados para validar el análisis automatizado.",
  },
];

export function purposeTitle(purpose: string): string {
  return PURPOSES.find((p) => p.purpose === purpose)?.title ?? purpose;
}
