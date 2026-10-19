// origen: src/server/entrypoints/http/guest-purposes.ts@9345b78
// Copy [UX — borrador]; la redacción final de cada descripción es [LEGAL DECISION] de Carlos.

export interface PurposeCopy {
  readonly purpose: string;
  readonly title: string;
  readonly description: string;
}

export const PURPOSES: readonly PurposeCopy[] = [
  { purpose: "STUDY_PARTICIPATION", title: "Participar en el Estudio Beta", description: "El estudiante participaría en sesiones de lectura del Estudio Beta de LectorPro." },
  { purpose: "AUDIO_RECORDING", title: "Grabación de audio", description: "Se grabaría el audio de las sesiones de lectura para poder analizarlas." },
  { purpose: "AUTOMATED_ANALYSIS", title: "Análisis automatizado", description: "El audio se analizaría con un motor automatizado de lectura." },
  { purpose: "HUMAN_REVIEW", title: "Revisión humana", description: "Una persona revisaría una muestra de los resultados para validar el análisis automatizado." },
];

export function purposeTitle(purpose: string): string {
  return PURPOSES.find((p) => p.purpose === purpose)?.title ?? purpose;
}
