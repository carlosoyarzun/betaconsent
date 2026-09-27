// Gobierna: specs/adapters/lectorpro-beta.spec.yaml `configuration` (único adapter activo
// en IT0, F-012). Espejo tipado en TypeScript de esos valores; la spec YAML es la fuente de
// verdad (specs/ no se edita desde código). Si specs/adapters/lectorpro-beta.spec.yaml
// cambia, este archivo se actualiza en el mismo PR que la enmienda de la spec.

export interface LectorProBetaConfig {
  readonly contextRef: string;
  readonly productRef: string;
  readonly allowPartialGrant: boolean;
  readonly requiredPurposes: readonly string[];
  readonly prohibitedPurposes: readonly string[];
}

export const LECTORPRO_BETA_CONFIG: LectorProBetaConfig = {
  contextRef: "BETA_2026_01",
  productRef: "LECTORPRO",
  allowPartialGrant: false,
  requiredPurposes: ["STUDY_PARTICIPATION", "AUDIO_RECORDING", "AUTOMATED_ANALYSIS", "HUMAN_REVIEW"],
  prohibitedPurposes: ["PRODUCT_IMPROVEMENT", "AI_TRAINING", "RESEARCH"],
};
