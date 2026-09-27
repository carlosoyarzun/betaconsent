// Gobierna: specs/test-framework.spec.yaml (TEST-FRAMEWORK), ADR-001 §11 regla (4)
// ("cada puerto tiene una suite de contrato que pasan todos sus adaptadores").
//
// Puerto de EJEMPLO para el marco de tests (CA-118/H03). No es un puerto real de
// ADR-001 §11 (ObjectStorage, IdentityProvider, etc.) ni vive en src/server/ports/**:
// es un puerto ficticio, deliberadamente ajeno al dominio, que existe solo para que
// lampone-qa y lampone-dev tengan un ejemplo ejecutable de "la misma suite de contrato
// corre contra varios adaptadores" antes de que exista ningún puerto real en src/.

export interface ExampleCounterPort {
  /** Incrementa el contador en 1 y devuelve el nuevo valor. */
  increment(): Promise<number>;
  /** Devuelve el valor actual sin modificarlo. */
  get(): Promise<number>;
  /** Vuelve el contador a 0. */
  reset(): Promise<void>;
}
