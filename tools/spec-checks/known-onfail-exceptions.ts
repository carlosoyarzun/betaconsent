// Gobierna: OPEN-RV-12 (specs/state-machines/revocation.spec.yaml), F-SEC-013-02 (SEC-CNS-013).
//
// OPEN-RV-12 (status: OPEN) dice literalmente: "errors[] de una transición no es sistemáticamente
// el cierre de onFail(guards); ... Se corrigió puntualmente en las transiciones tocadas por
// SEC-CNS-013 ...; falta un checker genérico que lo exija en todas. NO aplicado en esta ronda: solo
// se registra." Es decir: el propio spec de gobierno reconoce que la regla "errors ⊇ onFail(guards)"
// NO se cumple hoy en toda la spec, y que nadie la corrige todavía en las transiciones no tocadas por
// SEC-CNS-013.
//
// Esta lista es el inventario EXACTO (recalculado desde specs/state-machines/*.spec.yaml el
// 2026-09-27 por tools/spec-checks/h01-sm-checker.ts, ver README de este directorio para el método)
// de los huecos preexistentes: (unit, transitionId, guardId) donde el guard tiene onFail no nulo y
// ese error NO aparece en la lista `errors` de esa transición. Los guards GRD-CM-* (comunes,
// tenancy/CSRF/actor, común.spec.yaml) quedan FUERA de esta lista y del chequeo por completo: son
// guards transversales evaluados en toda ruta y sus onFail (ERR-CM-01, ERR-CM-02, ERR-CM-05,
// ERR-CM-09, ERR-CM-10, etc.) siguen la respuesta uniforme documentada en cada ERR-CM-* de
// common.spec.yaml ("En rutas del portador la respuesta externa es la uniforme de ERR-CM-01..."),
// un patrón análogo al de `globalErrors` (common.spec.yaml:156-158): no se espera que cada transición
// los liste explícitamente.
//
// El checker (h01-sm-checker.ts) SOLO tolera un hueco (unit, transitionId, guardId) si está en esta
// lista. Cualquier hueco NUEVO (guard no-CM con onFail fuera de `errors` en una combinación que no
// esté aquí) es un FALLO del checker (fail-closed para huecos nuevos, tal como pide OPEN-RV-12: "falta
// un checker genérico que lo exija en todas" — aquí no se exige retroactivamente sobre lo ya conocido,
// pero sí hacia delante).
//
// Regenerar esta lista (tras corregir specs, no antes) exige: (1) decisión humana de que el hueco
// corregido deja de ser una excepción, (2) quitar la fila correspondiente, (3) que el checker siga en
// PASS. Nunca se agrega una fila nueva sin ticket/cita que la respalde (evita que un guard nuevo con
// un hueco real se cuele como "conocido").
export interface KnownOnFailGap {
  unit: string;
  transition: string;
  guard: string;
}

export const KNOWN_ONFAIL_GAPS: readonly KnownOnFailGap[] = [
  { unit: "invitation", transition: "I3", guard: "GRD-IV-05" },
  { unit: "invitation", transition: "I3r", guard: "GRD-IV-04" },
  { unit: "invitation", transition: "I3r", guard: "GRD-IV-05" },
  { unit: "invitation", transition: "I4", guard: "GRD-IV-08" },
  { unit: "otp-challenge", transition: "V1", guard: "GRD-OT-03" },
  { unit: "otp-challenge", transition: "V1", guard: "GRD-OT-14" },
  { unit: "otp-challenge", transition: "V2", guard: "GRD-OT-13" },
  { unit: "otp-challenge", transition: "V2", guard: "GRD-OT-04" },
  { unit: "otp-challenge", transition: "V2", guard: "GRD-OT-03" },
  { unit: "otp-challenge", transition: "V2", guard: "GRD-OT-05" },
  { unit: "otp-challenge", transition: "V2r", guard: "GRD-OT-13" },
  { unit: "otp-challenge", transition: "V2r", guard: "GRD-OT-02" },
  { unit: "otp-challenge", transition: "V3", guard: "GRD-OT-13" },
  { unit: "otp-challenge", transition: "V3", guard: "GRD-OT-04" },
  { unit: "otp-challenge", transition: "V3", guard: "GRD-OT-07" },
  { unit: "otp-challenge", transition: "V6r", guard: "GRD-OT-03" },
  { unit: "consent-decision", transition: "C2", guard: "GRD-CD-01" },
  { unit: "consent-decision", transition: "C3", guard: "GRD-CD-05" },
  { unit: "consent-decision", transition: "C3", guard: "GRD-CD-12" },
  { unit: "consent-decision", transition: "C5", guard: "GRD-CD-05" },
  { unit: "consent-decision", transition: "C5", guard: "GRD-CD-12" },
  { unit: "consent-decision", transition: "C6", guard: "GRD-CD-09" },
  { unit: "revocation", transition: "R1", guard: "GRD-RV-02" },
  { unit: "revocation", transition: "R1", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R1", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R1r", guard: "GRD-RV-02" },
  { unit: "revocation", transition: "R1r", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R1r", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R1r", guard: "GRD-RV-25" },
  { unit: "revocation", transition: "RC3", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "RC3", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "RC3", guard: "GRD-RV-25" },
  { unit: "revocation", transition: "R2", guard: "GRD-RV-08" },
  { unit: "revocation", transition: "R2", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R2", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R2r", guard: "GRD-RV-18" },
  { unit: "revocation", transition: "R2r", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R2r", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "RH2", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R3", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R3", guard: "GRD-RV-24" },
  { unit: "revocation", transition: "R3r", guard: "GRD-RV-18" },
  { unit: "revocation", transition: "R3r", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R3r", guard: "GRD-RV-24" },
  { unit: "revocation", transition: "RH3", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "RH3", guard: "GRD-RV-24" },
  { unit: "revocation", transition: "RH3", guard: "GRD-RV-28" },
  { unit: "revocation", transition: "R4", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R4", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R4", guard: "GRD-RV-24" },
  { unit: "revocation", transition: "R5", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R6", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R7", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R8", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R9", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R10", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R10", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R11", guard: "GRD-RV-18" },
  { unit: "revocation", transition: "R11", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R11", guard: "GRD-RV-24" },
  { unit: "revocation", transition: "R12", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R12", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R12", guard: "GRD-RV-25" },
  { unit: "revocation", transition: "R12", guard: "GRD-RV-28" },
  { unit: "revocation", transition: "R12", guard: "GRD-RC-08" },
  { unit: "revocation", transition: "R12", guard: "GRD-RC-14" },
  { unit: "revocation", transition: "RH2v", guard: "GRD-RV-23" },
  { unit: "rights-case", transition: "RC0", guard: "GRD-RC-01" },
  { unit: "rights-case", transition: "RC1", guard: "GRD-RC-14" },
  { unit: "rights-case", transition: "RC2", guard: "GRD-RV-22" },
];

export function isKnownOnFailGap(unit: string, transition: string, guard: string): boolean {
  return KNOWN_ONFAIL_GAPS.some((g) => g.unit === unit && g.transition === transition && g.guard === guard);
}
