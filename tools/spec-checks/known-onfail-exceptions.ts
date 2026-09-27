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
// 2026-09-27 por tools/spec-checks/h01-sm-checker.ts, ver README de este directorio para el método;
// revisión SEC-CNS-014 C1/C2, misma fecha) de los huecos preexistentes: (unit, transitionId, guardId)
// donde el guard tiene onFail no nulo y ese error NO aparece en `errors` de esa transición NI en
// common.spec.yaml `globalErrors` (ERR-CM-06, ERR-CM-12; common.spec.yaml:156-158 — esos dos SÍ están
// exentos, porque el propio spec los declara aplicables a TODA transición de TODA spec: "el checker
// los cuenta como usados"). Ningún otro guard queda exento por prefijo: la revisión SEC-CNS-014
// corrigió una versión anterior de este checker que excluía todo GRD-CM-* sin base en las specs (no
// hay ningún globalErrors ni convención documentada que cubra ERR-CM-01/02/05/07/09/10 fuera de
// declararlos en `errors`); esa exclusión se retiró y sumó 72 huecos nuevos en 33 transiciones.
//
// El checker (h01-sm-checker.ts) SOLO tolera un hueco (unit, transitionId, guardId) si está en esta
// lista. Cualquier hueco NUEVO (guard con onFail fuera de `errors` ∪ globalErrors, en una combinación
// que no esté aquí) es un FALLO del checker (fail-closed para huecos nuevos, tal como pide OPEN-RV-12:
// "falta un checker genérico que lo exija en todas" — aquí no se exige retroactivamente sobre lo ya
// conocido, pero sí hacia delante).
//
// PRIORITARIO (SEC-CNS-014): las 21 filas de GRD-CM-02 (guard_T_tenant_consistency, onFail ERR-CM-02
// INVITER_TENANT_MISMATCH) son el grupo más grande y el de mayor riesgo — es el guard anti cross-tenant
// (SM-CNS-001 R0.4 "Guard T"). Que su error no esté listado en `errors[]` de 21 transiciones no prueba
// un fallo de aislamiento (el guard igual se evalúa y rechaza; esto es un hueco de DOCUMENTACIÓN del
// contrato de errores, no de la lógica), pero es el primer grupo a revisar y cerrar antes que el resto.
//
// Regenerar esta lista (tras corregir specs, no antes) exige: (1) decisión humana de que el hueco
// corregido deja de ser una excepción, (2) quitar la fila correspondiente, (3) que el checker siga en
// PASS. Nunca se agrega una fila nueva sin ticket/cita que la respalde (evita que un guard nuevo con
// un hueco real se cuele como "conocido"). Una fila se retira cuando deja de dispararse porque su
// onFail pasa a ser un globalError o porque la spec la corrige; no se retira "a mano" sin volver a
// correr el checker.
export interface KnownOnFailGap {
  unit: string;
  transition: string;
  guard: string;
}

export const KNOWN_ONFAIL_GAPS: readonly KnownOnFailGap[] = [
  // --- GRD-CM-02 (Guard T, cross-tenant): las 21 filas originales se cerraron el 2026-09-27
  // (SEC-CNS-014, aprobado por Carlos): se agregó ERR-CM-02 a errors[] en las 21 transiciones
  // (invitation I2/I3/I3r/I4/I5/I6/I7/I9, otp-challenge V1/V3, consent-decision C1/C2/C3/C5,
  // revocation R1/R2/R3/R8, rights-case RC0, tenant-context.Enrollment EN0/EN1). Ya no son
  // excepciones: el checker exige errors ⊇ onFail(GRD-CM-02) en esas transiciones.
  // --- Resto de GRD-CM-* (CM-01 15, CM-07 10, CM-06 9, CM-10 8, CM-05 4, CM-09 2, CM-03/04/08 1) ---
  { unit: "invitation", transition: "I1", guard: "GRD-CM-08" },
  { unit: "invitation", transition: "I2", guard: "GRD-CM-01" },
  { unit: "invitation", transition: "I2", guard: "GRD-CM-07" },
  { unit: "invitation", transition: "I3", guard: "GRD-CM-01" },
  { unit: "invitation", transition: "I3", guard: "GRD-CM-07" },
  { unit: "invitation", transition: "I3r", guard: "GRD-CM-01" },
  { unit: "invitation", transition: "I3r", guard: "GRD-CM-03" },
  { unit: "invitation", transition: "I3r", guard: "GRD-CM-04" },
  { unit: "invitation", transition: "I3r", guard: "GRD-CM-05" },
  { unit: "invitation", transition: "I3r", guard: "GRD-CM-07" },
  { unit: "invitation", transition: "I4", guard: "GRD-CM-01" },
  { unit: "invitation", transition: "I7u", guard: "GRD-CM-10" },
  { unit: "invitation", transition: "I9", guard: "GRD-CM-01" },
  { unit: "otp-challenge", transition: "V1", guard: "GRD-CM-01" },
  { unit: "otp-challenge", transition: "V1", guard: "GRD-CM-06" },
  { unit: "otp-challenge", transition: "V2r", guard: "GRD-CM-10" },
  { unit: "consent-decision", transition: "C1", guard: "GRD-CM-01" },
  { unit: "consent-decision", transition: "C1", guard: "GRD-CM-07" },
  { unit: "consent-decision", transition: "C2", guard: "GRD-CM-05" },
  { unit: "consent-decision", transition: "C2", guard: "GRD-CM-10" },
  { unit: "consent-decision", transition: "C3", guard: "GRD-CM-05" },
  { unit: "consent-decision", transition: "C3", guard: "GRD-CM-09" },
  { unit: "consent-decision", transition: "C3", guard: "GRD-CM-10" },
  { unit: "consent-decision", transition: "C4", guard: "GRD-CM-10" },
  { unit: "consent-decision", transition: "C5", guard: "GRD-CM-05" },
  { unit: "consent-decision", transition: "C5", guard: "GRD-CM-09" },
  { unit: "consent-decision", transition: "C5", guard: "GRD-CM-10" },
  { unit: "revocation", transition: "R1", guard: "GRD-CM-07" },
  { unit: "revocation", transition: "R1r", guard: "GRD-CM-01" },
  { unit: "revocation", transition: "R1r", guard: "GRD-CM-06" },
  { unit: "revocation", transition: "RC3", guard: "GRD-CM-07" },
  { unit: "revocation", transition: "R2", guard: "GRD-CM-06" },
  { unit: "revocation", transition: "R2", guard: "GRD-CM-07" },
  { unit: "revocation", transition: "R3", guard: "GRD-CM-06" },
  { unit: "revocation", transition: "R3", guard: "GRD-CM-07" },
  { unit: "revocation", transition: "R8", guard: "GRD-CM-01" },
  { unit: "revocation", transition: "R8", guard: "GRD-CM-06" },
  { unit: "revocation", transition: "R8", guard: "GRD-CM-07" },
  { unit: "revocation", transition: "R8h", guard: "GRD-CM-10" },
  { unit: "revocation", transition: "R10", guard: "GRD-CM-01" },
  { unit: "revocation", transition: "R10", guard: "GRD-CM-06" },
  { unit: "revocation", transition: "R11", guard: "GRD-CM-01" },
  { unit: "revocation", transition: "R11", guard: "GRD-CM-06" },
  { unit: "revocation", transition: "R12", guard: "GRD-CM-07" },
  { unit: "rights-case", transition: "RC0", guard: "GRD-CM-01" },
  { unit: "rights-case", transition: "RC1", guard: "GRD-CM-06" },
  { unit: "rights-case", transition: "RC1", guard: "GRD-CM-01" },
  { unit: "rights-case", transition: "RC1c", guard: "GRD-CM-10" },
  { unit: "tenant-context.Enrollment", transition: "EN0", guard: "GRD-CM-01" },
  { unit: "tenant-context.Enrollment", transition: "EN1", guard: "GRD-CM-01" },
  // --- Huecos preexistentes no-CM (F-SEC-013-02 original) ---
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
  { unit: "revocation", transition: "R2", guard: "GRD-RV-08" },
  { unit: "revocation", transition: "R2", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R2", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R2r", guard: "GRD-RV-18" },
  { unit: "revocation", transition: "R2r", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R2r", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R3", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R3r", guard: "GRD-RV-18" },
  { unit: "revocation", transition: "R3r", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R4", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R4", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R5", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R6", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R7", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R8", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R9", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R10", guard: "GRD-RV-19" },
  { unit: "revocation", transition: "R10", guard: "GRD-RV-23" },
  { unit: "revocation", transition: "R11", guard: "GRD-RV-18" },
  { unit: "revocation", transition: "R11", guard: "GRD-RV-23" },
  { unit: "rights-case", transition: "RC0", guard: "GRD-RC-01" },
  // --- Los 15 huecos "corregidos puntualmente" según OPEN-RV-12 (revocation.spec.yaml, texto de la
  // rev. previa) se cerraron el 2026-09-27 (SEC-CNS-014, aprobado por Carlos): revocation RH2
  // (GRD-RV-23), RH2v (GRD-RV-23), RH3 (GRD-RV-23, GRD-RV-28), R12 (GRD-RV-19, GRD-RV-23,
  // GRD-RV-25, GRD-RV-28, GRD-RC-08, GRD-RC-14), RC3 (GRD-RV-19, GRD-RV-23, GRD-RV-25);
  // rights-case RC1 (GRD-RC-14), RC2 (GRD-RV-22). Se agregó el onFail exacto de cada guard a
  // errors[] de la transición correspondiente. Ya no son excepciones.
];

export function isKnownOnFailGap(unit: string, transition: string, guard: string): boolean {
  return KNOWN_ONFAIL_GAPS.some((g) => g.unit === unit && g.transition === transition && g.guard === guard);
}
