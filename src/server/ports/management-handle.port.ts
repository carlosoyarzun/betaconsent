// Gobierna: revocation.spec.yaml managementLink (CFG-RV-MANAGEMENT-LINK: "issuedBy consent-decision C3 (con el
// receipt), solo al canal ligado"), consent-decision.spec.yaml C3 (:160), RECEIPT_CREATED.managementLinkIssued
// (:447-448), ADR-001 §11. Puerto de registro del handle del enlace de gestión (tenant_resolve.handle). Vive en
// TenantTxPorts: se escribe en la MISMA unidad de trabajo que el lote C3 (decisión + ledger + invitación), de modo
// que "GRANTED sin enlace registrado" no existe y el ledger dice la verdad (managementLinkIssued). Solo el HASH del
// handle cruza el puerto; el token en claro nunca persiste aquí.

export interface ManagementHandleRegistration {
  readonly tenantId: string;
  /** sha256 hex del handle en claro (hashTenantHandle). */
  readonly handleHash: string;
  readonly chainRef: string;
  readonly revokedDecisionRef: string;
}

export interface ManagementHandleRegistryPort {
  register(input: ManagementHandleRegistration): Promise<void>;
}
