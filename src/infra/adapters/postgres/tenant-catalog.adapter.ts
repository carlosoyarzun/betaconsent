// Gobierna: CA-124 (H09), PR-C; src/server/ports/tenant-catalog.port.ts,
// db/migrations/0005_tenant_catalog.sql, tenant-context.spec.yaml GRD-TC-03, invitation.spec.yaml
// GRD-IV-02, common.spec.yaml GRD-CM-03. Solo lectura (el dominio nunca crea sujetos ni
// participaciones; la siembra es de aprovisionamiento). Opera dentro de PgUnitOfWork.inTenant:
// RLS por app.current_tenant_id(); desconocido o de otro tenant = false/null (fail-closed).

import type { SchoolParticipationStatus, SchoolParticipationView, TenantCatalogPort } from "../../../server/ports/tenant-catalog.port.ts";
import type { TenantTx } from "./unit-of-work.ts";

interface ParticipationRow {
  participation_ref: string;
  context_ref: string;
  product_ref: string;
  status: SchoolParticipationStatus;
}

export function createPgTenantCatalogAdapter(tx: TenantTx): TenantCatalogPort {
  return {
    async subjectBelongsToTenant(tenantId, subjectRef) {
      const r = await tx.query("SELECT 1 FROM app.subject WHERE tenant_id = $1 AND subject_ref = $2", [tenantId, subjectRef]);
      return r.rows.length > 0;
    },
    async findParticipation(tenantId, participationRef) {
      const r = await tx.query<ParticipationRow>(
        `SELECT participation_ref, context_ref, product_ref, status FROM app.school_participation
          WHERE tenant_id = $1 AND participation_ref = $2`,
        [tenantId, participationRef],
      );
      const row = r.rows[0];
      return row
        ? { participationRef: row.participation_ref, contextRef: row.context_ref, productRef: row.product_ref, status: row.status }
        : null;
    },
  };
}
