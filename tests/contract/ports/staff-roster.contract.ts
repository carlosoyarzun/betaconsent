// Gobierna: src/server/ports/staff-roster.port.ts, API-CNS-116 (GET /staff/roster), diseno
// api-cns-116-staff-list-design.md rev. 2 §5 (mapeo PC-1/PC-2), §3 (keyset R6), REQ-CNS-036 AC-05/AC-06, DEC-BR-019,
// SEC-CNS-018 rev. 2. Suite de contrato compartida memoria/Postgres: las MISMAS escenas corren contra el adaptador
// in-memory y contra la vista app.staff_roster_invitation_status. TEST-CNS-1070..1074. Solo datos sinteticos.
//
// Las escenas son factibles en Postgres hoy: a lo mas UNA invitacion "no terminal" por (tenant, contexto, sujeto)
// (GRD-IV-01, unico parcial 0010) y solo los estados que persiste el CHECK invitation_state_enum.

import assert from "node:assert/strict";

import type { InvitationState } from "../../../src/server/ports/invitation-repository.port.ts";
import type { StaffInvitationStatus, StaffRosterKeysetAfter, StaffRosterProjectionRow } from "../../../src/server/ports/staff-roster.port.ts";
import { fixtureUuid } from "../uuid-fixture.ts";

const HOUR = 3_600_000;

export interface SceneInvitation {
  readonly subjectRef: string;
  readonly contextRef: string;
  readonly state: InvitationState;
  /** Desfase respecto del reloj de la BD/proceso en ms (negativo = ya vencida); null = sin vencimiento. */
  readonly expiresInMs: number | null;
}

export interface RosterScene {
  readonly tenantId: string;
  readonly subjects: readonly string[];
  readonly participations: readonly { readonly participationRef: string; readonly contextRef: string }[];
  readonly enrollments?: readonly { readonly subjectRef: string; readonly participationRef: string; readonly state: "ACTIVE" | "CLOSED" }[];
  /** En orden de creacion (la ultima es la mas reciente). */
  readonly invitations?: readonly SceneInvitation[];
}

export interface RosterHarness {
  seed(scene: RosterScene): Promise<void>;
  read(request: { tenantId: string; principalRef?: string; after?: StaffRosterKeysetAfter | null; rowLimit: number }): Promise<readonly StaffRosterProjectionRow[]>;
  /** Filas STAFF_ROSTER_READ del tenant (resource_ref = tenant_id). */
  accessLogRows(tenantId: string): Promise<readonly { readonly actorRef: string; readonly resourceRef: string }[]>;
}

export type RegisterStaffRosterTest = (name: string, body: (h: RosterHarness) => Promise<void>) => void;

const byC = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

async function readAll(h: RosterHarness, tenantId: string): Promise<readonly StaffRosterProjectionRow[]> {
  return h.read({ tenantId, rowLimit: 1000 });
}

export function runStaffRosterContract(adapterName: string, register: RegisterStaffRosterTest): void {
  const name = (id: string, text: string): string => `${id} StaffRoster contract (${adapterName}): ${text}`;

  register(name("TEST-CNS-1070", "mapeo de cada estado persistible a su estado operativo, con expiracion perezosa (D1, D9, PC-1)"), async (h) => {
    const tenantId = fixtureUuid("t1070");
    const cases: Array<[InvitationState | null, number | null, StaffInvitationStatus]> = [
      [null, null, "NOT_INVITED"],
      ["DRAFT", null, "PENDING_SEND"],
      ["DRAFT", -HOUR, "PENDING_SEND"],
      ["READY", null, "PENDING_SEND"],
      ["READY", HOUR, "PENDING_SEND"],
      ["READY", -HOUR, "CLOSED_WITHOUT_DECISION"],
      ["SENT", HOUR, "SENT"],
      ["SENT", -HOUR, "CLOSED_WITHOUT_DECISION"],
      ["OPENED", HOUR, "SENT"],
      ["OPENED", -HOUR, "CLOSED_WITHOUT_DECISION"],
      ["VERIFIED", HOUR, "SENT"],
      ["VERIFIED", -HOUR, "CLOSED_WITHOUT_DECISION"],
      ["COMPLETED", null, "DECISION_RECORDED"],
      ["COMPLETED", HOUR, "DECISION_RECORDED"],
      ["COMPLETED", -HOUR, "DECISION_RECORDED"],
      ["DECLINED", HOUR, "DECISION_RECORDED"],
      ["DECLINED", -HOUR, "DECISION_RECORDED"],
    ];
    const subjects = cases.map((_, i) => fixtureUuid(`s1070-${i}`));
    await h.seed({
      tenantId,
      subjects,
      participations: [{ participationRef: fixtureUuid("p1070"), contextRef: "CTX_A" }],
      invitations: cases.flatMap(([state, expiresInMs], i) =>
        state === null ? [] : [{ subjectRef: subjects[i] as string, contextRef: "CTX_A", state, expiresInMs }],
      ),
    });
    const rows = await readAll(h, tenantId);
    assert.equal(rows.length, cases.length);
    const byRef = new Map(rows.map((r) => [r.subjectRef, r.staffStatus]));
    cases.forEach(([state, expires, expected], i) => {
      assert.equal(byRef.get(subjects[i] as string), expected, `${state ?? "sin invitacion"} expires=${expires} -> ${expected}`);
    });
  });

  register(name("TEST-CNS-1071", "prioridad PC-2: no terminal efectiva > cualquier decision > cerrada; COMPLETED y DECLINED indistinguibles"), async (h) => {
    const tenantId = fixtureUuid("t1071");
    const [a, b, c, d, e] = ["s1071-a", "s1071-b", "s1071-c", "s1071-d", "s1071-e"].map((l) => fixtureUuid(l)) as [string, string, string, string, string];
    await h.seed({
      tenantId,
      subjects: [a, b, c, d, e],
      participations: [{ participationRef: fixtureUuid("p1071"), contextRef: "CTX_A" }],
      invitations: [
        // a: decision antigua + borrador nuevo -> manda la no terminal.
        { subjectRef: a, contextRef: "CTX_A", state: "COMPLETED", expiresInMs: null },
        { subjectRef: a, contextRef: "CTX_A", state: "DRAFT", expiresInMs: null },
        // b: rechazada antigua + enviada vigente nueva -> SENT (no revela la decision previa).
        { subjectRef: b, contextRef: "CTX_A", state: "DECLINED", expiresInMs: null },
        { subjectRef: b, contextRef: "CTX_A", state: "SENT", expiresInMs: HOUR },
        // c: decision + cerrada mas reciente -> la decision gana sobre la cerrada.
        { subjectRef: c, contextRef: "CTX_A", state: "DECLINED", expiresInMs: -HOUR },
        { subjectRef: c, contextRef: "CTX_A", state: "SENT", expiresInMs: -HOUR },
        // d: COMPLETED y DECLINED -> DECISION_RECORDED.
        { subjectRef: d, contextRef: "CTX_A", state: "COMPLETED", expiresInMs: null },
        { subjectRef: d, contextRef: "CTX_A", state: "DECLINED", expiresInMs: null },
        // e: solo cerrada -> CLOSED_WITHOUT_DECISION.
        { subjectRef: e, contextRef: "CTX_A", state: "READY", expiresInMs: -HOUR },
      ],
    });
    const status = new Map((await readAll(h, tenantId)).map((r) => [r.subjectRef, r.staffStatus]));
    assert.equal(status.get(a), "PENDING_SEND");
    assert.equal(status.get(b), "SENT");
    assert.equal(status.get(c), "DECISION_RECORDED");
    assert.equal(status.get(d), "DECISION_RECORDED");
    assert.equal(status.get(e), "CLOSED_WITHOUT_DECISION");
  });

  register(name("TEST-CNS-1072", "keyset (subject_ref, context_ref) COLLATE C con dos contextos: sin duplicar ni saltar filas, orden estable, limites 1 y mas que el total"), async (h) => {
    const tenantId = fixtureUuid("t1072");
    const subjects = Array.from({ length: 12 }, (_, i) => fixtureUuid(`s1072-${i}`));
    await h.seed({
      tenantId,
      subjects,
      participations: [
        { participationRef: fixtureUuid("p1072-a"), contextRef: "CTX_A" },
        { participationRef: fixtureUuid("p1072-b"), contextRef: "CTX_B" },
      ],
      // Un alumno con invitacion solo en CTX_B: el contexto es parte de la llave.
      invitations: [{ subjectRef: subjects[3] as string, contextRef: "CTX_B", state: "SENT", expiresInMs: HOUR }],
    });
    const expected = subjects.flatMap((s) => ["CTX_A", "CTX_B"].map((c) => `${s}|${c}`)).sort((x, y) => {
      const [xs = "", xc = ""] = x.split("|");
      const [ys = "", yc = ""] = y.split("|");
      return byC(xs, ys) || byC(xc, yc);
    });
    const all = await readAll(h, tenantId);
    assert.deepEqual(all.map((r) => `${r.subjectRef}|${r.contextRef}`), expected);
    assert.equal(all.find((r) => r.subjectRef === subjects[3] && r.contextRef === "CTX_B")?.staffStatus, "SENT");
    assert.equal(all.find((r) => r.subjectRef === subjects[3] && r.contextRef === "CTX_A")?.staffStatus, "NOT_INVITED");

    for (const pageSize of [1, 3, 5, 24, 100]) {
      const seen: string[] = [];
      let after: StaffRosterKeysetAfter | null = null;
      for (let guard = 0; guard < 100; guard += 1) {
        const page: readonly StaffRosterProjectionRow[] = await h.read({ tenantId, after, rowLimit: pageSize });
        assert.ok(page.length <= pageSize);
        for (const r of page) seen.push(`${r.subjectRef}|${r.contextRef}`);
        if (page.length < pageSize) break;
        const last = page[page.length - 1] as StaffRosterProjectionRow;
        after = { subjectRef: last.subjectRef, contextRef: last.contextRef };
      }
      assert.deepEqual(seen, expected, `pageSize=${pageSize}`);
      assert.equal(new Set(seen).size, seen.length, `sin duplicados pageSize=${pageSize}`);
    }
  });

  register(name("TEST-CNS-1073", "aislamiento por tenant: un subject_ref compartido entre tenants no cruza estado ni participacion"), async (h) => {
    const t1 = fixtureUuid("t1073-a");
    const t2 = fixtureUuid("t1073-b");
    const shared = fixtureUuid("s1073-shared");
    const only2 = fixtureUuid("s1073-only2");
    const p1 = fixtureUuid("p1073-a");
    const p2 = fixtureUuid("p1073-b");
    await h.seed({
      tenantId: t1,
      subjects: [shared],
      participations: [{ participationRef: p1, contextRef: "CTX_A" }],
      enrollments: [{ subjectRef: shared, participationRef: p1, state: "ACTIVE" }],
      invitations: [{ subjectRef: shared, contextRef: "CTX_A", state: "SENT", expiresInMs: HOUR }],
    });
    await h.seed({ tenantId: t2, subjects: [shared, only2], participations: [{ participationRef: p2, contextRef: "CTX_A" }] });
    const rows1 = await readAll(h, t1);
    const rows2 = await readAll(h, t2);
    assert.deepEqual(rows1.map((r) => [r.subjectRef, r.staffStatus, r.activeEnrollmentParticipationRef]), [[shared, "SENT", p1]]);
    assert.deepEqual(
      rows2.map((r) => [r.subjectRef, r.staffStatus, r.activeEnrollmentParticipationRef]).sort((x, y) => byC(String(x[0]), String(y[0]))),
      [[shared, "NOT_INVITED", null], [only2, "NOT_INVITED", null]].sort((x, y) => byC(String(x[0]), String(y[0]))),
    );
    // Un tenant sin datos (o desconocido) ve vacio.
    assert.deepEqual(await readAll(h, fixtureUuid("t1073-none")), []);
  });

  register(name("TEST-CNS-1074", "participation_ref de la matricula ACTIVE por contexto (CLOSED no cuenta); una fila STAFF_ROSTER_READ por lectura con resource_ref = tenant_id"), async (h) => {
    const tenantId = fixtureUuid("t1074");
    const [s1, s2, s3] = [fixtureUuid("s1074-1"), fixtureUuid("s1074-2"), fixtureUuid("s1074-3")] as [string, string, string];
    const [pa, pb] = [fixtureUuid("p1074-a"), fixtureUuid("p1074-b")] as [string, string];
    await h.seed({
      tenantId,
      subjects: [s1, s2, s3],
      participations: [
        { participationRef: pa, contextRef: "CTX_A" },
        { participationRef: pb, contextRef: "CTX_B" },
      ],
      enrollments: [
        { subjectRef: s1, participationRef: pa, state: "ACTIVE" },
        { subjectRef: s2, participationRef: pa, state: "CLOSED" },
        { subjectRef: s3, participationRef: pb, state: "ACTIVE" },
      ],
    });
    const rows = await readAll(h, tenantId);
    const get = (s: string, c: string): string | null | undefined => rows.find((r) => r.subjectRef === s && r.contextRef === c)?.activeEnrollmentParticipationRef;
    assert.equal(get(s1, "CTX_A"), pa);
    assert.equal(get(s1, "CTX_B"), null);
    assert.equal(get(s2, "CTX_A"), null);
    assert.equal(get(s3, "CTX_A"), null);
    assert.equal(get(s3, "CTX_B"), pb);

    const principal = fixtureUuid("staff-1074");
    const before = (await h.accessLogRows(tenantId)).length;
    await h.read({ tenantId, principalRef: principal, rowLimit: 5 });
    await h.read({ tenantId, principalRef: principal, rowLimit: 5, after: { subjectRef: s1, contextRef: "CTX_A" } });
    const log = await h.accessLogRows(tenantId);
    assert.equal(log.length - before, 2, "una fila por request");
    assert.ok(log.slice(before).every((r) => r.resourceRef === tenantId && r.actorRef === principal));
    assert.equal((await h.accessLogRows(fixtureUuid("t1074-other"))).length, 0, "ninguna fila en otro tenant");
  });
}
