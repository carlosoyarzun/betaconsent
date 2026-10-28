// Gobierna: plan v2 H1-09. Parser CSV y validación del lote (todo o nada, sin PII en el reporte).
import assert from "node:assert/strict";
import { test } from "node:test";

import { maskEmail, parseCsv, parseInvitationCsv } from "../../../src/cli/csv.ts";

const H = "student_ref,student_first_name,guardian_email";

test("CSV válido con CRLF, BOM y correo normalizado a minúsculas", () => {
  const r = parseInvitationCsv(`﻿${H}\r\nstu-0000001,Ana,Apoderado@Example.test\r\nstu-0000002,Luis,b@example.test\r\n`);
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.rows.length, 2);
    assert.equal(r.rows[0]?.guardianEmail, "apoderado@example.test");
  }
});

test("comillas RFC 4180: coma, comilla escapada y salto de línea embebidos", () => {
  assert.deepEqual(parseCsv('a,"b,c","d""e","f\ng"\n'), [["a", "b,c", 'd"e', "f\ng"]]);
  assert.throws(() => parseCsv('a,"sin cierre'));
  assert.throws(() => parseCsv('a,b"c'));
});

test("cabecera errónea rechaza el archivo", () => {
  for (const bad of ["student_ref,first_name,guardian_email\nx,y,z", "student_ref,student_first_name,guardian_email,rut\n", `${H},extra\n`]) {
    const r = parseInvitationCsv(bad);
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.headerError ?? "", /CSV_BAD_HEADER/);
  }
});

test("una fila inválida invalida el lote y se reportan todas sin correo completo", () => {
  const r = parseInvitationCsv(
    [H, "stu-0000001,Ana,ok@example.test", "corto,Ana,ok2@example.test", "stu-0000003,,ok3@example.test", `stu-0000004,${"x".repeat(41)},ok4@example.test`, "stu-0000005,Eva,secreto-sin-arroba", "12345678-5,Eva,ok5@example.test", "stu-0000001,Dup,ok6@example.test", "stu-0000007,Eva"].join("\n"),
  );
  assert.equal(r.ok, false);
  if (r.ok) return;
  assert.deepEqual(r.issues.map((i) => [i.row, i.field]), [[2, "student_ref"], [3, "student_first_name"], [4, "student_first_name"], [5, "guardian_email"], [6, "student_ref"], [7, "student_ref"], [8, "row"]]);
  const dump = JSON.stringify(r.issues);
  assert.ok(!dump.includes("ok@example.test") && !dump.includes("secreto-sin-arroba"));
  assert.equal(r.issues[3]?.masked_email, "***");
});

test("maskEmail deja solo la inicial y el dominio", () => {
  assert.equal(maskEmail("apoderado@example.test"), "a***@example.test");
  assert.equal(maskEmail("sinarroba"), "***");
});
