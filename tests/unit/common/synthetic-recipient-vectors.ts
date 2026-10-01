// Vectores compartidos por TEST-CNS-975 (regla TS) y TEST-CNS-979 (paridad con app.is_reserved_email). CA-128, EXT-B (i).
export const RESERVED_OK: readonly string[] = ["padre@colegio.test", "a.b+c@sub.dominio.invalid", "x@example.com", "x@example.org", "x@EXAMPLE.NET", "x@t.TEST"];
export const RESERVED_BAD: readonly string[] = [
  "persona@gmail.com", "persona@example.cl", "persona@miexample.com", "persona@example.com.evil.io", "persona@test.cl",
  "persona@colegio.testing", "sin-arroba.test", "dos@@x.test", "a b@x.test", "", "@x.test", "persona@invalid.com",
  "f1a5c9e3-4d27-4b68-9e30-2c4e6a8b0d51",
];
